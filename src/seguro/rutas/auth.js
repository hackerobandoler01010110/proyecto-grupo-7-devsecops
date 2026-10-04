'use strict';
// rutas/auth.js - A07: autenticacion por PIN robusta.
//   - PIN de 6 digitos (CSPRNG), guardado como HMAC, expira (5 min), un solo uso.
//   - Maximo de intentos por PIN y de solicitudes por correo/IP.
//   - Respuestas uniformes: no se revela si el correo existe.
//   - El PIN jamas viaja en la respuesta HTTP ni se escribe en los logs de seguridad.

const { describirReq } = require('../lib/logger');
const { v, exigirObjeto, soloCampos } = require('../lib/validacion');
const { ipDe, limitar } = require('../lib/http');

module.exports = function rutasAuth(ctx) {
  const { express, db, cfg, cripto, logger, notificador, limitadores, autenticar } = ctx;
  const router = express.Router();

  router.post('/login', (req, res) => {
    exigirObjeto(req.body);
    soloCampos(req.body, ['email']);
    const email = v.email(req.body.email);

    const l1 = limitadores.loginIp.consumir(ipDe(req));
    const l2 = limitadores.loginEmail.consumir(email);
    if (!l1.permitido || !l2.permitido) {
      logger.seguridad({ evento: 'login_limite_excedido', ...describirReq(req) });
      return limitar(res, l1.permitido ? l2 : l1);
    }

    const usuario = db.prepare('SELECT id, email, rol FROM usuarios WHERE email = ?').get(email);
    if (usuario) {
      const pin = cripto.generarPin();
      const ahora = Date.now();
      db.prepare('UPDATE pines SET usado = 1 WHERE usuario_id = ? AND usado = 0').run(usuario.id); // un solo PIN vigente
      db.prepare(
        'INSERT INTO pines (usuario_id, pin_hash, creado_en, expira_en, intentos, usado) VALUES (?, ?, ?, ?, 0, 0)'
      ).run(
        usuario.id,
        cripto.hmac(`pin:${usuario.id}`, pin),
        new Date(ahora).toISOString(),
        new Date(ahora + cfg.pin.ttlSeg * 1000).toISOString()
      );
      notificador.enviarPin(usuario, pin);
      logger.seguridad({ nivel: 'INFO', evento: 'pin_emitido', ...describirReq(req), destino_id: usuario.id });
    } else {
      logger.seguridad({ evento: 'login_correo_desconocido', ...describirReq(req) });
    }
    // Misma respuesta exista o no el correo (anti-enumeracion de usuarios).
    return res.json({
      mensaje: `Si el correo esta registrado, se envio un PIN de 6 digitos por SMS. Expira en ${Math.round(cfg.pin.ttlSeg / 60)} minutos.`,
    });
  });

  router.post('/login/verificar', (req, res) => {
    exigirObjeto(req.body);
    soloCampos(req.body, ['email', 'pin']);
    const email = v.email(req.body.email);
    const pin = v.pin(req.body.pin);

    // Solo cuentan los FALLOS (un login legitimo nunca queda castigado). Clave IP+correo:
    // un atacante no puede bloquear al titular desde otra IP. El tope por PIN (5 intentos) y
    // el de solicitudes de PIN (5 por ventana) acotan los intentos totales sin importar la IP.
    const claveFallos = `${ipDe(req)}|${email}`;
    const bloqueo = limitadores.verificar.revisar(claveFallos);
    if (!bloqueo.permitido) {
      logger.seguridad({ evento: 'verificacion_limite_excedido', ...describirReq(req) });
      return limitar(res, bloqueo);
    }

    const fallo401 = (motivo) => {
      limitadores.verificar.consumir(claveFallos);
      logger.seguridad({ evento: 'login_fallido', motivo, ...describirReq(req) });
      return res.status(401).json({ autenticado: false, error: 'PIN invalido o expirado' });
    };

    const usuario = db.prepare('SELECT id, rol FROM usuarios WHERE email = ?').get(email);
    if (!usuario) return fallo401('usuario_inexistente');

    const ahora = new Date();
    const reg = db.prepare(
      'SELECT id, pin_hash, intentos FROM pines WHERE usuario_id = ? AND usado = 0 AND expira_en > ? ORDER BY id DESC LIMIT 1'
    ).get(usuario.id, ahora.toISOString());
    if (!reg) return fallo401('pin_inexistente_expirado_o_usado');

    if (reg.intentos >= cfg.pin.maxIntentos) {
      logger.seguridad({ evento: 'pin_bloqueado', ...describirReq(req), destino_id: usuario.id });
      return limitar(res, { reintentoSeg: cfg.pin.ttlSeg }, 'PIN bloqueado por demasiados intentos. Solicita uno nuevo.');
    }

    if (!cripto.iguales(reg.pin_hash, cripto.hmac(`pin:${usuario.id}`, pin))) {
      const intentos = reg.intentos + 1;
      db.prepare('UPDATE pines SET intentos = ? WHERE id = ?').run(intentos, reg.id);
      if (intentos >= cfg.pin.maxIntentos) {
        limitadores.verificar.consumir(claveFallos); // fallo que bloquea el PIN (fallo401 cuenta los demas)
        logger.seguridad({ evento: 'pin_bloqueado', ...describirReq(req), destino_id: usuario.id });
        return limitar(res, { reintentoSeg: cfg.pin.ttlSeg }, 'PIN bloqueado por demasiados intentos. Solicita uno nuevo.');
      }
      return fallo401('pin_incorrecto');
    }

    // PIN correcto: se consume (un solo uso) y se emite la sesion.
    db.prepare('UPDATE pines SET usado = 1 WHERE id = ?').run(reg.id);
    const token = cripto.generarToken();
    const expira = new Date(ahora.getTime() + cfg.sesionTtlSeg * 1000).toISOString();
    db.prepare('INSERT INTO sesiones (usuario_id, token_hash, creado_en, expira_en) VALUES (?, ?, ?, ?)')
      .run(usuario.id, cripto.hmac('sesion', token), ahora.toISOString(), expira);
    logger.seguridad({ nivel: 'INFO', evento: 'login_exitoso', ...describirReq(req), destino_id: usuario.id });
    return res.json({ autenticado: true, token, tipo: 'Bearer', expira_en: expira });
  });

  // Cierre de sesion: revoca el token en el servidor (no basta con borrarlo en el cliente).
  router.post('/logout', autenticar, (req, res) => {
    db.prepare('DELETE FROM sesiones WHERE id = ?').run(req.usuario.sesionId);
    logger.seguridad({ nivel: 'INFO', evento: 'logout', ...describirReq(req) });
    res.json({ mensaje: 'Sesion cerrada' });
  });

  return router;
};
