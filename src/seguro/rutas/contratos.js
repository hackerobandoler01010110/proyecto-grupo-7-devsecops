'use strict';
// rutas/contratos.js
//   A02: el token de verificacion se guarda como HMAC-SHA256 (nunca en claro) y NO se
//        devuelve en la respuesta: se entrega al arrendatario por canal aparte. El texto
//        confidencial se cifra en reposo (AES-256-GCM).
//   A01: solo las partes del contrato (propietario de la propiedad y arrendatario) lo leen.
//   A09: TODO acceso a /contratos (autorizado, denegado o rechazado) queda en access.log.

const { describirReq } = require('../lib/logger');
const { v, exigirObjeto, soloCampos } = require('../lib/validacion');
const { limitar } = require('../lib/http');

module.exports = function rutasContratos(ctx) {
  const { express, db, cripto, logger, notificador, limitadores, autenticar, requerirRol } = ctx;
  const router = express.Router();

  // Va ANTES de la autenticacion: asi tambien queda registrado el intento sin sesion (401).
  router.use((req, res, next) => {
    res.on('finish', () => {
      const estado = res.statusCode;
      logger.acceso({
        evento: 'acceso_contrato',
        ...describirReq(req),
        contrato_id: res.locals.contratoId === undefined ? null : res.locals.contratoId,
        estado,
        resultado: estado < 400 ? 'autorizado' : (estado === 401 || estado === 403 ? 'denegado' : 'rechazado'),
        motivo: res.locals.motivo || null,
      });
    });
    next();
  });
  router.use(autenticar);

  router.post('/', requerirRol('propietario'), (req, res) => {
    exigirObjeto(req.body);
    soloCampos(req.body, ['propiedad_id', 'arrendatario_id', 'confidencial']);
    const propiedadId = v.id(req.body.propiedad_id, 'propiedad_id');
    const arrendatarioId = v.id(req.body.arrendatario_id, 'arrendatario_id');
    const confidencial = req.body.confidencial === undefined
      ? ''
      : v.texto(req.body.confidencial, 'confidencial', { min: 0, max: 500 });

    const prop = db.prepare('SELECT id, propietario_id FROM propiedades WHERE id = ?').get(propiedadId);
    if (!prop) return res.status(404).json({ error: 'Propiedad no encontrada' });
    if (prop.propietario_id !== req.usuario.id) {
      res.locals.motivo = 'contrato_sobre_propiedad_ajena';
      logger.seguridad({ evento: 'acceso_denegado', motivo: 'contrato_sobre_propiedad_ajena', ...describirReq(req) });
      return res.status(403).json({ error: 'No autorizado' });
    }
    const arrendatario = db.prepare('SELECT id, email, rol FROM usuarios WHERE id = ?').get(arrendatarioId);
    if (!arrendatario || arrendatario.rol !== 'arrendatario') {
      return res.status(400).json({ error: 'Solicitud invalida', detalles: ['arrendatario_id no corresponde a un arrendatario'] });
    }

    const token = cripto.generarToken();
    const r = db.prepare(
      `INSERT INTO contratos (propiedad_id, arrendatario_id, token_hash, confidencial_cifrado, verificado, creado_en)
       VALUES (?, ?, ?, ?, 0, ?)`
    ).run(propiedadId, arrendatarioId, cripto.hmac('contrato', token), cripto.cifrar(confidencial), new Date().toISOString());

    res.locals.contratoId = r.lastInsertRowid;
    notificador.enviarTokenContrato(arrendatario, r.lastInsertRowid, token); // canal aparte, no la respuesta HTTP
    return res.status(201).json({
      mensaje: 'Contrato creado. El token de verificacion fue enviado al arrendatario por un canal seguro.',
      contrato_id: r.lastInsertRowid,
    });
  });

  router.get('/:id', (req, res) => {
    const id = v.id(req.params.id);
    res.locals.contratoId = id;
    const c = db.prepare(
      `SELECT c.id, c.propiedad_id, c.arrendatario_id, c.confidencial_cifrado, c.verificado, c.creado_en,
              p.propietario_id
         FROM contratos c JOIN propiedades p ON p.id = c.propiedad_id
        WHERE c.id = ?`
    ).get(id);
    if (!c) {
      res.locals.motivo = 'contrato_inexistente';
      return res.status(404).json({ error: 'Contrato no encontrado' });
    }
    if (c.arrendatario_id !== req.usuario.id && c.propietario_id !== req.usuario.id) {
      res.locals.motivo = 'usuario_no_es_parte_del_contrato';
      logger.seguridad({ evento: 'acceso_denegado', motivo: 'usuario_no_es_parte_del_contrato', recurso: `contratos/${id}`, ...describirReq(req) });
      return res.status(403).json({ error: 'No autorizado' });
    }
    return res.json({
      id: c.id,
      propiedad_id: c.propiedad_id,
      arrendatario_id: c.arrendatario_id,
      verificado: Boolean(c.verificado),
      confidencial: cripto.descifrar(c.confidencial_cifrado),
      creado_en: c.creado_en,
    });
  });

  // El arrendatario confirma el contrato presentando el token que recibio.
  router.post('/:id/verificar', requerirRol('arrendatario'), (req, res) => {
    const id = v.id(req.params.id);
    res.locals.contratoId = id;
    exigirObjeto(req.body);
    soloCampos(req.body, ['token']);
    const token = v.token(req.body.token);

    const lim = limitadores.verificarContrato.consumir(`${req.usuario.id}:${id}`);
    if (!lim.permitido) { res.locals.motivo = 'limite_de_intentos'; return limitar(res, lim); }

    const c = db.prepare('SELECT id, arrendatario_id, token_hash FROM contratos WHERE id = ?').get(id);
    if (!c || c.arrendatario_id !== req.usuario.id) {
      res.locals.motivo = 'verificacion_sobre_contrato_ajeno_o_inexistente';
      return res.status(403).json({ error: 'No autorizado' });
    }
    if (!cripto.iguales(c.token_hash, cripto.hmac('contrato', token))) {
      res.locals.motivo = 'token_incorrecto';
      return res.status(401).json({ error: 'Token invalido' });
    }
    db.prepare('UPDATE contratos SET verificado = 1 WHERE id = ?').run(id);
    return res.json({ mensaje: 'Contrato verificado', verificado: true });
  });

  return router;
};
