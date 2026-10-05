'use strict';
// lib/auth.js - Autenticacion por sesion (A01/A07).
// Tras verificar el PIN se emite un token de sesion opaco (32 bytes aleatorios) que
// el cliente envia como "Authorization: Bearer <token>". En la base solo se guarda su
// HMAC, tiene expiracion y se puede revocar (logout). Sin dependencias externas.

const { describirReq } = require('./logger');

function crearAuth({ db, cripto, logger }) {
  function rechazar401(req, res, motivo) {
    logger.seguridad({ evento: 'autenticacion_fallida', motivo, ...describirReq(req) });
    res.set('WWW-Authenticate', 'Bearer');
    return res.status(401).json({ error: 'No autenticado' });
  }

  function autenticar(req, res, next) {
    const m = /^Bearer ([a-f0-9]{64})$/.exec(req.headers.authorization || '');
    if (!m) return rechazar401(req, res, 'token_ausente_o_con_formato_invalido');

    const fila = db.prepare(
      `SELECT u.id, u.rol, u.nombre, s.id AS sesion_id
         FROM sesiones s JOIN usuarios u ON u.id = s.usuario_id
        WHERE s.token_hash = ? AND s.expira_en > ?`
    ).get(cripto.hmac('sesion', m[1]), new Date().toISOString());
    if (!fila) return rechazar401(req, res, 'sesion_invalida_o_expirada');

    req.usuario = { id: fila.id, rol: fila.rol, nombre: fila.nombre, sesionId: fila.sesion_id };
    return next();
  }

  const requerirRol = (...roles) => (req, res, next) => {
    if (!roles.includes(req.usuario.rol)) {
      if (res.locals) res.locals.motivo = 'rol_insuficiente';
      logger.seguridad({ evento: 'acceso_denegado', motivo: 'rol_insuficiente', ...describirReq(req) });
      return res.status(403).json({ error: 'No autorizado' });
    }
    return next();
  };

  return { autenticar, requerirRol };
}

module.exports = { crearAuth };
