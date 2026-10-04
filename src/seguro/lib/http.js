'use strict';
// lib/http.js - Utilidades pequenas compartidas por las rutas.

// Express 4 no captura rechazos de handlers async: sin esto una promesa rechazada
// tumbaria el proceso o dejaria la peticion colgada.
const asincrono = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// Se usa la IP del socket (no X-Forwarded-For, que el cliente puede falsificar).
const ipDe = (req) => (req.socket && req.socket.remoteAddress) || 'desconocida';

const esViolacionUnicidad = (err) => /UNIQUE constraint failed/i.test(String(err && err.message));

function limitar(res, resultado, mensaje = 'Demasiadas solicitudes. Intenta mas tarde.') {
  res.set('Retry-After', String(resultado.reintentoSeg));
  return res.status(429).json({ error: mensaje });
}

module.exports = { asincrono, ipDe, esViolacionUnicidad, limitar };
