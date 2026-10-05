'use strict';
// lib/logger.js - Registro de eventos en JSON-lines (A09).
//   access.log     -> TODO acceso (autorizado o denegado) a contratos confidenciales
//   seguridad.log  -> logins, PIN, limites, ssrf bloqueado, cambios de precio, 403/401...
//   errores.log    -> detalle interno de errores 500 (stack incluido, NUNCA al cliente)
// JSON.stringify escapa saltos de linea y comillas: evita log forging con entradas hostiles.
// Pendiente (fuera de alcance): rotacion de logs y envio a un SIEM.

const fs = require('fs');
const path = require('path');

function crearLogger({ dir, consola = true }) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });

  function escribir(archivo, nivel, evento) {
    const linea = JSON.stringify({ ts: new Date().toISOString(), nivel, ...evento });
    try {
      fs.appendFileSync(path.join(dir, archivo), linea + '\n', { mode: 0o600 });
    } catch (e) {
      console.error('[logger] no se pudo escribir en', archivo);
    }
    if (consola) console.log(`[${archivo}] ${linea}`);
  }

  return {
    acceso: (e) => escribir('access.log', 'INFO', e),
    seguridad: (e) => escribir('seguridad.log', (e && e.nivel) || 'WARN', e),
    error: (e) => escribir('errores.log', 'ERROR', e),
  };
}

// Datos comunes de contexto de una peticion para los logs.
function describirReq(req) {
  return {
    ip: req.socket && req.socket.remoteAddress,
    metodo: req.method,
    ruta: String(req.originalUrl || req.url || '').split('?')[0].slice(0, 200),
    usuario_id: req.usuario ? req.usuario.id : null,
  };
}

module.exports = { crearLogger, describirReq };
