'use strict';
// server.js - PropNet API (VERSION SEGURA, Grupo 7 - OWASP Top 10)
// crearApp() arma la aplicacion con dependencias inyectables (base de datos, logger,
// notificador) para poder probarla; iniciar() la levanta con la configuracion real.

const crypto = require('crypto');
const express = require('express');

const baseConfig = require('./config');
const { abrirBaseDatos } = require('./db');
const { crearCripto } = require('./lib/cripto');
const { crearLogger, describirReq } = require('./lib/logger');
const { crearLimitador } = require('./lib/limitador');
const { crearAuth } = require('./lib/auth');
const { descargarImagen } = require('./lib/ssrf');
const { ErrorValidacion } = require('./lib/validacion');
const { ipDe, limitar } = require('./lib/http');

// Canal simulado de SMS / correo. En produccion se reemplaza por un proveedor real.
function crearNotificador(cfg) {
  return {
    enviarPin(usuario, pin) {
      if (cfg.smsSimulado) console.log(`[SMS SIMULADO] PIN para ${usuario.email}: ${pin} (expira en ${cfg.pin.ttlSeg}s)`);
    },
    enviarTokenContrato(usuario, contratoId, token) {
      if (cfg.smsSimulado) console.log(`[CANAL SIMULADO] Token del contrato ${contratoId} para ${usuario.email}: ${token}`);
    },
  };
}

function crearApp({ db, cfg: sobrescribir = {}, logger, cripto, notificador, descargar = descargarImagen } = {}) {
  if (!db) throw new Error('crearApp requiere una base de datos');
  const cfg = { ...baseConfig, ...sobrescribir };
  const log = logger || crearLogger({ dir: cfg.dirLogs, consola: cfg.logConsola });
  const cr = cripto || crearCripto(cfg.secreto);
  const notif = notificador || crearNotificador(cfg);

  const limitadores = Object.fromEntries(
    Object.entries(cfg.limites).map(([nombre, opciones]) => [nombre, crearLimitador(opciones)])
  );
  const { autenticar, requerirRol } = crearAuth({ db, cripto: cr, logger: log });
  const ctx = { express, db, cfg, cripto: cr, logger: log, notificador: notif, limitadores, autenticar, requerirRol, descargarImagen: descargar };

  const app = express();
  app.disable('x-powered-by'); // A05: no anunciar el framework
  app.set('query parser', 'simple'); // sin objetos anidados en query (?a[b]=c)

  // A05: cabeceras de seguridad en TODAS las respuestas.
  app.use((req, res, next) => {
    res.set({
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'no-referrer',
      'Cache-Control': 'no-store',
      'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
      'Cross-Origin-Resource-Policy': 'same-origin',
    });
    if (req.secure || req.headers['x-forwarded-proto'] === 'https') {
      res.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    }
    next();
  });

  // Limite global por IP.
  app.use((req, res, next) => {
    const r = limitadores.global.consumir(ipDe(req));
    if (!r.permitido) {
      log.seguridad({ evento: 'limite_global_excedido', ...describirReq(req) });
      return limitar(res, r);
    }
    return next();
  });

  app.use(express.json({ limit: '10kb' })); // cuerpos pequenos, solo objetos/arreglos JSON

  app.get('/salud', (req, res) => res.json({ estado: 'ok' }));

  const { propiedades, arriendos } = require('./rutas/propiedades')(ctx);
  app.use('/', require('./rutas/auth')(ctx));
  app.use('/usuarios', require('./rutas/usuarios')(ctx));
  app.use('/propiedades', propiedades);
  app.use('/arriendos', arriendos);
  app.use('/contratos', require('./rutas/contratos')(ctx));
  app.use('/visitas', require('./rutas/visitas')(ctx));
  app.use('/imagenes', require('./rutas/imagenes')(ctx));

  app.use((req, res) => res.status(404).json({ error: 'Recurso no encontrado' }));

  // A05: manejador de errores generico. El cliente NUNCA ve stack, rutas ni mensajes
  // internos; recibe un identificador de incidente que permite ubicar el detalle en errores.log.
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    if (res.headersSent) return req.socket.destroy();
    if (err instanceof ErrorValidacion) {
      return res.status(400).json({ error: 'Solicitud invalida', detalles: err.detalles });
    }
    if (err && err.type === 'entity.parse.failed') return res.status(400).json({ error: 'JSON invalido' });
    if (err && err.type === 'entity.too.large') return res.status(413).json({ error: 'Cuerpo demasiado grande' });
    if (err && err.status >= 400 && err.status < 500) return res.status(err.status).json({ error: 'Solicitud invalida' });

    const incidente = crypto.randomUUID();
    log.error({
      evento: 'error_interno',
      incidente,
      ...describirReq(req),
      mensaje: err && err.message,
      stack: err && err.stack,
    });
    return res.status(500).json({ error: 'Error interno del servidor', incidente });
  });

  // Mantenimiento: borra PIN y sesiones vencidos.
  app.limpiarExpirados = () => {
    const ahora = new Date().toISOString();
    db.prepare('DELETE FROM sesiones WHERE expira_en < ?').run(ahora);
    db.prepare('DELETE FROM pines WHERE expira_en < ?').run(ahora);
  };
  return app;
}

async function iniciar() {
  const db = await abrirBaseDatos(baseConfig.rutaDb);
  if (!db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'sesiones'").get()) {
    db.close();
    throw new Error('La base de datos no esta inicializada. Ejecuta primero: npm run seed');
  }
  const logger = crearLogger({ dir: baseConfig.dirLogs, consola: baseConfig.logConsola });
  const app = crearApp({ db, logger });

  process.on('unhandledRejection', (motivo) => {
    logger.error({ evento: 'unhandled_rejection', mensaje: String(motivo && motivo.message), stack: motivo && motivo.stack });
  });

  const servidor = app.listen(baseConfig.puerto, baseConfig.host, () => {
    console.log(`PropNet API (SEGURA) escuchando en http://${baseConfig.host}:${baseConfig.puerto}`);
    if (baseConfig.smsSimulado) console.log('Canal SMS/correo SIMULADO: los PIN aparecen en esta consola.');
  });
  servidor.setTimeout(15000);
  setInterval(() => app.limpiarExpirados(), 10 * 60 * 1000).unref();
  return servidor;
}

if (require.main === module) {
  iniciar().catch((err) => {
    console.error('Error al iniciar el servidor:', err.message);
    process.exit(1);
  });
}

module.exports = { crearApp, iniciar, crearNotificador };
