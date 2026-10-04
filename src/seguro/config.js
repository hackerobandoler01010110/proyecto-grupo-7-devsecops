'use strict';
// config.js - Configuracion centralizada de PropNet (version segura).
// Todo valor sensible sale del entorno; nada de secretos en el codigo (A02/A05).

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const env = process.env;
const produccion = env.NODE_ENV === 'production';

const entero = (valor, defecto) => {
  const n = Number.parseInt(valor, 10);
  return Number.isFinite(n) && n > 0 ? n : defecto;
};
const booleano = (valor, defecto) =>
  valor === undefined ? defecto : ['1', 'true', 'si', 'yes'].includes(String(valor).toLowerCase());

// Secreto maestro (32 bytes en hex). De el se derivan la clave HMAC (hash de
// tokens/PIN) y la clave AES-256-GCM (datos confidenciales de contratos).
function cargarSecreto() {
  const valida = (s) => /^[a-f0-9]{64}$/i.test(s);
  if (env.PROPNET_SECRET) {
    if (!valida(env.PROPNET_SECRET)) {
      throw new Error('PROPNET_SECRET debe ser un hex de 64 caracteres (32 bytes)');
    }
    return env.PROPNET_SECRET.toLowerCase();
  }
  if (produccion) throw new Error('En produccion PROPNET_SECRET es obligatorio');

  // Desarrollo/laboratorio: se genera una vez y se guarda en .secret (ignorado por git).
  const ruta = path.join(__dirname, '.secret');
  if (fs.existsSync(ruta)) {
    const guardado = fs.readFileSync(ruta, 'utf8').trim();
    if (!valida(guardado)) throw new Error('El archivo .secret esta corrupto; borralo y vuelve a ejecutar el seed');
    return guardado.toLowerCase();
  }
  const nuevo = crypto.randomBytes(32).toString('hex');
  fs.writeFileSync(ruta, nuevo + '\n', { mode: 0o600 });
  return nuevo;
}

const MIN = 60 * 1000;

module.exports = {
  produccion,
  puerto: entero(env.PORT, 3000),
  // El auditor esta en otra maquina, por eso se escucha en todas las interfaces por defecto.
  host: env.HOST || '0.0.0.0',
  rutaDb: env.DB_PATH || path.join(__dirname, 'propnet.db'),
  dirLogs: env.LOG_DIR || path.join(__dirname, 'logs'),
  logConsola: booleano(env.LOG_CONSOLA, true),
  // Canal "SMS/correo" simulado por consola. En produccion queda apagado.
  smsSimulado: booleano(env.SMS_SIMULADO, !produccion),
  secreto: cargarSecreto(),

  pin: {
    ttlSeg: entero(env.PIN_TTL_SEGUNDOS, 300), // expira a los 5 min
    maxIntentos: entero(env.PIN_MAX_INTENTOS, 5),
  },
  sesionTtlSeg: entero(env.SESION_TTL_SEGUNDOS, 3600),

  // Limitadores (ventana fija, por clave). Ajustables por entorno para las demos.
  limites: {
    global: { max: entero(env.LIMITE_GLOBAL_POR_MIN, 300), ventanaMs: MIN },
    loginIp: { max: entero(env.LOGIN_MAX_POR_IP, 20), ventanaMs: 15 * MIN },
    loginEmail: { max: entero(env.LOGIN_MAX_SOLICITUDES, 5), ventanaMs: 15 * MIN },
    verificar: { max: entero(env.VERIFICAR_MAX, 10), ventanaMs: 15 * MIN },
    verificarContrato: { max: 5, ventanaMs: 15 * MIN },
    imagenes: { max: 10, ventanaMs: MIN },
  },

  precio: { min: 10000, max: 50000000 }, // CLP

  imagenes: {
    // Lista blanca ESTRICTA de hosts (coincidencia exacta). Configurable por entorno.
    hostsPermitidos: (env.IMG_HOSTS_PERMITIDOS || 'images.unsplash.com,upload.wikimedia.org')
      .split(',').map((s) => s.trim().toLowerCase()).filter(Boolean),
    maxBytes: 5 * 1024 * 1024,
    timeoutMs: 5000,
  },
};
