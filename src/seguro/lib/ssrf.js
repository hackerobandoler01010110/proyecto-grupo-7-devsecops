'use strict';
// lib/ssrf.js - Descarga segura de imagenes remotas (A10).
// Capas de defensa (todas deben cumplirse):
//   1. Solo https, sin credenciales en la URL, solo puerto 443.
//   2. El host debe estar en una LISTA BLANCA exacta. Las IP literales se rechazan siempre.
//   3. Se resuelve el DNS y se rechaza si CUALQUIER direccion es privada/local/link-local
//      (127/8, 10/8, 172.16/12, 192.168/16, 169.254/16 -metadatos de nube-, ::1, fc00::/7...).
//   4. La conexion se fija a la IP ya validada (evita DNS rebinding entre validar y conectar).
//   5. NO se siguen redirecciones (3xx = error), tiempo maximo, tamano maximo, tipo MIME y
//      firma binaria (magic bytes) de imagen.

const net = require('net');
const dns = require('dns');
const https = require('https');
const crypto = require('crypto');

class ErrorSsrf extends Error {
  constructor(motivo) {
    super('URL no permitida');
    this.name = 'ErrorSsrf';
    this.motivo = motivo; // solo para el log interno; el cliente recibe un mensaje generico
  }
}

const bloqueadas = new net.BlockList();
[
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
  ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24],
  ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24],
  ['224.0.0.0', 4], ['240.0.0.0', 4],
].forEach(([dir, prefijo]) => bloqueadas.addSubnet(dir, prefijo, 'ipv4'));
[
  ['::', 128], ['::1', 128], ['fc00::', 7], ['fe80::', 10], ['ff00::', 8],
  ['2001:db8::', 32], ['64:ff9b::', 96], ['2002::', 16],
].forEach(([dir, prefijo]) => bloqueadas.addSubnet(dir, prefijo, 'ipv6'));

// true = NO se debe conectar (privada, local, reservada o direccion invalida).
function esIpPrivada(ip) {
  const familia = net.isIP(ip);
  if (!familia) return true;
  if (familia === 6) {
    // IPv4 mapeada en IPv6: se evalua la IPv4 interna (::ffff:127.0.0.1 o ::ffff:7f00:1)
    let m = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);
    if (m) return esIpPrivada(m[1]);
    m = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i.exec(ip);
    if (m) {
      const a = parseInt(m[1], 16);
      const b = parseInt(m[2], 16);
      return esIpPrivada(`${a >> 8}.${a & 255}.${b >> 8}.${b & 255}`);
    }
    return bloqueadas.check(ip, 'ipv6');
  }
  return bloqueadas.check(ip, 'ipv4');
}

function validarUrl(entrada, { hostsPermitidos }) {
  if (typeof entrada !== 'string' || entrada.length === 0 || entrada.length > 2048) {
    throw new ErrorSsrf('formato');
  }
  let u;
  try { u = new URL(entrada); } catch (e) { throw new ErrorSsrf('no_parseable'); }

  if (u.protocol !== 'https:') throw new ErrorSsrf('esquema_no_permitido');
  if (u.username || u.password) throw new ErrorSsrf('credenciales_en_url');
  if (u.port && u.port !== '443') throw new ErrorSsrf('puerto_no_permitido');

  const host = u.hostname.toLowerCase().replace(/\.$/, '');
  // WHATWG normaliza 2130706433, 0x7f.1, etc. a "127.0.0.1": igual se detecta como IP.
  if (net.isIP(host) || host.startsWith('[')) throw new ErrorSsrf('ip_literal');
  if (!hostsPermitidos.includes(host)) throw new ErrorSsrf('host_fuera_de_lista_blanca');
  return { url: u, host };
}

async function resolverPublico(host, resolver = dns.promises.lookup) {
  let direcciones;
  try {
    direcciones = await resolver(host, { all: true, verbatim: true });
  } catch (e) {
    throw new ErrorSsrf('dns_fallo');
  }
  if (!direcciones || direcciones.length === 0) throw new ErrorSsrf('sin_resolucion');
  for (const d of direcciones) {
    if (esIpPrivada(d.address)) throw new ErrorSsrf('resuelve_a_ip_privada');
  }
  return direcciones[0];
}

const TIPOS = new Set(['image/jpeg', 'image/png', 'image/webp']);

function firmaValida(tipo, c) {
  if (tipo === 'image/jpeg') return c.length >= 3 && c[0] === 0xff && c[1] === 0xd8 && c[2] === 0xff;
  if (tipo === 'image/png') {
    return c.length >= 8 && c.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]));
  }
  if (tipo === 'image/webp') {
    return c.length >= 12 && c.subarray(0, 4).toString('latin1') === 'RIFF' && c.subarray(8, 12).toString('latin1') === 'WEBP';
  }
  return false;
}

async function descargarImagen(entrada, { hostsPermitidos, maxBytes, timeoutMs, resolver }) {
  const { url, host } = validarUrl(entrada, { hostsPermitidos });
  const destino = await resolverPublico(host, resolver);

  return new Promise((resolve, reject) => {
    const req = https.request({
      host,
      port: 443,
      path: url.pathname + url.search,
      method: 'GET',
      servername: host, // SNI y verificacion del certificado contra el host original
      timeout: timeoutMs,
      headers: { 'User-Agent': 'PropNet/1.0', Accept: 'image/jpeg,image/png,image/webp' },
      // Se conecta SOLO a la IP ya validada (anti DNS-rebinding).
      lookup: (h, opciones, cb) => (opciones && opciones.all
        ? cb(null, [{ address: destino.address, family: destino.family }])
        : cb(null, destino.address, destino.family)),
    }, (res) => {
      if (res.statusCode !== 200) {
        res.resume();
        return reject(new ErrorSsrf(res.statusCode >= 300 && res.statusCode < 400 ? 'redireccion_bloqueada' : 'estado_no_200'));
      }
      const tipo = String(res.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
      if (!TIPOS.has(tipo)) { res.resume(); return reject(new ErrorSsrf('tipo_no_permitido')); }
      const declarado = Number(res.headers['content-length']);
      if (Number.isFinite(declarado) && declarado > maxBytes) { res.resume(); return reject(new ErrorSsrf('demasiado_grande')); }

      let total = 0;
      let cabecera = Buffer.alloc(0);
      const hash = crypto.createHash('sha256');
      res.on('data', (trozo) => {
        total += trozo.length;
        if (total > maxBytes) return req.destroy(new ErrorSsrf('demasiado_grande'));
        if (cabecera.length < 16) cabecera = Buffer.concat([cabecera, trozo.subarray(0, 16 - cabecera.length)]);
        hash.update(trozo);
        return undefined;
      });
      res.on('end', () => {
        if (!firmaValida(tipo, cabecera)) return reject(new ErrorSsrf('firma_invalida'));
        return resolve({ tipo, bytes: total, sha256: hash.digest('hex') });
      });
      res.on('error', reject);
      return undefined;
    });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', reject);
    req.end();
  });
}

module.exports = { ErrorSsrf, esIpPrivada, validarUrl, resolverPublico, descargarImagen };
