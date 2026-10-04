'use strict';
// lib/cripto.js - Primitivas criptograficas (A02/A07). Solo modulo `crypto` de Node.
//  - Tokens y sesiones: 32 bytes aleatorios (CSPRNG), NUNCA Math.random().
//  - En la base solo se guarda HMAC-SHA256(secreto, valor): si se filtra la base,
//    los tokens no sirven. (Para secretos de 256 bits aleatorios HMAC es suficiente;
//    bcrypt/argon2 se justifican para contrasenas de baja entropia.)
//  - Datos confidenciales de contratos: AES-256-GCM (confidencialidad + integridad).

const crypto = require('crypto');

function crearCripto(secretoHex) {
  const maestra = Buffer.from(secretoHex, 'hex');
  const derivar = (info) =>
    Buffer.from(crypto.hkdfSync('sha256', maestra, Buffer.alloc(0), info, 32));
  const claveHmac = derivar('propnet:hmac:v1');
  const claveAes = derivar('propnet:aes-gcm:v1');

  return {
    generarToken: () => crypto.randomBytes(32).toString('hex'),

    // PIN de 6 digitos con CSPRNG (uniforme, sin sesgo de modulo).
    generarPin: () => String(crypto.randomInt(0, 1000000)).padStart(6, '0'),

    // `dominio` separa usos (pin:<id>, sesion, contrato) para que un hash de un
    // contexto no sirva en otro.
    hmac: (dominio, valor) =>
      crypto.createHmac('sha256', claveHmac).update(`${dominio}:${valor}`).digest('hex'),

    // Comparacion en tiempo constante.
    iguales(a, b) {
      const A = Buffer.from(String(a));
      const B = Buffer.from(String(b));
      return A.length === B.length && crypto.timingSafeEqual(A, B);
    },

    cifrar(texto) {
      const iv = crypto.randomBytes(12);
      const cifrador = crypto.createCipheriv('aes-256-gcm', claveAes, iv);
      const datos = Buffer.concat([cifrador.update(String(texto), 'utf8'), cifrador.final()]);
      const tag = cifrador.getAuthTag();
      return ['v1', iv.toString('base64'), tag.toString('base64'), datos.toString('base64')].join('.');
    },

    descifrar(paquete) {
      const [version, iv, tag, datos] = String(paquete).split('.');
      if (version !== 'v1' || !iv || !tag || datos === undefined) {
        throw new Error('formato de dato cifrado invalido');
      }
      const d = crypto.createDecipheriv('aes-256-gcm', claveAes, Buffer.from(iv, 'base64'));
      d.setAuthTag(Buffer.from(tag, 'base64'));
      return Buffer.concat([d.update(Buffer.from(datos, 'base64')), d.final()]).toString('utf8');
    },
  };
}

module.exports = { crearCripto };
