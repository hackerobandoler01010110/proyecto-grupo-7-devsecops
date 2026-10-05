'use strict';
// lib/validacion.js - Zero Trust Input: NINGUNA entrada del cliente se usa sin pasar
// por una lista blanca o una expresion regular estricta (ONF 27034, politica general).
// Cualquier incumplimiento lanza ErrorValidacion -> HTTP 400.

class ErrorValidacion extends Error {
  constructor(detalles) {
    super('Solicitud invalida');
    this.name = 'ErrorValidacion';
    this.detalles = Array.isArray(detalles) ? detalles : [String(detalles)];
  }
}
const falla = (mensaje) => { throw new ErrorValidacion([mensaje]); };

const RE = {
  id: /^[1-9]\d{0,8}$/,
  nombre: /^\p{L}[\p{L}\p{M} '.-]{1,59}$/u,
  telefono: /^\+?\d{8,15}$/,
  email: /^[a-z0-9._%+-]{1,64}@[a-z0-9-]{1,63}(\.[a-z0-9-]{1,63}){1,4}$/,
  // Letras, marcas, numeros, puntuacion y espacios. Quedan FUERA < > = ` | ~ ^ + (simbolos),
  // por lo que no puede formarse una etiqueta HTML. Se permite "$" (montos).
  titulo: /^[\p{L}\p{M}\p{N}\p{P}\p{Zs}$]{3,100}$/u,
  texto: /^[\p{L}\p{M}\p{N}\p{P}\p{Zs}$\r\n]*$/u,
  fecha: /^\d{4}-\d{2}-\d{2}$/,
  hora: /^(09|1[0-8]):(00|30)$/, // bloques de 30 min entre 09:00 y 18:30
  pin: /^\d{6}$/,
  token: /^[a-f0-9]{64}$/,
  enteroTexto: /^\d{1,9}$/,
};

const COMUNAS = [
  // Region Metropolitana
  'Alhué', 'Buin', 'Calera de Tango', 'Cerrillos', 'Cerro Navia', 'Colina', 'Conchalí',
  'Curacaví', 'El Bosque', 'El Monte', 'Estación Central', 'Huechuraba', 'Independencia',
  'Isla de Maipo', 'La Cisterna', 'La Florida', 'La Granja', 'La Pintana', 'La Reina',
  'Lampa', 'Las Condes', 'Lo Barnechea', 'Lo Espejo', 'Lo Prado', 'Macul', 'Maipú',
  'María Pinto', 'Melipilla', 'Ñuñoa', 'Padre Hurtado', 'Paine', 'Pedro Aguirre Cerda',
  'Peñaflor', 'Peñalolén', 'Pirque', 'Providencia', 'Pudahuel', 'Puente Alto', 'Quilicura',
  'Quinta Normal', 'Recoleta', 'Renca', 'San Bernardo', 'San Joaquín', 'San José de Maipo',
  'San Miguel', 'San Pedro', 'San Ramón', 'Santiago', 'Talagante', 'Tiltil', 'Vitacura',
  // Region de Valparaiso (principales)
  'Valparaíso', 'Viña del Mar', 'Concón', 'Quilpué', 'Villa Alemana', 'Casablanca', 'Quintero',
];
const sinAcentos = (s) => s.normalize('NFD').replace(/\p{M}/gu, '').toLowerCase().trim();
const MAPA_COMUNAS = new Map(COMUNAS.map((c) => [sinAcentos(c), c]));

function exigirObjeto(cuerpo) {
  if (cuerpo === null || typeof cuerpo !== 'object' || Array.isArray(cuerpo)) {
    falla('El cuerpo debe ser un objeto JSON');
  }
}

// Lista blanca de campos: cualquier campo extra (rol, is_vip, __proto__...) se rechaza.
// Evita mass assignment y prototype pollution.
function soloCampos(objeto, permitidos) {
  for (const clave of Object.keys(objeto)) {
    if (!permitidos.includes(clave)) falla('El cuerpo contiene campos no permitidos');
  }
}

const v = {
  id(valor, campo = 'id') {
    const s = typeof valor === 'number' ? String(valor) : valor;
    if (typeof s !== 'string' || !RE.id.test(s)) falla(`${campo} debe ser un entero positivo`);
    return Number(s);
  },

  entero(valor, campo, min, max) {
    if (typeof valor !== 'number' || !Number.isSafeInteger(valor) || valor < min || valor > max) {
      falla(`${campo} debe ser un entero entre ${min} y ${max}`);
    }
    return valor;
  },

  // Entero que llega como texto (query string): solo digitos, 1 a 9.
  enteroTexto(valor, campo, min, max) {
    if (typeof valor !== 'string' || !RE.enteroTexto.test(valor)) falla(`${campo} debe ser numerico`);
    const n = Number(valor);
    if (n < min || n > max) falla(`${campo} fuera de rango`);
    return n;
  },

  texto(valor, campo, { min = 1, max = 100, re = RE.texto } = {}) {
    if (typeof valor !== 'string') falla(`${campo} debe ser texto`);
    const t = valor.normalize('NFC').trim();
    if (t.length < min || t.length > max) falla(`${campo} debe tener entre ${min} y ${max} caracteres`);
    if (!re.test(t)) falla(`${campo} contiene caracteres no permitidos`);
    return t;
  },

  nombre(valor, campo = 'nombre') {
    if (typeof valor !== 'string') falla(`${campo} debe ser texto`);
    const t = valor.normalize('NFC').trim();
    if (!RE.nombre.test(t)) falla(`${campo} invalido`);
    return t;
  },

  telefono(valor, campo = 'telefono') {
    if (typeof valor !== 'string' || !RE.telefono.test(valor.trim())) {
      falla(`${campo} debe tener formato +56912345678`);
    }
    return valor.trim();
  },

  email(valor, campo = 'email') {
    if (typeof valor !== 'string' || valor.length > 254) falla(`${campo} invalido`);
    const e = valor.trim().toLowerCase();
    if (!RE.email.test(e)) falla(`${campo} invalido`);
    return e;
  },

  titulo(valor, campo = 'titulo') {
    return v.texto(valor, campo, { min: 3, max: 100, re: RE.titulo });
  },

  // Descripcion: texto plano. Cualquier "<" o ">" la rechaza (no se puede inyectar HTML).
  descripcion(valor, campo = 'descripcion') {
    return v.texto(valor, campo, { min: 1, max: 1000, re: RE.texto });
  },

  comuna(valor, campo = 'comuna') {
    if (typeof valor !== 'string' || valor.length > 60) falla(`${campo} invalida`);
    const canonica = MAPA_COMUNAS.get(sinAcentos(valor));
    if (!canonica) falla(`${campo} no pertenece a la lista de comunas permitidas`);
    return canonica;
  },

  fecha(valor, campo = 'fecha', { ahora = new Date(), maxDias = 180 } = {}) {
    if (typeof valor !== 'string' || !RE.fecha.test(valor)) falla(`${campo} debe tener formato AAAA-MM-DD`);
    const [y, m, d] = valor.split('-').map(Number);
    const dt = new Date(Date.UTC(y, m - 1, d));
    if (dt.getUTCFullYear() !== y || dt.getUTCMonth() !== m - 1 || dt.getUTCDate() !== d) {
      falla(`${campo} no es una fecha real`);
    }
    const hoy = Date.UTC(ahora.getUTCFullYear(), ahora.getUTCMonth(), ahora.getUTCDate());
    const dias = Math.round((dt.getTime() - hoy) / 86400000);
    if (dias < 0 || dias > maxDias) falla(`${campo} debe estar entre hoy y los proximos ${maxDias} dias`);
    return valor;
  },

  hora(valor, campo = 'hora') {
    if (typeof valor !== 'string' || !RE.hora.test(valor)) {
      falla(`${campo} debe ser un bloque HH:00 o HH:30 entre 09:00 y 18:30`);
    }
    return valor;
  },

  pin(valor, campo = 'pin') {
    if (typeof valor !== 'string' || !RE.pin.test(valor)) falla(`${campo} debe tener 6 digitos`);
    return valor;
  },

  token(valor, campo = 'token') {
    if (typeof valor !== 'string' || !RE.token.test(valor)) falla(`${campo} invalido`);
    return valor;
  },
};

// Escape de salida (defensa en profundidad para A08): se aplica siempre que un dato
// guardado se inserte en HTML, aunque la entrada ya haya sido validada.
function escaparHtml(valor) {
  return String(valor)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

module.exports = { ErrorValidacion, v, exigirObjeto, soloCampos, escaparHtml, COMUNAS };
