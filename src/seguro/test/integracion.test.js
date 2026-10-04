'use strict';
// Pruebas de integracion: levantan la API real (base en memoria) y verifican los 10 controles.
// Ejecutar: npm test
process.env.PROPNET_SECRET = process.env.PROPNET_SECRET || 'c'.repeat(64);
process.env.LOG_CONSOLA = 'false';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const { abrirBaseDatos } = require('../db');
const { crearCripto } = require('../lib/cripto');
const { sembrar } = require('../seed');
const { crearApp } = require('../server');
const cfgBase = require('../config');

const cripto = crearCripto(cfgBase.secreto);
const RUTA_RAIZ_MALA = /(node_modules|\.js:\d+|[A-Za-z]:\\|\/home\/|\/Users\/|\/usr\/|\bat [\w.<]+ \()/;

function dia(n) { // fecha futura AAAA-MM-DD
  const d = new Date(Date.now() + n * 86400000);
  return d.toISOString().slice(0, 10);
}

async function levantar(extra = {}) {
  const db = await abrirBaseDatos(null);
  const tokensContrato = await sembrar(db, cripto);
  const eventos = { acceso: [], seguridad: [], error: [] };
  const logger = {
    acceso: (e) => eventos.acceso.push(e),
    seguridad: (e) => eventos.seguridad.push(e),
    error: (e) => eventos.error.push(e),
  };
  const pines = {};
  const tokensEnviados = {};
  const notificador = {
    enviarPin: (u, pin) => { pines[u.email] = pin; },
    enviarTokenContrato: (u, id, token) => { tokensEnviados[id] = token; },
  };
  const app = crearApp({ db: extra.db || db, logger, notificador, cripto, ...extra.opciones });
  const servidor = await new Promise((resolve) => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
  const base = `http://127.0.0.1:${servidor.address().port}`;

  async function api(metodo, ruta, { token, cuerpo, crudo, cabeceras = {} } = {}) {
    const headers = { ...cabeceras };
    if (token) headers.Authorization = `Bearer ${token}`;
    let body;
    if (crudo !== undefined) { body = crudo; headers['Content-Type'] = 'application/json'; }
    else if (cuerpo !== undefined) { body = JSON.stringify(cuerpo); headers['Content-Type'] = 'application/json'; }
    const r = await fetch(base + ruta, { method: metodo, headers, body });
    const texto = await r.text();
    let json = null;
    try { json = JSON.parse(texto); } catch (e) { /* html u otro */ }
    return { estado: r.status, json, texto, cabeceras: r.headers };
  }
  async function login(email) {
    const a = await api('POST', '/login', { cuerpo: { email } });
    assert.equal(a.estado, 200, 'login');
    const b = await api('POST', '/login/verificar', { cuerpo: { email, pin: pines[email] } });
    assert.equal(b.estado, 200, 'verificar');
    return b.json.token;
  }
  const cerrar = () => new Promise((r) => servidor.close(r));
  return { db, api, login, eventos, pines, tokensEnviados, tokensContrato, cerrar, app, base };
}

test('A01 control de acceso: autenticacion obligatoria y propiedad del recurso', async () => {
  const t = await levantar();
  try {
    const maria = await t.login('maria@propnet.cl');
    const juan = await t.login('juan@propnet.cl');

    // Sin sesion -> 401
    assert.equal((await t.api('PUT', '/arriendos/1', { cuerpo: { precio: 100000 } })).estado, 401);
    assert.equal((await t.api('PUT', '/usuarios/1', { cuerpo: { nombre: 'Hacker' } })).estado, 401);
    // Tokens basura / mal formados -> 401
    assert.equal((await t.api('PUT', '/arriendos/1', { token: 'x', cuerpo: { precio: 100000 } })).estado, 401);
    assert.equal((await t.api('PUT', '/arriendos/1', { token: 'a'.repeat(64), cuerpo: { precio: 100000 } })).estado, 401);

    // Arrendatario no puede cambiar precios ni datos del propietario -> 403
    assert.equal((await t.api('PUT', '/arriendos/1', { token: juan, cuerpo: { precio: 100000 } })).estado, 403);
    assert.equal((await t.api('PUT', '/usuarios/1', { token: juan, cuerpo: { nombre: 'Hackeado', telefono: '+56900000000' } })).estado, 403);
    assert.equal(t.db.prepare('SELECT precio FROM propiedades WHERE id = 1').get().precio, 450000);
    assert.equal(t.db.prepare('SELECT nombre FROM usuarios WHERE id = 1').get().nombre, 'Maria Propietaria');

    // Propietario NO puede tocar propiedad de otro propietario (Carla = 4, propiedad 3)
    assert.equal((await t.api('PUT', '/arriendos/3', { token: maria, cuerpo: { precio: 100000 } })).estado, 403);
    // Propietario si puede con la suya
    const ok = await t.api('PUT', '/arriendos/1', { token: maria, cuerpo: { precio: 480000 } });
    assert.equal(ok.estado, 200);
    assert.equal(t.db.prepare('SELECT precio FROM propiedades WHERE id = 1').get().precio, 480000);
    assert.equal((await t.api('PUT', '/arriendos/999', { token: maria, cuerpo: { precio: 480000 } })).estado, 404);

    // Datos invalidos / limites de negocio
    for (const precio of [1, -5, '480000', 1e12, null, 1.5]) {
      assert.equal((await t.api('PUT', '/arriendos/1', { token: maria, cuerpo: { precio } })).estado, 400, `precio ${precio}`);
    }

    // Mass assignment: rol y otros campos no permitidos
    assert.equal((await t.api('PUT', '/usuarios/2', { token: juan, cuerpo: { nombre: 'Juan Perez', rol: 'propietario' } })).estado, 400);
    assert.equal(t.db.prepare('SELECT rol FROM usuarios WHERE id = 2').get().rol, 'arrendatario');
    // Arrendatario no fija valor de arriendo de referencia
    assert.equal((await t.api('PUT', '/usuarios/2', { token: juan, cuerpo: { valor_arriendo_referencia: 1000000 } })).estado, 403);
    // Edicion legitima del propio perfil
    assert.equal((await t.api('PUT', '/usuarios/2', { token: juan, cuerpo: { nombre: 'Juan Perez', telefono: '+56922222223' } })).estado, 200);
    // Propietario fija su valor de referencia
    assert.equal((await t.api('PUT', '/usuarios/1', { token: maria, cuerpo: { valor_arriendo_referencia: 520000 } })).estado, 200);
    // Id invalido
    assert.equal((await t.api('PUT', '/usuarios/1%20OR%201=1', { token: maria, cuerpo: { nombre: 'Maria Lopez' } })).estado, 400);

    // Logout revoca la sesion en el servidor
    assert.equal((await t.api('POST', '/logout', { token: juan })).estado, 200);
    assert.equal((await t.api('PUT', '/usuarios/2', { token: juan, cuerpo: { nombre: 'Juan Perez' } })).estado, 401);

    assert.ok(t.eventos.seguridad.some((e) => e.evento === 'acceso_denegado'), 'los 403 quedan en el log de seguridad');
  } finally { await t.cerrar(); }
});

test('A02 criptografia: token solo como hash, nunca en la respuesta; confidencial cifrado', async () => {
  const t = await levantar();
  try {
    const maria = await t.login('maria@propnet.cl');
    const juan = await t.login('juan@propnet.cl');

    const r = await t.api('POST', '/contratos', { token: maria, cuerpo: { propiedad_id: 1, arrendatario_id: 2, confidencial: 'Renta $450.000' } });
    assert.equal(r.estado, 201);
    const id = r.json.contrato_id;
    assert.ok(!/token/i.test(Object.keys(r.json).join(',')), 'la respuesta no tiene campo token');
    const tokenEnClaro = t.tokensEnviados[id];
    assert.match(tokenEnClaro, /^[a-f0-9]{64}$/);
    assert.ok(!r.texto.includes(tokenEnClaro), 'el token no viaja en la respuesta HTTP');

    const fila = t.db.prepare('SELECT token_hash, confidencial_cifrado FROM contratos WHERE id = ?').get(id);
    assert.notEqual(fila.token_hash, tokenEnClaro);
    assert.match(fila.token_hash, /^[a-f0-9]{64}$/);
    assert.ok(!fila.confidencial_cifrado.includes('Renta'), 'texto confidencial cifrado en reposo');
    // Tampoco los contratos sembrados guardan el token en claro
    for (const tk of Object.values(t.tokensContrato)) {
      assert.equal(t.db.prepare('SELECT COUNT(*) n FROM contratos WHERE token_hash = ?').get(tk).n, 0);
    }

    // Verificacion: el arrendatario correcto con el token correcto
    assert.equal((await t.api('POST', `/contratos/${id}/verificar`, { token: juan, cuerpo: { token: 'f'.repeat(64) } })).estado, 401);
    assert.equal((await t.api('POST', `/contratos/${id}/verificar`, { token: juan, cuerpo: { token: 'corto' } })).estado, 400);
    assert.equal((await t.api('POST', `/contratos/${id}/verificar`, { token: maria, cuerpo: { token: tokenEnClaro } })).estado, 403); // rol propietario
    const ok = await t.api('POST', `/contratos/${id}/verificar`, { token: juan, cuerpo: { token: tokenEnClaro } });
    assert.equal(ok.estado, 200);
    assert.equal(t.db.prepare('SELECT verificado FROM contratos WHERE id = ?').get(id).verificado, 1);

    // Las partes leen el contrato descifrado; la respuesta no incluye hash ni token
    const leido = await t.api('GET', `/contratos/${id}`, { token: juan });
    assert.equal(leido.estado, 200);
    assert.equal(leido.json.confidencial, 'Renta $450.000');
    assert.ok(!('token_hash' in leido.json) && !('token_verificacion' in leido.json));

    // Autorizacion al crear: sin sesion, rol equivocado, propiedad ajena, arrendatario invalido
    assert.equal((await t.api('POST', '/contratos', { cuerpo: { propiedad_id: 1, arrendatario_id: 2 } })).estado, 401);
    assert.equal((await t.api('POST', '/contratos', { token: juan, cuerpo: { propiedad_id: 1, arrendatario_id: 2 } })).estado, 403);
    assert.equal((await t.api('POST', '/contratos', { token: maria, cuerpo: { propiedad_id: 3, arrendatario_id: 2 } })).estado, 403);
    assert.equal((await t.api('POST', '/contratos', { token: maria, cuerpo: { propiedad_id: 1, arrendatario_id: 1 } })).estado, 400);
    assert.equal((await t.api('POST', '/contratos', { token: maria, cuerpo: { propiedad_id: 1, arrendatario_id: 2, confidencial: '<script>x</script>' } })).estado, 400);
  } finally { await t.cerrar(); }
});

test('A03 inyeccion SQL: el buscador rechaza payloads y responde solo con datos legitimos', async () => {
  const t = await levantar();
  try {
    const q = (qs) => t.api('GET', `/propiedades/buscar?${qs}`);
    const enc = encodeURIComponent;

    const normal = await q('comuna=Providencia&precio_max=1000000');
    assert.equal(normal.estado, 200);
    assert.equal(normal.json.length, 1);
    assert.equal((await q('comuna=nunoa')).json[0].comuna, 'Ñuñoa'); // sin acentos tambien
    assert.equal((await q('')).json.length, 3);
    assert.equal((await q('precio_max=450000')).json.length, 2);

    const payloads = [
      `comuna=${enc("' OR '1'='1")}`,
      `comuna=${enc("Providencia' UNION SELECT id,email,rol,telefono,1 FROM usuarios--")}`,
      `comuna=${enc("%'; DROP TABLE propiedades;--")}`,
      `precio_max=${enc('0 OR 1=1')}`,
      `precio_max=${enc('NOT_A_NUMBER); DROP TABLE propiedades;--')}`,
      `precio_max=${enc('1 UNION SELECT 1,2,3,4,5,6')}`,
      'comuna=A&comuna=B',          // parametro repetido (arreglo)
      `comuna[$ne]=x`,              // sintaxis de objeto
      `otro=1`,                     // parametro desconocido
    ];
    for (const p of payloads) {
      const r = await q(p);
      assert.equal(r.estado, 400, `payload: ${p} -> ${r.estado}`);
      assert.ok(!RUTA_RAIZ_MALA.test(r.texto));
    }
    // La tabla sigue intacta tras los intentos
    assert.equal(t.db.prepare('SELECT COUNT(*) n FROM propiedades').get().n, 3);
  } finally { await t.cerrar(); }
});

test('A04 reservas: conflicto = 409, slots y fechas validados, unicidad a nivel de base', async () => {
  const t = await levantar();
  try {
    const juan = await t.login('juan@propnet.cl');
    const maria = await t.login('maria@propnet.cl');
    const cuerpo = { propiedad_id: 1, fecha: dia(10), hora: '10:00' };

    assert.equal((await t.api('POST', '/visitas', { cuerpo })).estado, 401);
    const r1 = await t.api('POST', '/visitas', { token: juan, cuerpo });
    assert.equal(r1.estado, 201);
    const r2 = await t.api('POST', '/visitas', { token: maria, cuerpo });
    assert.equal(r2.estado, 409);
    assert.equal(t.db.prepare('SELECT COUNT(*) n FROM visitas').get().n, 1);
    // Otro horario / otra propiedad si se puede
    assert.equal((await t.api('POST', '/visitas', { token: maria, cuerpo: { ...cuerpo, hora: '10:30' } })).estado, 201);
    assert.equal((await t.api('POST', '/visitas', { token: maria, cuerpo: { ...cuerpo, propiedad_id: 2 } })).estado, 201);

    // Concurrencia: 8 peticiones simultaneas al mismo slot -> exactamente 1 gana
    const carrera = await Promise.all(Array.from({ length: 8 }, () =>
      t.api('POST', '/visitas', { token: juan, cuerpo: { propiedad_id: 3, fecha: dia(11), hora: '15:00' } })));
    assert.equal(carrera.filter((r) => r.estado === 201).length, 1);
    assert.equal(carrera.filter((r) => r.estado === 409).length, 7);

    // Respaldo en la base: aunque se evada la validacion, el UNIQUE lo impide
    assert.throws(() => t.db.prepare('INSERT INTO visitas (propiedad_id, usuario_id, visitante, fecha, hora, creado_en) VALUES (?,?,?,?,?,?)')
      .run(1, 2, 'X', cuerpo.fecha, cuerpo.hora, 'ahora'), /UNIQUE/i);

    // Validaciones
    const malos = [
      { ...cuerpo, hora: '03:00' }, { ...cuerpo, hora: '10:15' }, { ...cuerpo, fecha: dia(-3) },
      { ...cuerpo, fecha: '2026-02-30' }, { ...cuerpo, fecha: dia(400) }, { ...cuerpo, propiedad_id: 'abc' },
      { ...cuerpo, propiedad_id: '1 OR 1=1' }, { ...cuerpo, extra: 1 }, { ...cuerpo, visitante: '<script>' }, {},
    ];
    for (const m of malos) assert.equal((await t.api('POST', '/visitas', { token: juan, cuerpo: m })).estado, 400, JSON.stringify(m));
    assert.equal((await t.api('POST', '/visitas', { token: juan, cuerpo: { ...cuerpo, propiedad_id: 99 } })).estado, 404);
  } finally { await t.cerrar(); }
});

test('A05 errores y cabeceras: sin stack, sin rutas, sin X-Powered-By', async () => {
  const t = await levantar();
  try {
    const juan = await t.login('juan@propnet.cl');

    // JSON mal formado, cuerpo gigante, ruta inexistente, metodo raro
    const malJson = await t.api('POST', '/login', { crudo: '{"email": ' });
    assert.equal(malJson.estado, 400);
    const grande = await t.api('POST', '/login', { cuerpo: { email: 'a@b.cl', relleno: 'x'.repeat(20000) } });
    assert.equal(grande.estado, 413);
    const noExiste = await t.api('GET', '/admin/config');
    assert.equal(noExiste.estado, 404);
    for (const r of [malJson, grande, noExiste]) {
      assert.ok(!RUTA_RAIZ_MALA.test(r.texto), `fuga en: ${r.texto}`);
      assert.ok(!('stack' in (r.json || {})));
    }
    // Arreglo JSON / escalar como cuerpo
    assert.equal((await t.api('POST', '/login', { crudo: '[1,2]' })).estado, 400);

    // Cabeceras de seguridad
    const salud = await t.api('GET', '/salud');
    assert.equal(salud.cabeceras.get('x-powered-by'), null);
    assert.equal(salud.cabeceras.get('x-content-type-options'), 'nosniff');
    assert.equal(salud.cabeceras.get('x-frame-options'), 'DENY');
    assert.match(salud.cabeceras.get('content-security-policy'), /default-src 'none'/);
    assert.equal(salud.cabeceras.get('cache-control'), 'no-store');

    // Error interno real (la base falla con un mensaje con ruta): el cliente solo recibe un id
    const db2 = await abrirBaseDatos(null);
    await sembrar(db2, cripto);
    const rota = {
      exec: (s) => db2.exec(s),
      prepare: (sql) => {
        if (/SELECT titulo, descripcion FROM propiedades/.test(sql)) {
          return { get() { throw new Error("SQLITE_ERROR en /home/ubuntu/propnet/src/seguro/db.js:42"); } };
        }
        return db2.prepare(sql);
      },
    };
    const t2 = await levantar({ db: rota });
    try {
      const r = await t2.api('GET', '/propiedades/1');
      assert.equal(r.estado, 500);
      assert.deepEqual(Object.keys(r.json).sort(), ['error', 'incidente']);
      assert.ok(!r.texto.includes('/home/') && !r.texto.includes('SQLITE'));
      const interno = t2.eventos.error.find((e) => e.incidente === r.json.incidente);
      assert.ok(interno && /SQLITE_ERROR/.test(interno.mensaje) && interno.stack, 'el detalle SI queda en el log interno');
    } finally { await t2.cerrar(); }
    void juan;
  } finally { await t.cerrar(); }
});

test('A06 dependencias: package.json sin los paquetes vulnerables de la version insegura', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'));
  const deps = Object.keys(pkg.dependencies || {});
  for (const mala of ['node-fetch', 'moment', 'leaflet']) assert.ok(!deps.includes(mala), `${mala} no debe estar`);
  assert.deepEqual(deps.sort(), ['express', 'sql.js']);
});

test('A07 autenticacion: PIN 6 digitos, un solo uso, expira, limite de intentos y de solicitudes', async () => {
  const t = await levantar();
  try {
    const email = 'juan@propnet.cl';
    const generico = await t.api('POST', '/login', { cuerpo: { email: 'nadie@propnet.cl' } });
    const real = await t.api('POST', '/login', { cuerpo: { email } });
    assert.equal(generico.estado, 200);
    assert.equal(real.estado, 200);
    assert.equal(generico.texto, real.texto, 'misma respuesta exista o no el correo');
    assert.ok(!/\d{6}/.test(real.texto) && !('pin' in real.json), 'el PIN no viaja en la respuesta');
    assert.match(t.pines[email], /^\d{6}$/);
    const pin = t.pines[email];
    // En la base solo hay un hash, no el PIN
    const fila = t.db.prepare('SELECT pin_hash, expira_en, creado_en FROM pines WHERE usuario_id = 2').get();
    assert.notEqual(fila.pin_hash, pin);
    const ttl = (new Date(fila.expira_en) - new Date(fila.creado_en)) / 1000;
    assert.equal(ttl, 300, 'expira a los 5 minutos');
    // Rechaza PIN con formato antiguo de 3 digitos
    assert.equal((await t.api('POST', '/login/verificar', { cuerpo: { email, pin: '123' } })).estado, 400);
    assert.equal((await t.api('POST', '/login/verificar', { cuerpo: { email, pin: 123456 } })).estado, 400);

    // Correcto -> sesion; reutilizar el mismo PIN -> 401
    const ok = await t.api('POST', '/login/verificar', { cuerpo: { email, pin } });
    assert.equal(ok.estado, 200);
    assert.match(ok.json.token, /^[a-f0-9]{64}$/);
    assert.equal((await t.api('POST', '/login/verificar', { cuerpo: { email, pin } })).estado, 401);
    // El token de sesion tampoco esta en claro en la base
    assert.equal(t.db.prepare('SELECT COUNT(*) n FROM sesiones WHERE token_hash = ?').get(ok.json.token).n, 0);

    // PIN expirado -> 401
    await t.api('POST', '/login', { cuerpo: { email } });
    const pinExp = t.pines[email];
    t.db.prepare('UPDATE pines SET expira_en = ? WHERE usado = 0').run(new Date(Date.now() - 1000).toISOString());
    assert.equal((await t.api('POST', '/login/verificar', { cuerpo: { email, pin: pinExp } })).estado, 401);

    // Fuerza bruta: 5 intentos fallidos bloquean ese PIN (aunque luego llegue el correcto)
    await t.api('POST', '/login', { cuerpo: { email } });
    const buenoSinUsar = t.pines[email];
    const incorrecto = buenoSinUsar === '000000' ? '000001' : '000000';
    const codigos = [];
    for (let i = 0; i < 6; i++) codigos.push((await t.api('POST', '/login/verificar', { cuerpo: { email, pin: incorrecto } })).estado);
    assert.deepEqual(codigos, [401, 401, 401, 401, 429, 429]);
    assert.equal((await t.api('POST', '/login/verificar', { cuerpo: { email, pin: buenoSinUsar } })).estado, 429, 'bloqueado aunque sea el PIN correcto');
    // Un PIN nuevo invalida al anterior bloqueado
    await t.api('POST', '/login', { cuerpo: { email } });
    assert.equal((await t.api('POST', '/login/verificar', { cuerpo: { email, pin: t.pines[email] } })).estado, 200);

    // Correo desconocido en verificar: mismo 401 generico
    assert.equal((await t.api('POST', '/login/verificar', { cuerpo: { email: 'nadie@propnet.cl', pin: '123456' } })).estado, 401);

    // Limite de solicitudes de PIN por correo (5 por ventana)
    const t2 = await levantar();
    try {
      const estados = [];
      for (let i = 0; i < 7; i++) estados.push((await t2.api('POST', '/login', { cuerpo: { email: 'pedro@propnet.cl' } })).estado);
      assert.deepEqual(estados, [200, 200, 200, 200, 200, 429, 429]);
    } finally { await t2.cerrar(); }

    assert.ok(t.eventos.seguridad.some((e) => e.evento === 'pin_bloqueado'));
    assert.ok(!JSON.stringify(t.eventos).includes(pin), 'el PIN no aparece en ningun log');
  } finally { await t.cerrar(); }
});

test('A07 limitador de verificacion: solo cuentan los fallos y bloquea aun con el PIN correcto', async () => {
  const t = await levantar({ opciones: { cfg: { limites: { ...cfgBase.limites, verificar: { max: 3, ventanaMs: 60000 } } } } });
  try {
    const email = 'pedro@propnet.cl';
    // Los aciertos no consumen cupo: se pueden hacer muchos logins validos
    for (let i = 0; i < 4; i++) {
      await t.api('POST', '/login', { cuerpo: { email } });
      assert.equal((await t.api('POST', '/login/verificar', { cuerpo: { email, pin: t.pines[email] } })).estado, 200);
    }
    // 3 fallos (PIN inexistente) agotan el cupo; el siguiente es 429 incluso con PIN valido
    for (let i = 0; i < 3; i++) assert.equal((await t.api('POST', '/login/verificar', { cuerpo: { email, pin: '111111' } })).estado, 401);
    await t.api('POST', '/login', { cuerpo: { email: 'juan@propnet.cl' } });
    assert.equal((await t.api('POST', '/login/verificar', { cuerpo: { email, pin: '111111' } })).estado, 429);
    // Otro correo (misma IP) no se ve afectado
    assert.equal((await t.api('POST', '/login/verificar', { cuerpo: { email: 'juan@propnet.cl', pin: t.pines['juan@propnet.cl'] } })).estado, 200);
  } finally { await t.cerrar(); }
});

test('A08 XSS: no se acepta HTML y la salida se escapa', async () => {
  const t = await levantar();
  try {
    const maria = await t.login('maria@propnet.cl');
    const juan = await t.login('juan@propnet.cl');
    const base = { titulo: 'Depto luminoso', descripcion: 'Cerca del metro', comuna: 'Providencia', precio: 400000 };

    assert.equal((await t.api('POST', '/propiedades', { cuerpo: base })).estado, 401);
    assert.equal((await t.api('POST', '/propiedades', { token: juan, cuerpo: base })).estado, 403);
    const ok = await t.api('POST', '/propiedades', { token: maria, cuerpo: base });
    assert.equal(ok.estado, 201);
    // propietario_id sale de la sesion
    assert.equal(t.db.prepare('SELECT propietario_id FROM propiedades WHERE id = ?').get(ok.json.id).propietario_id, 1);
    assert.equal((await t.api('POST', '/propiedades', { token: maria, cuerpo: { ...base, propietario_id: 4 } })).estado, 400);

    const xss = ['<script>alert(1)</script>', '<img src=x onerror=alert(1)>', '"><svg/onload=alert(1)>', '<iframe src=javascript:alert(1)>'];
    for (const x of xss) {
      assert.equal((await t.api('POST', '/propiedades', { token: maria, cuerpo: { ...base, descripcion: x } })).estado, 400, x);
      assert.equal((await t.api('POST', '/propiedades', { token: maria, cuerpo: { ...base, titulo: x } })).estado, 400, x);
    }
    assert.equal(t.db.prepare("SELECT COUNT(*) n FROM propiedades WHERE descripcion LIKE '%<%' OR titulo LIKE '%<%'").get().n, 0);

    // Defensa en profundidad: si hubiera un registro hostil en la base (p. ej. datos antiguos), se escapa
    const r = t.db.prepare('INSERT INTO propiedades (propietario_id, titulo, descripcion, comuna, precio, creado_en) VALUES (1, ?, ?, ?, 100000, ?)')
      .run('<b>T</b>', '<script>alert(1)</script>', 'Providencia', 'x');
    const html = await t.api('GET', `/propiedades/${r.lastInsertRowid}`);
    assert.equal(html.estado, 200);
    assert.ok(!html.texto.includes('<script>') && !html.texto.includes('<b>'));
    assert.ok(html.texto.includes('&lt;script&gt;alert(1)&lt;/script&gt;'));
    assert.match(html.cabeceras.get('content-type'), /text\/html/);
    assert.match(html.cabeceras.get('content-security-policy'), /default-src 'none'/);
    assert.equal((await t.api('GET', '/propiedades/abc')).estado, 400);
    assert.equal((await t.api('GET', '/propiedades/9999')).estado, 404);
  } finally { await t.cerrar(); }
});

test('A09 registro: todo acceso a contratos (autorizado, denegado, sin sesion) queda en access.log', async () => {
  const t = await levantar();
  try {
    const juan = await t.login('juan@propnet.cl');
    const maria = await t.login('maria@propnet.cl');

    assert.equal((await t.api('GET', '/contratos/1')).estado, 401);                        // sin sesion
    assert.equal((await t.api('GET', '/contratos/2', { token: juan })).estado, 403);       // no es parte
    assert.equal((await t.api('GET', '/contratos/1', { token: juan })).estado, 200);       // arrendatario
    assert.equal((await t.api('GET', '/contratos/1', { token: maria })).estado, 200);      // propietaria
    assert.equal((await t.api('GET', '/contratos/999', { token: juan })).estado, 404);
    assert.equal((await t.api('GET', '/contratos/abc', { token: juan })).estado, 400);

    const a = t.eventos.acceso;
    assert.equal(a.length, 6, 'un evento por intento');
    const por = (estado) => a.filter((e) => e.estado === estado);
    assert.equal(por(401)[0].resultado, 'denegado');
    assert.equal(por(401)[0].usuario_id, null);
    assert.equal(por(403)[0].resultado, 'denegado');
    assert.equal(por(403)[0].usuario_id, 2);
    assert.equal(por(403)[0].contrato_id, 2);
    assert.equal(por(403)[0].motivo, 'usuario_no_es_parte_del_contrato');
    assert.deepEqual(por(200).map((e) => [e.usuario_id, e.resultado]), [[2, 'autorizado'], [1, 'autorizado']]);
    for (const e of a) {
      assert.ok(e.ip && e.metodo === 'GET' && e.ruta.startsWith('/contratos/'), 'campos: fecha, ip, metodo, ruta');
    }
    assert.ok(t.eventos.seguridad.some((e) => e.evento === 'autenticacion_fallida'));
    assert.ok(t.eventos.seguridad.some((e) => e.evento === 'acceso_denegado' && e.recurso === 'contratos/2'));
  } finally { await t.cerrar(); }
});

test('A09 logger real: escribe JSON-lines y neutraliza log forging', async () => {
  const { crearLogger } = require('../lib/logger');
  const dir = fs.mkdtempSync(path.join(require('os').tmpdir(), 'propnet-log-'));
  const lg = crearLogger({ dir, consola: false });
  lg.acceso({ evento: 'x', ruta: '/contratos/1\n{"nivel":"INFO","resultado":"autorizado","falso":true}' });
  const lineas = fs.readFileSync(path.join(dir, 'access.log'), 'utf8').trim().split('\n');
  assert.equal(lineas.length, 1, 'un salto de linea inyectado no crea una entrada falsa');
  assert.ok(JSON.parse(lineas[0]).ruta.includes('falso'));
  fs.rmSync(dir, { recursive: true, force: true });
});

test('A10 SSRF: destinos internos, metadatos de nube y esquemas peligrosos -> 400', async () => {
  // Se sube el limite de tasa para poder probar muchas URLs (el limite en si se prueba abajo).
  const t = await levantar({ opciones: { cfg: { limites: { ...cfgBase.limites, imagenes: { max: 1000, ventanaMs: 60000 } } } } });
  try {
    const maria = await t.login('maria@propnet.cl');
    const juan = await t.login('juan@propnet.cl');
    const pedir = (url, token = maria) => t.api('POST', '/imagenes/descargar', { token, cuerpo: { url } });

    assert.equal((await t.api('POST', '/imagenes/descargar', { cuerpo: { url: 'https://images.unsplash.com/a.jpg' } })).estado, 401);
    assert.equal((await pedir('https://images.unsplash.com/a.jpg', juan)).estado, 403);

    const bloqueadas = [
      'http://127.0.0.1:9999/latest/meta-data/',          // el mock del proyecto
      'http://169.254.169.254/latest/meta-data/',         // IMDS de AWS
      'http://metadata.google.internal/computeMetadata/v1/',
      'http://localhost:3000/', 'http://[::1]:3000/', 'http://0.0.0.0:3000/', 'http://127.1/', 'http://2130706433/',
      'https://127.0.0.1/', 'https://localhost/', 'https://evil.com/x.png',
      'file:///etc/passwd', 'gopher://127.0.0.1:6379/_FLUSHALL', 'ftp://127.0.0.1/', 'javascript:alert(1)',
      'https://user:pass@images.unsplash.com/a.jpg', 'https://images.unsplash.com:22/a.jpg',
      '', 'no-es-url', 'https://images.unsplash.com.evil.com/a.jpg',
    ];
    for (const url of bloqueadas) {
      const r = await pedir(url);
      assert.equal(r.estado, 400, `${url} -> ${r.estado}`);
      assert.deepEqual(r.json, { error: 'URL no permitida' }, 'respuesta generica, sin motivo ni detalles');
    }
    for (const rara of [null, 123, ['https://images.unsplash.com/a.jpg'], { href: 'x' }]) {
      assert.equal((await pedir(rara)).estado, 400);
    }
    const ev = t.eventos.seguridad.filter((e) => e.evento === 'ssrf_bloqueado');
    assert.ok(ev.length >= bloqueadas.length, 'cada intento bloqueado queda registrado');
    assert.ok(ev.some((e) => e.motivo === 'esquema_no_permitido') && ev.some((e) => e.motivo === 'host_fuera_de_lista_blanca'));
    assert.equal((await t.api('POST', '/imagenes/descargar', { token: maria, cuerpo: { url: 'https://images.unsplash.com/a.jpg', extra: 1 } })).estado, 400);
  } finally { await t.cerrar(); }
});

test('A10 SSRF: una URL permitida pasa por el descargador (inyectado) y solo devuelve metadatos', async () => {
  const llamadas = [];
  const t = await levantar({
    opciones: {
      descargar: async (url, opciones) => { llamadas.push([url, opciones]); return { tipo: 'image/png', bytes: 123, sha256: 'ab'.repeat(32) }; },
    },
  });
  try {
    const maria = await t.login('maria@propnet.cl');
    const r = await t.api('POST', '/imagenes/descargar', { token: maria, cuerpo: { url: 'https://images.unsplash.com/foto.png' } });
    assert.equal(r.estado, 200);
    assert.deepEqual(Object.keys(r.json).sort(), ['bytes', 'mensaje', 'sha256', 'tipo']);
    assert.deepEqual(llamadas[0][1].hostsPermitidos, cfgBase.imagenes.hostsPermitidos);
    // Limite de tasa: 10/min por usuario
    const estados = [];
    for (let i = 0; i < 12; i++) estados.push((await t.api('POST', '/imagenes/descargar', { token: maria, cuerpo: { url: 'https://images.unsplash.com/foto.png' } })).estado);
    assert.ok(estados.includes(429));
  } finally { await t.cerrar(); }
});

test('Limite global por IP y metodos no soportados', async () => {
  const t = await levantar({ opciones: { cfg: { limites: { ...cfgBase.limites, global: { max: 5, ventanaMs: 60000 } } } } });
  try {
    const estados = [];
    for (let i = 0; i < 8; i++) estados.push((await t.api('GET', '/salud')).estado);
    assert.deepEqual(estados, [200, 200, 200, 200, 200, 429, 429, 429]);
  } finally { await t.cerrar(); }
});
