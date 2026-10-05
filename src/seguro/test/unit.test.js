'use strict';
// Pruebas unitarias de los modulos de seguridad. Ejecutar: npm test
process.env.PROPNET_SECRET = process.env.PROPNET_SECRET || 'a'.repeat(64);
process.env.LOG_CONSOLA = 'false';

const test = require('node:test');
const assert = require('node:assert/strict');

const { v, ErrorValidacion, escaparHtml, soloCampos } = require('../lib/validacion');
const { esIpPrivada, validarUrl, resolverPublico, ErrorSsrf } = require('../lib/ssrf');
const { crearCripto } = require('../lib/cripto');
const { crearLimitador } = require('../lib/limitador');

const lanza = (fn) => assert.throws(fn, ErrorValidacion);

test('A03 validacion: comuna solo de la lista blanca (insensible a acentos/mayusculas)', () => {
  assert.equal(v.comuna('providencia'), 'Providencia');
  assert.equal(v.comuna('NUNOA'), 'Ñuñoa');
  assert.equal(v.comuna('viña del mar'), 'Viña del Mar');
  for (const mala of ["' OR '1'='1", 'Providencia; DROP TABLE propiedades', '%', 'Atlantida', '', 123, null, ['Providencia']]) {
    lanza(() => v.comuna(mala));
  }
});

test('A03 validacion: precio_max solo digitos', () => {
  assert.equal(v.enteroTexto('500000', 'precio_max', 0, 999999999), 500000);
  for (const mala of ['1 OR 1=1', '1; DROP TABLE x', '-1', '1e3', '0x10', '', '1234567890', ' 5', 5, ['1']]) {
    lanza(() => v.enteroTexto(mala, 'precio_max', 0, 999999999));
  }
});

test('A08 validacion: descripcion rechaza HTML y acepta texto normal', () => {
  assert.ok(v.descripcion('Luminoso depto, cerca del metro. Arriendo $450.000 (gastos comunes aparte).'));
  assert.ok(v.descripcion('Línea 1\nLínea 2'));
  for (const mala of [
    '<script>alert(1)</script>', '<img src=x onerror=alert(1)>', 'a > b', 'x=1', '`ls`', 'a|b', 'x\u0000y',
  ]) {
    lanza(() => v.descripcion(mala));
  }
  lanza(() => v.descripcion('a'.repeat(1001)));
  lanza(() => v.descripcion(''));
});

test('A08 escape de salida', () => {
  assert.equal(escaparHtml('<script>alert("x")</script>&\''), '&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;&amp;&#39;');
});

test('validacion: ids, enteros, email, telefono, nombre', () => {
  assert.equal(v.id('12'), 12);
  assert.equal(v.id(7), 7);
  for (const mal of ['0', '-1', '1.5', '1 OR 1=1', '01', 'abc', '', null, undefined, {}, 1234567890]) lanza(() => v.id(mal));
  assert.equal(v.entero(500000, 'precio', 10000, 50000000), 500000);
  for (const mal of [1, '500000', 1.5, NaN, Infinity, 50000001, -5, null]) lanza(() => v.entero(mal, 'precio', 10000, 50000000));
  assert.equal(v.email('  Maria@PropNet.cl '), 'maria@propnet.cl');
  for (const mal of ['x', 'a@b', '<a@b.cl', 'a b@c.cl', 'a@b..cl', 'a'.repeat(300) + '@b.cl', 5]) lanza(() => v.email(mal));
  assert.equal(v.telefono('+56911111111'), '+56911111111');
  for (const mal of ['123', '+56 9 1111 1111', '+56911111111; x', 'abc']) lanza(() => v.telefono(mal));
  assert.equal(v.nombre('María José O\'Higgins'), 'María José O\'Higgins');
  for (const mal of ['<b>x</b>', 'A', '1abc', 'x'.repeat(61)]) lanza(() => v.nombre(mal));
});

test('A04 validacion: fecha real y futura, hora en slots', () => {
  const ahora = new Date('2026-10-04T12:00:00Z');
  assert.equal(v.fecha('2026-10-10', 'fecha', { ahora }), '2026-10-10');
  assert.equal(v.fecha('2026-10-04', 'fecha', { ahora }), '2026-10-04'); // hoy
  for (const mala of ['2026-10-03', '2026-02-30', '2026-13-01', '2027-12-01', '10-10-2026', '2026-10-10T10:00', '0000-01-01', 20261010]) {
    lanza(() => v.fecha(mala, 'fecha', { ahora }));
  }
  assert.equal(v.hora('09:00'), '09:00');
  assert.equal(v.hora('18:30'), '18:30');
  for (const mala of ['08:30', '19:00', '10:15', '9:00', '24:00', '10:00:00', '10:00; x']) lanza(() => v.hora(mala));
});

test('mass assignment: campos no permitidos se rechazan (incl. __proto__)', () => {
  soloCampos({ nombre: 'x' }, ['nombre', 'telefono']);
  lanza(() => soloCampos({ nombre: 'x', rol: 'admin' }, ['nombre']));
  lanza(() => soloCampos(JSON.parse('{"__proto__": {"rol": "admin"}}'), ['nombre']));
});

test('A10 esIpPrivada: rangos privados, loopback, link-local y mapeadas', () => {
  const bloqueadas = [
    '127.0.0.1', '127.1.2.3', '10.0.0.5', '172.16.0.1', '172.31.255.255', '192.168.1.1',
    '169.254.169.254', '169.254.0.1', '100.64.0.1', '0.0.0.0', '224.0.0.1', '255.255.255.255',
    '::1', '::', 'fe80::1', 'fc00::1', 'fd12:3456::1', '::ffff:127.0.0.1', '::ffff:7f00:1', '::ffff:a9fe:a9fe',
    'no-es-ip',
  ];
  for (const ip of bloqueadas) assert.equal(esIpPrivada(ip), true, `${ip} deberia estar bloqueada`);
  for (const ip of ['8.8.8.8', '1.1.1.1', '151.101.1.1', '172.32.0.1', '2606:4700:4700::1111']) {
    assert.equal(esIpPrivada(ip), false, `${ip} deberia permitirse`);
  }
});

test('A10 validarUrl: lista blanca, https, sin IP literal ni credenciales', () => {
  const opciones = { hostsPermitidos: ['images.unsplash.com'] };
  assert.equal(validarUrl('https://images.unsplash.com/photo-1.jpg?w=800', opciones).host, 'images.unsplash.com');
  assert.equal(validarUrl('https://IMAGES.unsplash.com./a.png', opciones).host, 'images.unsplash.com');
  const motivos = {
    'http://images.unsplash.com/a.jpg': 'esquema_no_permitido',
    'ftp://images.unsplash.com/a.jpg': 'esquema_no_permitido',
    'file:///etc/passwd': 'esquema_no_permitido',
    'gopher://127.0.0.1:6379/_x': 'esquema_no_permitido',
    'https://127.0.0.1/': 'ip_literal',
    'https://127.0.0.1:9999/latest/meta-data/': 'puerto_no_permitido',
    'https://169.254.169.254/latest/meta-data/': 'ip_literal',
    'https://[::1]/': 'ip_literal',
    'https://[::ffff:127.0.0.1]/': 'ip_literal',
    'https://2130706433/': 'ip_literal',
    'https://0x7f.1/': 'ip_literal',
    'https://017700000001/': 'ip_literal',
    'https://localhost/': 'host_fuera_de_lista_blanca',
    'https://evil.com/': 'host_fuera_de_lista_blanca',
    'https://images.unsplash.com.evil.com/': 'host_fuera_de_lista_blanca',
    'https://evil.com#@images.unsplash.com/': 'host_fuera_de_lista_blanca',
    'https://images.unsplash.com@evil.com/': 'credenciales_en_url', // el "host" visible es en realidad userinfo
    'https://user:pass@images.unsplash.com/': 'credenciales_en_url',
    'https://images.unsplash.com:8443/': 'puerto_no_permitido',
    'no es una url': 'no_parseable',
  };
  for (const [url, motivo] of Object.entries(motivos)) {
    assert.throws(() => validarUrl(url, opciones), (e) => e instanceof ErrorSsrf && e.motivo === motivo, `${url} -> ${motivo}`);
  }
  for (const rara of [null, undefined, 5, {}, '', 'https://images.unsplash.com/' + 'a'.repeat(3000)]) {
    assert.throws(() => validarUrl(rara, opciones), ErrorSsrf);
  }
});

test('A10 resolverPublico: bloquea si CUALQUIER direccion resuelta es privada (DNS rebinding)', async () => {
  const resolverDe = (lista) => async () => lista;
  const ok = await resolverPublico('x.com', resolverDe([{ address: '8.8.8.8', family: 4 }]));
  assert.equal(ok.address, '8.8.8.8');
  await assert.rejects(resolverPublico('x.com', resolverDe([{ address: '127.0.0.1', family: 4 }])), (e) => e.motivo === 'resuelve_a_ip_privada');
  await assert.rejects(resolverPublico('x.com', resolverDe([{ address: '8.8.8.8', family: 4 }, { address: '169.254.169.254', family: 4 }])), (e) => e.motivo === 'resuelve_a_ip_privada');
  await assert.rejects(resolverPublico('x.com', resolverDe([{ address: '::1', family: 6 }])), (e) => e.motivo === 'resuelve_a_ip_privada');
  await assert.rejects(resolverPublico('x.com', resolverDe([])), (e) => e.motivo === 'sin_resolucion');
  await assert.rejects(resolverPublico('x.com', async () => { throw new Error('ENOTFOUND'); }), (e) => e.motivo === 'dns_fallo');
});

test('A02 cripto: hash, tokens, PIN y cifrado', () => {
  const c = crearCripto('b'.repeat(64));
  const t1 = c.generarToken();
  assert.match(t1, /^[a-f0-9]{64}$/);
  assert.notEqual(t1, c.generarToken());
  assert.match(c.hmac('contrato', t1), /^[a-f0-9]{64}$/);
  assert.equal(c.hmac('contrato', t1), c.hmac('contrato', t1));
  assert.notEqual(c.hmac('contrato', t1), c.hmac('sesion', t1));       // separacion de dominios
  assert.notEqual(c.hmac('contrato', t1), t1);                          // nunca el valor en claro
  assert.notEqual(c.hmac('contrato', t1), crearCripto('c'.repeat(64)).hmac('contrato', t1)); // depende del secreto
  assert.equal(c.iguales('abc', 'abc'), true);
  assert.equal(c.iguales('abc', 'abd'), false);
  assert.equal(c.iguales('abc', 'abcd'), false);

  for (let i = 0; i < 2000; i++) assert.match(c.generarPin(), /^\d{6}$/);

  const secreto = 'Renta liquida $450.000, aval: Maria';
  const p = c.cifrar(secreto);
  assert.ok(!p.includes('Renta'));
  assert.equal(c.descifrar(p), secreto);
  assert.notEqual(c.cifrar(secreto), p); // IV aleatorio
  assert.equal(c.descifrar(c.cifrar('')), '');
  const partes = p.split('.');
  const manipulado = [partes[0], partes[1], partes[2], Buffer.from('otra cosa').toString('base64')].join('.');
  assert.throws(() => c.descifrar(manipulado)); // GCM detecta manipulacion
  assert.throws(() => c.descifrar('basura'));
});

test('A07 limitador: bloquea al superar el maximo y reinicia por ventana', async () => {
  const l = crearLimitador({ max: 3, ventanaMs: 80 });
  assert.equal(l.consumir('k').permitido, true);
  assert.equal(l.consumir('k').permitido, true);
  assert.equal(l.consumir('k').permitido, true);
  const r = l.consumir('k');
  assert.equal(r.permitido, false);
  assert.ok(r.reintentoSeg >= 1);
  assert.equal(l.consumir('otra').permitido, true); // claves independientes
  await new Promise((res) => setTimeout(res, 100));
  assert.equal(l.consumir('k').permitido, true);
});
