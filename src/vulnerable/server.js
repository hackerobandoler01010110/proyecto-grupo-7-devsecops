// server.js - PropNet API (VERSION VULNERABLE a proposito, Grupo 7 - OWASP Top 10)
// Uso academico: auditoria DevSecOps. NO desplegar en produccion ni exponer a internet.

const express = require('express');
const fetch = require('node-fetch');
const { abrirBaseDatos } = require('./db');

const app = express();
app.use(express.json());

const PORT = 3000;

async function main() {
const db = await abrirBaseDatos();

// ---------------------------------------------------------------
// A07: Autenticacion debil con PIN numerico de 3 digitos, sin expiracion
// ---------------------------------------------------------------
app.post('/login', (req, res) => {
  const { email } = req.body;
  const usuario = db.prepare('SELECT * FROM usuarios WHERE email = ?').get(email);
  if (!usuario) return res.status(404).json({ error: 'Usuario no encontrado' });

  const pin = String(Math.floor(100 + Math.random() * 900)); // 3 digitos, ej: 100-999
  db.prepare('INSERT INTO pines (usuario_id, pin, creado_en) VALUES (?, ?, ?)')
    .run(usuario.id, pin, new Date().toISOString());

  // "Envio por SMS" simulado -> en realidad se imprime en consola/log del servidor
  console.log(`[SMS SIMULADO] PIN para ${usuario.email}: ${pin}`);
  res.json({ mensaje: 'PIN enviado por SMS', usuario_id: usuario.id });
});

app.post('/login/verificar', (req, res) => {
  const { usuario_id, pin } = req.body;
  // No hay expiracion, no hay limite de intentos, no se invalida tras el uso
  const registro = db.prepare(
    'SELECT * FROM pines WHERE usuario_id = ? AND pin = ? ORDER BY id DESC LIMIT 1'
  ).get(usuario_id, pin);

  if (registro) {
    return res.json({ autenticado: true, usuario_id });
  }
  res.status(401).json({ autenticado: false });
});

// ---------------------------------------------------------------
// A01: Control de acceso roto - cualquiera puede modificar datos de
// cualquier usuario o el valor de arriendos, sin verificar quien hace la peticion
// ---------------------------------------------------------------
app.put('/usuarios/:id', (req, res) => {
  const { id } = req.params;
  const { nombre, telefono, valor_arriendo_referencia } = req.body;
  // No se valida token/sesion ni que el solicitante sea el dueno del recurso
  db.prepare(
    'UPDATE usuarios SET nombre = ?, telefono = ?, valor_arriendo_referencia = ? WHERE id = ?'
  ).run(nombre, telefono, valor_arriendo_referencia, id);
  res.json({ mensaje: 'Usuario actualizado', id });
});

app.put('/arriendos/:id', (req, res) => {
  const { id } = req.params; // id de propiedad
  const { precio } = req.body;
  // Cualquier arrendatario puede cambiar el precio de cualquier propiedad
  db.prepare('UPDATE propiedades SET precio = ? WHERE id = ?').run(precio, id);
  res.json({ mensaje: 'Valor de arriendo actualizado', id, precio });
});

// ---------------------------------------------------------------
// A02: Fallas criptograficas - token de contrato guardado y devuelto en texto plano
// ---------------------------------------------------------------
app.post('/contratos', (req, res) => {
  const { propiedad_id, arrendatario_id, confidencial } = req.body;
  const token = 'TKN-' + Math.floor(Math.random() * 99999);
  db.prepare(
    'INSERT INTO contratos (propiedad_id, arrendatario_id, token_verificacion, confidencial) VALUES (?, ?, ?, ?)'
  ).run(propiedad_id, arrendatario_id, token, confidencial || '');
  res.json({ mensaje: 'Contrato creado', token_verificacion: token }); // se filtra en texto plano
});

// ---------------------------------------------------------------
// A03: Inyeccion SQL en el buscador avanzado (concatenacion directa)
// ---------------------------------------------------------------
app.get('/propiedades/buscar', (req, res) => {
  const { comuna = '', precio_max = '999999999' } = req.query;
  // Concatenacion directa de entrada del usuario dentro del SQL (vulnerable a proposito)
  const sql = `SELECT * FROM propiedades WHERE comuna LIKE '%${comuna}%' AND precio <= ${precio_max}`;
  try {
    const resultados = db.rawQuery(sql);
    res.json(resultados);
  } catch (err) {
    next_vuln_error(err, res); // ver A05 mas abajo
  }
});

// ---------------------------------------------------------------
// A04: Fallas de diseno - se puede reservar la misma propiedad
// multiples veces en el mismo horario, sin control de conflictos
// ---------------------------------------------------------------
app.post('/visitas', (req, res) => {
  const { propiedad_id, fecha, hora, visitante } = req.body;
  // No se verifica si ya existe una visita en ese mismo horario
  db.prepare(
    'INSERT INTO visitas (propiedad_id, fecha, hora, visitante) VALUES (?, ?, ?, ?)'
  ).run(propiedad_id, fecha, hora, visitante);
  res.json({ mensaje: 'Visita agendada sin control de conflictos', propiedad_id, fecha, hora });
});

// ---------------------------------------------------------------
// A08: XSS persistente - descripcion de propiedad acepta HTML sin sanitizar
// ---------------------------------------------------------------
app.post('/propiedades', (req, res) => {
  const { propietario_id, titulo, descripcion, comuna, precio } = req.body;
  db.prepare(
    'INSERT INTO propiedades (propietario_id, titulo, descripcion, comuna, precio) VALUES (?, ?, ?, ?, ?)'
  ).run(propietario_id, titulo, descripcion, comuna, precio); // descripcion se guarda tal cual, con HTML/<script>
  res.json({ mensaje: 'Propiedad publicada' });
});

app.get('/propiedades/:id', (req, res) => {
  const prop = db.prepare('SELECT * FROM propiedades WHERE id = ?').get(req.params.id);
  if (!prop) return res.status(404).json({ error: 'No encontrada' });
  // Se devuelve/renderiza la descripcion sin escapar -> XSS persistente si se ve en un front sin sanitizar
  res.send(`<h1>${prop.titulo}</h1><div>${prop.descripcion}</div>`);
});

// ---------------------------------------------------------------
// A09: Fallas de registro - acceso a contratos confidenciales sin log alguno
// ---------------------------------------------------------------
app.get('/contratos/:id', (req, res) => {
  const contrato = db.prepare('SELECT * FROM contratos WHERE id = ?').get(req.params.id);
  // No se valida quien pide el contrato, y tampoco se registra el acceso (autorizado o no)
  if (!contrato) return res.status(404).json({ error: 'No encontrado' });
  res.json(contrato);
});

// ---------------------------------------------------------------
// A10: SSRF - descarga de imagenes desde URL externa sin ninguna validacion,
// permite consultar endpoints internos (ej. metadatos de nube)
// ---------------------------------------------------------------
app.post('/imagenes/descargar', async (req, res) => {
  const { url } = req.body;
  try {
    // Sin lista blanca de dominios, sin bloqueo de IPs privadas/locales
    const respuesta = await fetch(url);
    const contenido = await respuesta.text();
    res.json({ mensaje: 'Descarga completada', url, contenido_parcial: contenido.slice(0, 500) });
  } catch (err) {
    next_vuln_error(err, res);
  }
});

// ---------------------------------------------------------------
// A05: Manejo inseguro de errores - se expone el stack trace completo,
// revelando rutas absolutas del servidor
// ---------------------------------------------------------------
function next_vuln_error(err, res) {
  res.status(500).json({
    error: 'Error interno',
    stack: err.stack, // revela rutas absolutas, ej: /home/usuario/propnet/src/vulnerable/server.js
  });
}

app.use((err, req, res, next) => {
  next_vuln_error(err, res);
});

app.listen(PORT, () => {
  console.log(`PropNet API (VULNERABLE) escuchando en http://localhost:${PORT}`);
  console.log('Uso academico unicamente. No exponer a redes publicas.');
});

} // fin main()

main().catch((err) => {
  console.error('Error al iniciar el servidor:', err);
  process.exit(1);
});
