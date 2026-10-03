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

const crypto = require('crypto');

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
// MITIGACIÓN A01: Control de acceso y Zero Trust Input
// ---------------------------------------------------------------

// 1. Middleware simulado de Autenticación (se asume que el frontend envía el ID del usuario en un header tras loguearse)
// En una implementación real más robusta (para mitigar A07), aquí validarías un token JWT.
function verificarAutenticacion(req, res, next) {
  const userId = req.headers['x-usuario-id'];
  
  // Validamos que el header exista y sea solo numérico (Regex)
  if (!userId || !/^\d+$/.test(userId)) {
    return res.status(401).json({ error: 'No autorizado. Faltan credenciales válidas.' });
  }
  
  // Guardamos el usuario autenticado en la request para las siguientes validaciones
  req.usuarioAuth = { id: parseInt(userId, 10) };
  next();
}

// 2. Ruta segura de actualización de usuarios
app.put('/usuarios/:id', verificarAutenticacion, (req, res) => {
  const { id } = req.params;
  const { nombre, telefono, valor_arriendo_referencia } = req.body;

  // A) ZERO TRUST INPUT: Listas blancas estrictas y expresiones regulares
  if (!/^\d+$/.test(id)) return res.status(400).json({ error: 'ID de usuario inválido' });
  
  if (nombre && !/^[a-zA-ZáéíóúÁÉÍÓÚñÑ\s]{3,50}$/.test(nombre)) {
    return res.status(400).json({ error: 'Nombre contiene caracteres no permitidos' });
  }
  
  if (telefono && !/^\+?[0-9]{9,15}$/.test(telefono)) {
    return res.status(400).json({ error: 'Formato de teléfono inválido' });
  }
  
  if (valor_arriendo_referencia && (!Number.isInteger(valor_arriendo_referencia) || valor_arriendo_referencia < 0)) {
    return res.status(400).json({ error: 'Valor de arriendo debe ser un número entero positivo' });
  }

  // B) CONTROL DE ACCESO (Autorización)
  // Comprobamos si el usuario logueado es el mismo que el del ID que se quiere modificar
  if (req.usuarioAuth.id !== parseInt(id, 10)) {
    return res.status(403).json({ error: 'Prohibido: Solo puedes modificar tu propio perfil' });
  }

  // C) EJECUCIÓN SEGURA
  db.prepare(
    'UPDATE usuarios SET nombre = ?, telefono = ?, valor_arriendo_referencia = ? WHERE id = ?'
  ).run(nombre, telefono, valor_arriendo_referencia, id);
  
  res.json({ mensaje: 'Usuario actualizado de forma segura', id });
});

// 3. Ruta segura de actualización de arriendos
app.put('/arriendos/:id', verificarAutenticacion, (req, res) => {
  const { id } = req.params; 
  const { precio } = req.body;

  // A) ZERO TRUST INPUT
  if (!/^\d+$/.test(id)) return res.status(400).json({ error: 'ID de propiedad inválido' });
  if (!Number.isInteger(precio) || precio <= 0) return res.status(400).json({ error: 'El precio debe ser mayor a 0' });

  // B) CONTROL DE ACCESO (Autorización)
  // Buscamos a quién le pertenece la propiedad
  const propiedad = db.prepare('SELECT propietario_id FROM propiedades WHERE id = ?').get(id);
  
  if (!propiedad) {
    return res.status(404).json({ error: 'Propiedad no encontrada' });
  }

  // Comprobamos si el usuario logueado es el dueño
  if (propiedad.propietario_id !== req.usuarioAuth.id) {
    return res.status(403).json({ error: 'Prohibido: No eres el propietario de este inmueble' });
  }

  // C) EJECUCIÓN SEGURA
  db.prepare('UPDATE propiedades SET precio = ? WHERE id = ?').run(precio, id);
  res.json({ mensaje: 'Valor de arriendo actualizado de forma segura', id, precio });
});

// ---------------------------------------------------------------
// MITIGACIÓN A02: Fallas criptográficas y Zero Trust Input
// ---------------------------------------------------------------
// Nota: Se agrega el middleware 'verificarAutenticacion' del paso A01 para proteger la ruta
app.post('/contratos', verificarAutenticacion, (req, res) => {
  const { propiedad_id, arrendatario_id, confidencial } = req.body;

  // A) ZERO TRUST INPUT: Validamos que los IDs sean números enteros positivos
  if (!Number.isInteger(propiedad_id) || propiedad_id <= 0) {
    return res.status(400).json({ error: 'ID de propiedad inválido' });
  }
  if (!Number.isInteger(arrendatario_id) || arrendatario_id <= 0) {
    return res.status(400).json({ error: 'ID de arrendatario inválido' });
  }
  
  // Limpiamos y limitamos el texto confidencial (evita inputs excesivamente largos)
  const textoSeguro = (typeof confidencial === 'string') 
    ? confidencial.substring(0, 255) 
    : '';

  // B) MITIGACIÓN CRIPTOGRÁFICA (Hashing)
  // Generamos un token seguro usando bytes aleatorios en lugar de Math.random()
  const tokenPlano = crypto.randomBytes(16).toString('hex');
  
  // Aplicamos un hash SHA-256 al token antes de tocar la base de datos
  const tokenHash = crypto.createHash('sha256').update(tokenPlano).digest('hex');

  // C) EJECUCIÓN SEGURA
  db.prepare(
    'INSERT INTO contratos (propiedad_id, arrendatario_id, token_verificacion, confidencial) VALUES (?, ?, ?, ?)'
  ).run(propiedad_id, arrendatario_id, tokenHash, textoSeguro);
  
  // Según el ASC.md: "nunca se devuelve en claro". Devolvemos solo un mensaje genérico.
  res.json({ 
    mensaje: 'Contrato creado de forma segura',
    identificador_seguro: 'Token generado y almacenado con hash' // Evitamos exponer el token original
  }); 
});

// ---------------------------------------------------------------
// MITIGACIÓN A03: Prevención de Inyección SQL y Zero Trust Input
// ---------------------------------------------------------------
app.get('/propiedades/buscar', (req, res) => {
  const { comuna = '', precio_max = '999999999' } = req.query;

  // A) ZERO TRUST INPUT: Regex para el precio (solo números positivos)
  // Rechaza cualquier intento de inyección de código como "NOT_A_NUMBER); DROP TABLE..."
  if (!/^\d+$/.test(precio_max)) {
    return res.status(400).json({ error: 'El precio máximo debe ser un valor numérico válido' });
  }

  // B) ZERO TRUST INPUT: Lista blanca estricta para las comunas permitidas
  const comunasPermitidas = ['Providencia', 'Ñuñoa', 'Santiago', 'Las Condes', 'Macul', ''];
  
  if (!comunasPermitidas.includes(comuna)) {
    return res.status(400).json({ error: 'Comuna no válida o fuera del área de cobertura' });
  }

  try {
    // C) EJECUCIÓN SEGURA CON CONSULTAS PARAMETRIZADAS
    // Se elimina "db.rawQuery" (que concatenaba texto) y se usa "db.prepare().all()"
    // El motor SQLite se encarga de escapar los caracteres peligrosos de forma segura.
    const resultados = db.prepare(
      'SELECT * FROM propiedades WHERE comuna LIKE ? AND precio <= ?'
    ).all(`%${comuna}%`, parseInt(precio_max, 10));
    
    res.json(resultados);
  } catch (err) {
    // Manejo seguro del error (Sin exponer Stack Traces, mitigando también A05)
    console.error('Error interno de DB en /propiedades/buscar:', err.message);
    res.status(500).json({ error: 'Error al procesar la búsqueda' });
  }
});

// ---------------------------------------------------------------
// MITIGACIÓN A04: Control de Conflictos (Diseño Seguro) y Zero Trust Input
// ---------------------------------------------------------------
// Nota: También se recomienda agregar 'verificarAutenticacion' aquí para que solo usuarios logueados agenden visitas
app.post('/visitas', verificarAutenticacion, (req, res) => {
  const { propiedad_id, fecha, hora, visitante } = req.body;

  // A) ZERO TRUST INPUT: Validaciones estrictas con Expresiones Regulares (Regex)
  if (!Number.isInteger(propiedad_id) || propiedad_id <= 0) {
    return res.status(400).json({ error: 'ID de propiedad inválido' });
  }
  
  // Validamos que la fecha tenga estrictamente el formato YYYY-MM-DD
  if (!/^\d{4}-\d{2}-\d{2}$/.test(fecha)) {
    return res.status(400).json({ error: 'Formato de fecha inválido. Use YYYY-MM-DD' });
  }
  
  // Validamos que la hora tenga estrictamente el formato HH:MM (24 horas)
  if (!/^([01]\d|2[0-3]):([0-5]\d)$/.test(hora)) {
    return res.status(400).json({ error: 'Formato de hora inválido. Use HH:MM' });
  }
  
  // Validamos el nombre del visitante (solo letras y espacios, previniendo inyección/XSS)
  if (!/^[a-zA-ZáéíóúÁÉÍÓÚñÑ\s]{3,50}$/.test(visitante)) {
    return res.status(400).json({ error: 'Nombre de visitante inválido o contiene caracteres no permitidos' });
  }

  // B) CONTROL DE CONFLICTOS (Lógica de Negocio Segura)
  // Consultamos a la base de datos si ya existe un registro con la misma propiedad, fecha y hora
  const visitaExistente = db.prepare(
    'SELECT id FROM visitas WHERE propiedad_id = ? AND fecha = ? AND hora = ?'
  ).get(propiedad_id, fecha, hora);

  if (visitaExistente) {
    // Si la visita ya existe, devolvemos el código HTTP 409 (Conflict) exigido por la pauta ASC
    return res.status(409).json({ error: 'Conflicto: La propiedad ya está reservada en ese horario' });
  }

  // C) EJECUCIÓN SEGURA
  db.prepare(
    'INSERT INTO visitas (propiedad_id, fecha, hora, visitante) VALUES (?, ?, ?, ?)'
  ).run(propiedad_id, fecha, hora, visitante);
  
  res.status(201).json({ mensaje: 'Visita agendada con éxito', propiedad_id, fecha, hora });
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
// MITIGACIÓN A05: Manejo Seguro de Errores (Sin fuga de información)
// ---------------------------------------------------------------

// Middleware global de manejo de errores en Express
app.use((err, req, res, next) => {
  // A) REGISTRO INTERNO SEGURO (Logging)
  console.error(`[ERROR CRÍTICO] - ${new Date().toISOString()}`);
  console.error(`Ruta: ${req.method} ${req.originalUrl}`);
  console.error(err.stack);

  // B) RESPUESTA DEFENSIVA AL CLIENTE
  res.status(500).json({
    error: 'Ocurrió un error interno en el servidor. Nuestro equipo ha sido notificado.'
  });
});

// ¡IMPORTANTE! Aquí debe ir el bloque app.listen antes de cerrar main()
app.listen(PORT, () => {
  console.log(`PropNet API (SEGURA) escuchando en http://localhost:${PORT}`);
  console.log('Fase 2 completada: Refactorización y Mitigación Integral.');
});

} // fin main()

main().catch((err) => {
  console.error('Error al iniciar el servidor:', err);
  process.exit(1);
});
