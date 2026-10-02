// seed.js - Crea la base de datos SQLite con datos de prueba para PropNet
const { abrirBaseDatos } = require('./db');

async function main() {
const db = await abrirBaseDatos();

db.exec(`
DROP TABLE IF EXISTS usuarios;
DROP TABLE IF EXISTS propiedades;
DROP TABLE IF EXISTS contratos;
DROP TABLE IF EXISTS visitas;
DROP TABLE IF EXISTS pines;

CREATE TABLE usuarios (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  nombre TEXT,
  email TEXT UNIQUE,
  telefono TEXT,
  rol TEXT, -- 'propietario' | 'arrendatario'
  valor_arriendo_referencia INTEGER
);

CREATE TABLE propiedades (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  propietario_id INTEGER,
  titulo TEXT,
  descripcion TEXT, -- HTML sin sanitizar (A08)
  comuna TEXT,
  precio INTEGER
);

CREATE TABLE contratos (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  propiedad_id INTEGER,
  arrendatario_id INTEGER,
  token_verificacion TEXT, -- guardado en texto plano (A02)
  confidencial TEXT
);

CREATE TABLE visitas (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  propiedad_id INTEGER,
  fecha TEXT,
  hora TEXT,
  visitante TEXT
);

CREATE TABLE pines (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  usuario_id INTEGER,
  pin TEXT, -- 3 digitos (A07)
  creado_en TEXT
);
`);

const insertUsuario = db.prepare(
  `INSERT INTO usuarios (nombre, email, telefono, rol, valor_arriendo_referencia) VALUES (?, ?, ?, ?, ?)`
);
insertUsuario.run('Maria Propietaria', 'maria@propnet.cl', '+56911111111', 'propietario', 500000);
insertUsuario.run('Juan Arrendatario', 'juan@propnet.cl', '+56922222222', 'arrendatario', null);

const insertPropiedad = db.prepare(
  `INSERT INTO propiedades (propietario_id, titulo, descripcion, comuna, precio) VALUES (?, ?, ?, ?, ?)`
);
insertPropiedad.run(1, 'Depto 2D1B Providencia', 'Luminoso depto cerca del metro.', 'Providencia', 450000);
insertPropiedad.run(1, 'Casa 3D2B Ñuñoa', 'Casa con patio, ideal para familia.', 'Ñuñoa', 700000);

const insertContrato = db.prepare(
  `INSERT INTO contratos (propiedad_id, arrendatario_id, token_verificacion, confidencial) VALUES (?, ?, ?, ?)`
);
insertContrato.run(1, 2, 'TKN-83920', 'Renta liquida mensual $450.000, aval: Maria Propietaria');

console.log('Base de datos propnet.db creada con datos de prueba.');
db.close();
}

main().catch((err) => {
  console.error('Error al crear la base de datos:', err);
  process.exit(1);
});
