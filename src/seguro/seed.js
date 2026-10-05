'use strict';
// seed.js - Crea la base de datos de la version SEGURA con datos de prueba.
// Esquema con restricciones (CHECK, UNIQUE) como segunda linea de defensa.
// ADVERTENCIA: borra y recrea las tablas. Bloqueado en produccion.

const cfg = require('./config');
const { abrirBaseDatos } = require('./db');
const { crearCripto } = require('./lib/cripto');

async function sembrar(db, cripto) {
  db.exec(`
    DROP TABLE IF EXISTS sesiones;
    DROP TABLE IF EXISTS pines;
    DROP TABLE IF EXISTS visitas;
    DROP TABLE IF EXISTS contratos;
    DROP TABLE IF EXISTS propiedades;
    DROP TABLE IF EXISTS usuarios;

    CREATE TABLE usuarios (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      nombre TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      telefono TEXT NOT NULL,
      rol TEXT NOT NULL CHECK (rol IN ('propietario', 'arrendatario')),
      valor_arriendo_referencia INTEGER
    );

    CREATE TABLE propiedades (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      propietario_id INTEGER NOT NULL,
      titulo TEXT NOT NULL,
      descripcion TEXT NOT NULL,
      comuna TEXT NOT NULL,
      precio INTEGER NOT NULL CHECK (precio > 0),
      creado_en TEXT NOT NULL
    );

    CREATE TABLE contratos (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      propiedad_id INTEGER NOT NULL,
      arrendatario_id INTEGER NOT NULL,
      token_hash TEXT NOT NULL,            -- HMAC-SHA256: el token jamas se guarda en claro (A02)
      confidencial_cifrado TEXT NOT NULL,  -- AES-256-GCM
      verificado INTEGER NOT NULL DEFAULT 0,
      creado_en TEXT NOT NULL
    );

    CREATE TABLE visitas (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      propiedad_id INTEGER NOT NULL,
      usuario_id INTEGER NOT NULL,
      visitante TEXT NOT NULL,
      fecha TEXT NOT NULL,
      hora TEXT NOT NULL,
      creado_en TEXT NOT NULL,
      UNIQUE (propiedad_id, fecha, hora)   -- A04: imposible duplicar el horario
    );

    CREATE TABLE pines (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      usuario_id INTEGER NOT NULL,
      pin_hash TEXT NOT NULL,              -- HMAC del PIN, no el PIN
      creado_en TEXT NOT NULL,
      expira_en TEXT NOT NULL,
      intentos INTEGER NOT NULL DEFAULT 0,
      usado INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX idx_pines_usuario ON pines (usuario_id, usado);

    CREATE TABLE sesiones (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      usuario_id INTEGER NOT NULL,
      token_hash TEXT NOT NULL UNIQUE,
      creado_en TEXT NOT NULL,
      expira_en TEXT NOT NULL
    );
  `);

  const ahora = new Date().toISOString();
  const insU = db.prepare('INSERT INTO usuarios (nombre, email, telefono, rol, valor_arriendo_referencia) VALUES (?, ?, ?, ?, ?)');
  insU.run('Maria Propietaria', 'maria@propnet.cl', '+56911111111', 'propietario', 500000);   // id 1
  insU.run('Juan Arrendatario', 'juan@propnet.cl', '+56922222222', 'arrendatario', null);     // id 2
  insU.run('Pedro Arrendatario', 'pedro@propnet.cl', '+56933333333', 'arrendatario', null);   // id 3
  insU.run('Carla Propietaria', 'carla@propnet.cl', '+56944444444', 'propietario', 380000);   // id 4

  const insP = db.prepare('INSERT INTO propiedades (propietario_id, titulo, descripcion, comuna, precio, creado_en) VALUES (?, ?, ?, ?, ?, ?)');
  insP.run(1, 'Depto 2D1B Providencia', 'Luminoso depto cerca del metro.', 'Providencia', 450000, ahora);   // id 1
  insP.run(1, 'Casa 3D2B Ñuñoa', 'Casa con patio, ideal para familia.', 'Ñuñoa', 700000, ahora);            // id 2
  insP.run(4, 'Depto 1D1B Viña del Mar', 'Departamento con vista al mar.', 'Viña del Mar', 380000, ahora);  // id 3

  const tokens = { contrato1: cripto.generarToken(), contrato2: cripto.generarToken() };
  const insC = db.prepare('INSERT INTO contratos (propiedad_id, arrendatario_id, token_hash, confidencial_cifrado, verificado, creado_en) VALUES (?, ?, ?, ?, 0, ?)');
  insC.run(1, 2, cripto.hmac('contrato', tokens.contrato1), cripto.cifrar('Renta liquida mensual $450.000, aval: Maria Propietaria'), ahora); // id 1 (Juan)
  insC.run(2, 3, cripto.hmac('contrato', tokens.contrato2), cripto.cifrar('Renta liquida mensual $700.000, aval: Familia Soto'), ahora);        // id 2 (Pedro)
  return tokens;
}

module.exports = { sembrar };

if (require.main === module) {
  (async () => {
    if (cfg.produccion) throw new Error('El seed borra datos y esta bloqueado en produccion');
    const db = await abrirBaseDatos(cfg.rutaDb);
    const tokens = await sembrar(db, crearCripto(cfg.secreto));
    db.close();
    console.log('Base de datos segura creada con datos de prueba.');
    console.log('Usuarios: maria@propnet.cl (propietaria), juan@propnet.cl y pedro@propnet.cl (arrendatarios), carla@propnet.cl (propietaria)');
    console.log('Tokens de verificacion de contratos (se muestran UNA sola vez; en la base solo queda su hash):');
    console.log(`  contrato 1 (Juan):  ${tokens.contrato1}`);
    console.log(`  contrato 2 (Pedro): ${tokens.contrato2}`);
  })().catch((err) => {
    console.error('Error al crear la base de datos:', err.message);
    process.exit(1);
  });
}
