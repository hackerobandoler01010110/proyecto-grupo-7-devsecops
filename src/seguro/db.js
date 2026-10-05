'use strict';
// db.js - Wrapper sobre sql.js (SQLite en WebAssembly) con la misma API que la
// version vulnerable, pero SIN rawQuery(): en src/seguro/ no existe ningun camino
// para ejecutar SQL armado por concatenacion (A03). Todo va con parametros (?).

const fs = require('fs');
const path = require('path');
const initSqlJs = require('sql.js');

const RUTA_POR_DEFECTO = path.join(__dirname, 'propnet.db');

// ruta === null -> base en memoria (tests).
async function abrirBaseDatos(ruta = RUTA_POR_DEFECTO) {
  const SQL = await initSqlJs();
  const enMemoria = ruta === null;
  const sqljsDb = !enMemoria && fs.existsSync(ruta)
    ? new SQL.Database(fs.readFileSync(ruta))
    : new SQL.Database();

  // Escritura atomica (archivo temporal + rename) con permisos restrictivos.
  function guardar() {
    if (enMemoria) return;
    const tmp = ruta + '.tmp';
    fs.writeFileSync(tmp, Buffer.from(sqljsDb.export()), { mode: 0o600 });
    fs.renameSync(tmp, ruta);
  }

  return {
    // Solo DDL / scripts fijos escritos por nosotros (nunca datos del usuario).
    exec(sql) {
      sqljsDb.run(sql);
      guardar();
    },

    prepare(sql) {
      return {
        get(...params) {
          const stmt = sqljsDb.prepare(sql);
          try {
            stmt.bind(params);
            return stmt.step() ? stmt.getAsObject() : null;
          } finally {
            stmt.free();
          }
        },
        all(...params) {
          const stmt = sqljsDb.prepare(sql);
          try {
            stmt.bind(params);
            const filas = [];
            while (stmt.step()) filas.push(stmt.getAsObject());
            return filas;
          } finally {
            stmt.free();
          }
        },
        run(...params) {
          sqljsDb.run(sql, params);
          // OJO: leer estos valores ANTES de guardar(): export() reabre la base
          // y reinicia last_insert_rowid().
          const changes = sqljsDb.getRowsModified();
          const r = sqljsDb.exec('SELECT last_insert_rowid()');
          const lastInsertRowid = r.length ? r[0].values[0][0] : null;
          guardar();
          return { changes, lastInsertRowid };
        },
      };
    },

    close() {
      guardar();
      sqljsDb.close();
    },
  };
}

module.exports = { abrirBaseDatos };
