// db.js - Wrapper simple sobre sql.js (SQLite en WebAssembly, sin compilacion nativa)
// Expone una API parecida a better-sqlite3: db.prepare(sql).run(...) / .get(...) / .all(...)
// y persiste el contenido en disco (propnet.db) tras cada escritura.

const fs = require('fs');
const path = require('path');
const initSqlJs = require('sql.js');

const DB_PATH = path.join(__dirname, 'propnet.db');

async function abrirBaseDatos() {
  const SQL = await initSqlJs();
  let sqljsDb;

  if (fs.existsSync(DB_PATH)) {
    const buffer = fs.readFileSync(DB_PATH);
    sqljsDb = new SQL.Database(buffer);
  } else {
    sqljsDb = new SQL.Database();
  }

  function guardar() {
    const data = sqljsDb.export();
    fs.writeFileSync(DB_PATH, Buffer.from(data));
  }

  return {
    // Ejecuta SQL sin parametros (DDL: CREATE TABLE, DROP TABLE, etc.)
    exec(sql) {
      sqljsDb.run(sql);
      guardar();
    },

    // Para SELECT ... WHERE x = ? con un solo resultado
    prepare(sql) {
      return {
        get(...params) {
          const stmt = sqljsDb.prepare(sql);
          stmt.bind(params);
          let row = null;
          if (stmt.step()) {
            row = stmt.getAsObject();
          }
          stmt.free();
          return row;
        },
        all(...params) {
          const stmt = sqljsDb.prepare(sql);
          stmt.bind(params);
          const rows = [];
          while (stmt.step()) {
            rows.push(stmt.getAsObject());
          }
          stmt.free();
          return rows;
        },
        run(...params) {
          sqljsDb.run(sql, params);
          guardar();
          return { changes: sqljsDb.getRowsModified() };
        },
      };
    },

    // Variante que ejecuta SQL ya armado como texto plano (para la inyeccion SQL, A03)
    // OJO: se usa a proposito sin parametros en el endpoint vulnerable.
    rawQuery(sql) {
      const resultado = sqljsDb.exec(sql); // [{columns:[], values:[[...]]}]
      if (resultado.length === 0) return [];
      const { columns, values } = resultado[0];
      return values.map((fila) =>
        Object.fromEntries(fila.map((valor, i) => [columns[i], valor]))
      );
    },

    close() {
      guardar();
      sqljsDb.close();
    },
  };
}

module.exports = { abrirBaseDatos };
