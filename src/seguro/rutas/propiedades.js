'use strict';
// rutas/propiedades.js
//   A01: solo el propietario autenticado publica y cambia el precio de SUS propiedades.
//   A03: buscador con consultas parametrizadas + lista blanca de comunas + regex de precio.
//   A08: la descripcion no admite HTML (validacion) y ademas se escapa al renderizar.

const { describirReq } = require('../lib/logger');
const { v, exigirObjeto, soloCampos, escaparHtml } = require('../lib/validacion');

module.exports = function rutasPropiedades(ctx) {
  const { express, db, cfg, logger, autenticar, requerirRol } = ctx;
  const propiedades = express.Router();
  const arriendos = express.Router();

  // GET /propiedades/buscar?comuna=...&precio_max=...  (publico, solo lectura)
  propiedades.get('/buscar', (req, res) => {
    const q = req.query || {};
    soloCampos(q, ['comuna', 'precio_max']);
    const comuna = q.comuna === undefined || q.comuna === '' ? null : v.comuna(q.comuna);
    const precioMax = q.precio_max === undefined
      ? cfg.precio.max
      : v.enteroTexto(q.precio_max, 'precio_max', 0, 999999999);

    const filas = db.prepare(
      `SELECT id, titulo, descripcion, comuna, precio
         FROM propiedades
        WHERE (? IS NULL OR comuna = ?) AND precio <= ?
        ORDER BY id LIMIT 100`
    ).all(comuna, comuna, precioMax);
    return res.json(filas);
  });

  // GET /propiedades/:id  (HTML con escape de salida)
  propiedades.get('/:id', (req, res) => {
    const id = v.id(req.params.id);
    const p = db.prepare('SELECT titulo, descripcion FROM propiedades WHERE id = ?').get(id);
    if (!p) return res.status(404).json({ error: 'No encontrada' });
    res.set('Content-Type', 'text/html; charset=utf-8');
    // CSP restrictiva: aunque algo se colara, el navegador no ejecuta scripts ni recursos.
    res.set('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'");
    return res.send(
      `<!doctype html><meta charset="utf-8"><h1>${escaparHtml(p.titulo)}</h1><div>${escaparHtml(p.descripcion)}</div>`
    );
  });

  propiedades.post('/', autenticar, requerirRol('propietario'), (req, res) => {
    exigirObjeto(req.body);
    soloCampos(req.body, ['titulo', 'descripcion', 'comuna', 'precio']);
    const titulo = v.titulo(req.body.titulo);
    const descripcion = v.descripcion(req.body.descripcion);
    const comuna = v.comuna(req.body.comuna);
    const precio = v.entero(req.body.precio, 'precio', cfg.precio.min, cfg.precio.max);

    // El propietario SIEMPRE sale de la sesion, nunca del cuerpo (anti-IDOR / suplantacion).
    const r = db.prepare(
      'INSERT INTO propiedades (propietario_id, titulo, descripcion, comuna, precio, creado_en) VALUES (?, ?, ?, ?, ?, ?)'
    ).run(req.usuario.id, titulo, descripcion, comuna, precio, new Date().toISOString());
    return res.status(201).json({ mensaje: 'Propiedad publicada', id: r.lastInsertRowid });
  });

  // PUT /arriendos/:id  (id = propiedad)
  arriendos.put('/:id', autenticar, requerirRol('propietario'), (req, res) => {
    const id = v.id(req.params.id);
    exigirObjeto(req.body);
    soloCampos(req.body, ['precio']);
    const precio = v.entero(req.body.precio, 'precio', cfg.precio.min, cfg.precio.max);

    const p = db.prepare('SELECT id, propietario_id, precio FROM propiedades WHERE id = ?').get(id);
    if (!p) return res.status(404).json({ error: 'No encontrada' });
    if (p.propietario_id !== req.usuario.id) {
      logger.seguridad({ evento: 'acceso_denegado', motivo: 'precio_de_propiedad_ajena', recurso: `propiedades/${id}`, ...describirReq(req) });
      return res.status(403).json({ error: 'No autorizado' });
    }
    db.prepare('UPDATE propiedades SET precio = ? WHERE id = ?').run(precio, id);
    logger.seguridad({ nivel: 'INFO', evento: 'precio_modificado', recurso: `propiedades/${id}`, anterior: p.precio, nuevo: precio, ...describirReq(req) });
    return res.json({ mensaje: 'Valor de arriendo actualizado', id, precio });
  });

  return { propiedades, arriendos };
};
