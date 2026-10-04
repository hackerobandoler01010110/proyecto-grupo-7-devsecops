'use strict';
// rutas/visitas.js - A04: diseno seguro del agendamiento.
//   - Slots cerrados (09:00-18:30 cada 30 min), fecha real, futura y con horizonte maximo.
//   - Verificacion previa de conflicto + restriccion UNIQUE(propiedad, fecha, hora) en la
//     base como respaldo definitivo contra condiciones de carrera -> HTTP 409.

const { describirReq } = require('../lib/logger');
const { v, exigirObjeto, soloCampos } = require('../lib/validacion');
const { esViolacionUnicidad } = require('../lib/http');

module.exports = function rutasVisitas(ctx) {
  const { express, db, logger, autenticar } = ctx;
  const router = express.Router();

  router.post('/', autenticar, (req, res) => {
    exigirObjeto(req.body);
    soloCampos(req.body, ['propiedad_id', 'fecha', 'hora', 'visitante']);
    const b = req.body;
    const propiedadId = v.id(b.propiedad_id, 'propiedad_id');
    const fecha = v.fecha(b.fecha);
    const hora = v.hora(b.hora);
    const visitante = b.visitante === undefined ? req.usuario.nombre : v.nombre(b.visitante, 'visitante');

    if (!db.prepare('SELECT id FROM propiedades WHERE id = ?').get(propiedadId)) {
      return res.status(404).json({ error: 'Propiedad no encontrada' });
    }

    const conflicto = () => {
      logger.seguridad({ evento: 'reserva_en_conflicto', recurso: `propiedades/${propiedadId}`, fecha, hora, ...describirReq(req) });
      return res.status(409).json({ error: 'Ya existe una visita agendada para esa propiedad en ese horario' });
    };

    if (db.prepare('SELECT id FROM visitas WHERE propiedad_id = ? AND fecha = ? AND hora = ?').get(propiedadId, fecha, hora)) {
      return conflicto();
    }
    try {
      const r = db.prepare(
        'INSERT INTO visitas (propiedad_id, usuario_id, visitante, fecha, hora, creado_en) VALUES (?, ?, ?, ?, ?, ?)'
      ).run(propiedadId, req.usuario.id, visitante, fecha, hora, new Date().toISOString());
      return res.status(201).json({ mensaje: 'Visita agendada', id: r.lastInsertRowid, propiedad_id: propiedadId, fecha, hora });
    } catch (err) {
      if (esViolacionUnicidad(err)) return conflicto(); // carrera: otra peticion gano el slot
      throw err;
    }
  });

  return router;
};
