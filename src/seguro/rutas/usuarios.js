'use strict';
// rutas/usuarios.js - A01: control de acceso a nivel de objeto (anti-IDOR).
// Un usuario solo puede modificar SU PROPIO perfil; el valor de referencia de arriendo
// solo lo fija un propietario sobre si mismo. El rol no es modificable por la API.

const { describirReq } = require('../lib/logger');
const { v, exigirObjeto, soloCampos } = require('../lib/validacion');

module.exports = function rutasUsuarios(ctx) {
  const { express, db, cfg, logger, autenticar } = ctx;
  const router = express.Router();

  router.put('/:id', autenticar, (req, res) => {
    const id = v.id(req.params.id);
    if (id !== req.usuario.id) {
      res.locals.motivo = 'modificacion_de_otro_usuario';
      logger.seguridad({ evento: 'acceso_denegado', motivo: 'modificacion_de_otro_usuario', recurso: `usuarios/${id}`, ...describirReq(req) });
      return res.status(403).json({ error: 'No autorizado' });
    }

    exigirObjeto(req.body);
    soloCampos(req.body, ['nombre', 'telefono', 'valor_arriendo_referencia']);
    const b = req.body;
    const sets = [];
    const params = [];

    if (b.nombre !== undefined) { sets.push('nombre = ?'); params.push(v.nombre(b.nombre)); }
    if (b.telefono !== undefined) { sets.push('telefono = ?'); params.push(v.telefono(b.telefono)); }
    if (b.valor_arriendo_referencia !== undefined) {
      if (req.usuario.rol !== 'propietario') {
        logger.seguridad({ evento: 'acceso_denegado', motivo: 'valor_arriendo_sin_ser_propietario', ...describirReq(req) });
        return res.status(403).json({ error: 'No autorizado' });
      }
      sets.push('valor_arriendo_referencia = ?');
      params.push(b.valor_arriendo_referencia === null
        ? null
        : v.entero(b.valor_arriendo_referencia, 'valor_arriendo_referencia', cfg.precio.min, cfg.precio.max));
    }
    if (sets.length === 0) return res.status(400).json({ error: 'Solicitud invalida', detalles: ['No hay campos para actualizar'] });

    // Las columnas de SET salen de literales fijos de arriba; los valores van parametrizados.
    db.prepare(`UPDATE usuarios SET ${sets.join(', ')} WHERE id = ?`).run(...params, id);
    return res.json({ mensaje: 'Usuario actualizado', id });
  });

  return router;
};
