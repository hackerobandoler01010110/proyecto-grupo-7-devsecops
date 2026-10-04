'use strict';
// rutas/imagenes.js - A10: SSRF. Toda la logica de defensa vive en lib/ssrf.js.
// Al cliente solo se le dice "URL no permitida": el motivo exacto va al log interno.

const { describirReq } = require('../lib/logger');
const { exigirObjeto, soloCampos } = require('../lib/validacion');
const { ErrorSsrf } = require('../lib/ssrf');
const { asincrono, limitar } = require('../lib/http');

module.exports = function rutasImagenes(ctx) {
  const { express, cfg, logger, limitadores, autenticar, requerirRol, descargarImagen } = ctx;
  const router = express.Router();

  router.post('/descargar', autenticar, requerirRol('propietario'), asincrono(async (req, res) => {
    exigirObjeto(req.body);
    soloCampos(req.body, ['url']);

    const lim = limitadores.imagenes.consumir(String(req.usuario.id));
    if (!lim.permitido) return limitar(res, lim);

    try {
      const r = await descargarImagen(req.body.url, {
        hostsPermitidos: cfg.imagenes.hostsPermitidos,
        maxBytes: cfg.imagenes.maxBytes,
        timeoutMs: cfg.imagenes.timeoutMs,
      });
      return res.json({ mensaje: 'Imagen validada', tipo: r.tipo, bytes: r.bytes, sha256: r.sha256 });
    } catch (err) {
      if (err instanceof ErrorSsrf) {
        logger.seguridad({
          evento: 'ssrf_bloqueado',
          motivo: err.motivo,
          url: String(req.body.url).slice(0, 200),
          ...describirReq(req),
        });
        return res.status(400).json({ error: 'URL no permitida' });
      }
      logger.error({ evento: 'descarga_imagen_fallida', mensaje: err.message, ...describirReq(req) });
      return res.status(502).json({ error: 'No fue posible obtener la imagen' });
    }
  }));

  return router;
};
