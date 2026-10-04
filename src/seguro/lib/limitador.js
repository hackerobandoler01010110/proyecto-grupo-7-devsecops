'use strict';
// lib/limitador.js - Limitador de tasa en memoria, ventana fija por clave.
// Mitiga fuerza bruta (A07) y abuso general. Limitacion conocida: el estado se
// pierde al reiniciar y no se comparte entre instancias (usar Redis en produccion).

const MAX_CLAVES = 10000;

function crearLimitador({ max, ventanaMs }) {
  const mapa = new Map();
  const limpieza = setInterval(() => {
    const ahora = Date.now();
    for (const [clave, e] of mapa) if (e.reinicio <= ahora) mapa.delete(clave);
  }, Math.min(ventanaMs, 60000));
  limpieza.unref(); // no impide que el proceso termine

  return {
    consumir(clave) {
      const ahora = Date.now();
      let e = mapa.get(clave);
      if (!e || e.reinicio <= ahora) {
        if (mapa.size >= MAX_CLAVES) mapa.delete(mapa.keys().next().value); // tope de memoria
        e = { cuenta: 0, reinicio: ahora + ventanaMs };
        mapa.set(clave, e);
      }
      e.cuenta += 1;
      return {
        permitido: e.cuenta <= max,
        restante: Math.max(0, max - e.cuenta),
        reintentoSeg: Math.max(1, Math.ceil((e.reinicio - ahora) / 1000)),
      };
    },
    // Consulta sin consumir: bloqueado cuando ya se registraron `max` eventos en la ventana.
    revisar(clave) {
      const e = mapa.get(clave);
      if (!e || e.reinicio <= Date.now()) return { permitido: true, reintentoSeg: 0 };
      return { permitido: e.cuenta < max, reintentoSeg: Math.max(1, Math.ceil((e.reinicio - Date.now()) / 1000)) };
    },
    reiniciar() { mapa.clear(); },
  };
}

module.exports = { crearLimitador };
