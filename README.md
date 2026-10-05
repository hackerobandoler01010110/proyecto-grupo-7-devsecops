# PropNet API — Grupo 7 (DevSecOps)

Plataforma de gestión de propiedades y arriendos. Proyecto de la
evaluación "Ética, Gobernanza (ISO/IEC 27034) y Seguridad Aplicada
(OWASP Top 10)".

El repositorio contiene **dos versiones de la misma API**:

- `src/vulnerable/`: con las 10 fallas del OWASP Top 10 introducidas a
  propósito, para auditarlas (Fase 1).
- `src/seguro/`: con los 10 riesgos mitigados, probada con pruebas
  automatizadas y re-auditada con el mismo script (Fase 2).

## Integrantes

- David Zamorano — Líder técnico / DevSecOps
- Giancarlo Guarda — Desarrollador
- Marcelo Astudillo — Auditor / Pentester

## Estructura del repositorio

```
gobierno-seguridad/    Manifiesto ético, ONF y ASC (ISO/IEC 27034)
src/vulnerable/        API con las 10 fallas OWASP Top 10 a propósito
  server.js, db.js, seed.js, metadata-mock.js (blanco de la demo SSRF)
src/seguro/            Misma API con los 10 controles implementados
  server.js            Ensamblado de la app, cabeceras y manejo de errores
  config.js            Configuración centralizada (variables de entorno)
  db.js, seed.js       Acceso a datos (solo consultas parametrizadas) y datos de prueba
  lib/                 auth, cripto, validacion, ssrf, limitador, logger, http
  rutas/               Una ruta por dominio: auth, usuarios, propiedades,
                       visitas, contratos, imagenes
  test/                26 pruebas automatizadas (unitarias e integración)
auditoria/
  auditar.sh           Script que ejecuta las pruebas de A01 a A10 (Fase 1 y Fase 2)
  fase1/               Evidencia contra la API vulnerable
  fase2/               Evidencia contra la API segura (re-pruebas)
```

## Requisitos

- Node.js 18 o superior (se probó con Node 24) y npm.
- Para `auditar.sh`: Git Bash, WSL, Linux o macOS, con `curl`.

## Cómo ejecutar la API vulnerable

```bash
cd src/vulnerable
npm install
npm run seed      # crea propnet.db con datos de prueba
npm start         # escucha en http://localhost:3000
```

Para probar el SSRF (A10) de forma controlada, en otra terminal y en la
misma máquina que el servidor:

```bash
node metadata-mock.js   # simula un endpoint de metadatos en :9999
```

## Cómo ejecutar la API segura

```bash
cd src/seguro
npm ci            # instala exactamente lo indicado en package-lock.json
npm test          # 26 pruebas automatizadas
npm run seed      # crea propnet.db y .secret (clave local), con datos de prueba
npm start         # escucha en http://0.0.0.0:3000
```

Comprobación rápida: `curl http://localhost:3000/salud` responde
`{"estado":"ok"}`.

El canal de PIN por SMS está **simulado**: el PIN aparece en la consola
del servidor, en líneas `[SMS SIMULADO]`. Los usuarios de prueba son
`maria@propnet.cl` y `carla@propnet.cl` (propietarias) y
`juan@propnet.cl` y `pedro@propnet.cl` (arrendatarios).

Variables de entorno principales (todas opcionales en desarrollo):

| Variable | Para qué sirve | Valor por defecto |
|---|---|---|
| `PORT`, `HOST` | Puerto y dirección de escucha | `3000`, `0.0.0.0` |
| `PROPNET_SECRET` | Clave maestra (64 caracteres hex). Obligatoria con `NODE_ENV=production` | se genera en `.secret` |
| `DB_PATH` | Ruta de la base de datos | `src/seguro/propnet.db` |
| `LOG_DIR` | Carpeta de logs (`access.log`, `seguridad.log`, `errores.log`) | `src/seguro/logs` |
| `PIN_TTL_SEGUNDOS` | Vigencia del PIN | `300` |
| `IMG_HOSTS_PERMITIDOS` | Lista blanca de hosts para descarga de imágenes | `images.unsplash.com,upload.wikimedia.org` |

## Cómo ejecutar la auditoría

El script se lanza desde la raíz del repositorio con la API corriendo. El
modo se deduce de la carpeta de salida: si contiene `fase2` ejecuta las
pruebas de la versión segura; también se puede forzar con `FASE=fase2`.

**Fase 1 (API vulnerable):**

```bash
bash auditoria/auditar.sh http://localhost:3000 auditoria/fase1
```

**Fase 2 (API segura):**

```bash
# Terminal 1: servidor, guardando la consola para que el script lea los PIN
cd src/seguro
npm start 2>&1 | tee salida.txt

# Terminal 2: auditoría desde la raíz del repositorio
FASE=fase2 SERVER_OUT=src/seguro/salida.txt LOG_ACCESO=src/seguro/logs/access.log \
  bash auditoria/auditar.sh http://localhost:3000 auditoria/fase2
```

La Fase 2 inicia sesión sola y marca cada prueba como `PASS` o `FAIL`; el
script termina con código 0 solo si no hay ningún `FAIL`. Los PIN se
entregan, por orden de prioridad, con las variables `PIN_MARIA` y
`PIN_JUAN`, leyéndolos de `SERVER_OUT`, o por teclado.

**Auditoría desde otra máquina:** se reemplaza `localhost` por la IP del
equipo servidor (`ipconfig` en Windows). El puerto 3000 debe estar
permitido en el firewall del servidor. El mock de metadatos de la Fase 1
sigue corriendo en el servidor, porque la petición SSRF la hace el propio
servidor. `salida.txt`, `.secret`, `logs/` y `*.db` no se versionan.

## Resumen de riesgos y mitigaciones

Detalle por riesgo (control, archivos y evidencia) en
`gobierno-seguridad/ASC.md`.

| # | Riesgo OWASP | Control principal en `src/seguro/` | Estado |
|---|---|---|---|
| A01 | Control de acceso roto | Sesión con token Bearer + verificación de dueño del recurso | ✅ Implementado |
| A02 | Fallas criptográficas | Token guardado como HMAC-SHA256, nunca devuelto; texto confidencial cifrado con AES-256-GCM | ✅ Implementado |
| A03 | Inyección SQL | Consultas parametrizadas + lista blanca de comunas + regex en precio | ✅ Implementado |
| A04 | Diseño inseguro (reservas) | Validación previa + restricción UNIQUE; conflicto responde 409 | ✅ Implementado |
| A05 | Mala configuración de seguridad | Errores genéricos con id de incidente + cabeceras de seguridad | ✅ Implementado |
| A06 | Dependencias vulnerables | Solo `express` y `sql.js`; se eliminaron `moment`, `leaflet` y `node-fetch` | ✅ Implementado |
| A07 | Autenticación débil | PIN de 6 dígitos, 5 min, un solo uso, límite de intentos | ✅ Implementado |
| A08 | XSS persistente | Se rechaza HTML en la entrada + escape de salida + CSP | ✅ Implementado |
| A09 | Fallas de registro y monitoreo | `access.log` con todo acceso a contratos (autorizado y denegado) | ✅ Implementado |
| A10 | SSRF | Lista blanca de hosts + bloqueo de IP privadas + solo https, sin redirecciones | ✅ Implementado |

## Resultados de verificación

| Verificación | Resultado |
|---|---|
| `npm test` en `src/seguro` | 26 pruebas, 0 fallas |
| `npm audit` en `src/seguro` | 0 vulnerabilidades |
| `npm audit` en `src/vulnerable` | 2 vulnerabilidades altas (`moment` y `node-fetch`) |
| `auditar.sh` Fase 1 (API vulnerable) | Las fallas de A01 a A10 se reproducen (ver `auditoria/fase1/`) |
| `auditar.sh` Fase 2 (API segura) | 53 verificaciones `PASS`, 0 `FAIL` (ver `auditoria/fase2/`) |

Ejemplo del antes y después de A10, con la misma URL
`http://127.0.0.1:9999/latest/meta-data/`: en la Fase 1 responde 200 con
datos internos; en la Fase 2 responde 400 `URL no permitida`.

## Estado de la evidencia

Las evidencias de `auditoria/fase1/` y `auditoria/fase2/` se generaron
desde el mismo equipo del servidor (`localhost`). Se regenerarán desde una
máquina auditora separada en la demostración en aula, y ese cambio quedará
en un commit aparte.

## Advertencia

`src/vulnerable/` contiene fallas de seguridad introducidas a propósito
con fines académicos. No desplegar en producción ni exponer a redes
públicas.
