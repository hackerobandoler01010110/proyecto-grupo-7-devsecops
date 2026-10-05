# Perfil de Controles Específicos (ASC) — PropNet
### OWASP Top 10 → Control implementado → Verificación

Este documento enlaza cada riesgo con el control que lo mitiga en
`src/seguro/`, el archivo donde está implementado y la forma de
verificarlo: una evidencia generada por `auditoria/auditar.sh` y una
prueba automatizada (`npm test` en `src/seguro/`).

## Controles por riesgo

| # | Riesgo | Control aplicado en `src/seguro/` | Dónde está | Evidencia (`auditoria/fase2/`) |
|---|---|---|---|---|
| A01 | Control de acceso roto (modificar propietarios/arriendos ajenos) | Sesión con token Bearer emitido tras verificar el PIN (se guarda solo su hash, vence a la hora y se revoca en `/logout`). Cada ruta verifica autenticación, rol y que el solicitante sea dueño del recurso; el rol no se puede modificar y los campos no permitidos se rechazan. | `lib/auth.js`, `rutas/usuarios.js`, `rutas/propiedades.js`, `rutas/contratos.js` | `A01_control_acceso.txt`: sin sesión 401; recurso ajeno 403; campo `rol` 400 |
| A02 | Tokens de contrato sin hash | El token se genera con `crypto.randomBytes`, se guarda como HMAC-SHA256 (clave derivada de `PROPNET_SECRET`) y **nunca se devuelve en la respuesta**: se entrega al arrendatario por un canal aparte y este lo confirma en `POST /contratos/:id/verificar`. El texto confidencial se cifra en reposo con AES-256-GCM. | `lib/cripto.js`, `rutas/contratos.js`, `seed.js` | `A02_criptografia.txt`: la respuesta no contiene el token ni su hash |
| A03 | Inyección SQL en buscador | Consultas parametrizadas (se eliminó `rawQuery`), lista blanca de comunas (insensible a acentos y mayúsculas), `precio_max` solo con dígitos y rechazo de parámetros desconocidos o repetidos. | `db.js`, `lib/validacion.js`, `rutas/propiedades.js` | `A03_sql_injection.txt`: `' OR '1'='1`, `UNION SELECT` y `DROP TABLE` responden 400 |
| A04 | Reserva duplicada en mismo horario | Bloques de 30 min entre 09:00 y 18:30, fecha real entre hoy y 180 días, verificación previa y restricción `UNIQUE(propiedad_id, fecha, hora)` en la base como respaldo ante peticiones simultáneas. Exige sesión. | `rutas/visitas.js`, `seed.js`, `lib/validacion.js` | `A04_reserva_1.txt` (201) y `A04_reserva_2.txt` (409) |
| A05 | Exposición de stack trace | Manejador de errores genérico: el cliente recibe un mensaje y un identificador de incidente, y el detalle va solo a `errores.log`. Se oculta `X-Powered-By` y se envían `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Cache-Control: no-store`, `Content-Security-Policy` y `Cross-Origin-Resource-Policy` (más HSTS bajo HTTPS). Cuerpos limitados a 10 KB y límite global por IP. | `server.js`, `config.js` | `A05_stack_trace.txt`: respuestas sin rutas de archivo ni stack |
| A06 | Dependencias vulnerables | Se eliminaron `moment`, `leaflet` y `node-fetch` (sin uso en el código seguro; la descarga usa el módulo `https` de Node). Quedan solo `express` y `sql.js`, fijadas con `package-lock.json` e instaladas con `npm ci`. | `package.json`, `package-lock.json` | `A06_dependencias.txt`: `found 0 vulnerabilities` |
| A07 | PIN de 3 dígitos por SMS sin expiración | PIN de 6 dígitos con generador criptográfico, guardado como HMAC, vigencia de 5 minutos, un solo uso, máximo 5 intentos por PIN y límites de solicitudes por IP y por correo. Respuestas uniformes: no revela si el correo existe y el PIN nunca viaja en la respuesta ni en los logs. | `rutas/auth.js`, `lib/cripto.js`, `lib/limitador.js` | `A07_login_pin.txt`: PIN reutilizado 401; fuerza bruta 401 x4 y luego 429 |
| A08 | XSS persistente en descripción | La entrada rechaza HTML (400) mediante regex; al renderizar se escapa la salida y la vista responde con CSP `default-src 'none'`. `propietario_id` sale de la sesión. | `lib/validacion.js`, `rutas/propiedades.js` | `A08_xss.txt`: `<script>` y `<img onerror>` responden 400; la vista no contiene `<script>` |
| A09 | Acceso a contratos sin registro | Registro en JSON de **todo** acceso a `/contratos` (autorizado, denegado o sin sesión) con fecha, IP, método, ruta, usuario, contrato, estado, resultado y motivo. Además `seguridad.log` para eventos de seguridad. | `lib/logger.js`, `rutas/contratos.js` | `A09_logging.txt` y `src/seguro/logs/access.log` |
| A10 | SSRF en descarga de imágenes | Solo `https` (puerto 443, sin credenciales), lista blanca exacta de hosts, rechazo de IP literales, bloqueo de rangos privados, locales y de metadatos tras resolver el DNS, conexión fijada a la IP validada, sin seguir redirecciones, con tiempo, tamaño, tipo MIME y firma de imagen limitados. Solo propietarios y con límite de tasa. La respuesta al cliente es genérica y el motivo exacto queda en `seguridad.log`. | `lib/ssrf.js`, `rutas/imagenes.js`, `config.js` | `A10_ssrf.txt`: metadatos, `127.0.0.1`, `localhost`, `file://` responden 400 |

## Verificación automatizada

| Prueba | Qué cubre | Cómo ejecutarla |
|---|---|---|
| `src/seguro/test/unit.test.js` | Validación (regex y listas blancas), anti-SSRF, criptografía y limitador | `cd src/seguro && npm test` |
| `src/seguro/test/integracion.test.js` | A01 a A10 de punta a punta contra la API levantada con base en memoria | `cd src/seguro && npm test` |
| `auditoria/auditar.sh` (Fase 2) | 53 verificaciones contra la API en ejecución, con login real | Ver `README.md` |

Resultado actual: 26 pruebas sin fallas, `npm audit` sin vulnerabilidades y
53 verificaciones `PASS` con 0 `FAIL` en Fase 2.

## Notas

- La columna "Evidencia" apunta a los archivos reales generados por
  `auditoria/auditar.sh` en `auditoria/fase2/`.
- Limitaciones conocidas de esta versión (el detalle y su justificación
  están en `ONF.md`, sección 5): límites de tasa en memoria, canal de
  PIN simulado, sin rotación de logs y sin terminación HTTPS en la
  aplicación.
- Este archivo se actualiza si cambia un control o su evidencia.
