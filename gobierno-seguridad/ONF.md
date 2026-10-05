# Marco Normativo Organizacional (ONF) — PropNet
### Basado en ISO/IEC 27034 — Seguridad de aplicaciones

## 1. Alcance

Este ONF aplica a todo el ciclo de vida de PropNet API: diseño,
desarrollo, pruebas, despliegue y mantenimiento, cubriendo tanto el
código propio como las dependencias de terceros.

## 2. Roles y responsabilidades

| Rol | Responsabilidad |
|---|---|
| Líder técnico / DevSecOps | Define el ASC, aprueba excepciones, valida cierre de hallazgos |
| Desarrollador | Implementa controles, corrige hallazgos de su módulo |
| Auditor / Pentester | Ejecuta pruebas de los 10 riesgos OWASP y documenta evidencia |
| Equipo completo | Revisa y aprueba cambios vía Pull Request antes de fusionar a `main` |

## 3. Ciclo de vida seguro de la aplicación (resumen ISO/IEC 27034)

1. **Especificación de requisitos de seguridad** — qué datos son
   sensibles (contratos, montos, identidad) y qué controles son
   obligatorios para cada uno (ver `ASC.md`).
2. **Diseño seguro** — *Zero Trust Input*: ninguna entrada del cliente se
   confía sin validar.
3. **Implementación** — listas blancas, expresiones regulares,
   parametrización de consultas, manejo de errores sin fuga de
   información.
4. **Verificación** — pruebas automatizadas (`npm test`) y pruebas de
   penetración contra los 10 riesgos del OWASP Top 10 con
   `auditoria/auditar.sh`, documentadas en `auditoria/`.
5. **Liberación y mantenimiento** — actualización periódica de
   dependencias (`npm audit`), monitoreo de logs de acceso.

## 4. Política general de controles

- Toda entrada de usuario se valida contra una lista blanca o una
  expresión regular antes de usarse. Los campos no previstos se rechazan
  (HTTP 400).
- Ninguna credencial, token o secreto se almacena en texto plano: los
  tokens de sesión, de contrato y los PIN se guardan como HMAC-SHA256 y
  los datos confidenciales de contratos, cifrados con AES-256-GCM. La
  clave maestra sale de la variable de entorno `PROPNET_SECRET` y no se
  versiona.
- Los mensajes de error que ve el cliente nunca incluyen rutas de
  archivo, stack traces ni detalles de la base de datos; el detalle queda
  en `errores.log` asociado a un identificador de incidente.
- Todo acceso a datos confidenciales (contratos) queda registrado con
  fecha, IP, usuario, contrato y resultado (autorizado/denegado). Los
  registros se escriben en JSON, de modo que una entrada hostil no pueda
  falsificar líneas de log, y no contienen PIN, tokens ni el contenido de
  los contratos.
- Las dependencias se revisan con `npm audit` antes de cada liberación y
  se instalan con `npm ci` a partir de `package-lock.json`. Se evita
  añadir dependencias que el código no necesite.

### 4.1 Parámetros acordados

| Control | Valor |
|---|---|
| Longitud y vigencia del PIN | 6 dígitos, 5 minutos, un solo uso |
| Intentos por PIN | 5; luego se bloquea y se debe solicitar uno nuevo |
| Solicitudes de PIN | 5 por correo y 20 por IP cada 15 minutos |
| Vigencia de la sesión | 1 hora, revocable con `/logout` |
| Verificación de contrato | 5 intentos por usuario y contrato cada 15 minutos |
| Horario de visitas | Bloques de 30 min entre 09:00 y 18:30, hasta 180 días hacia adelante |
| Descarga de imágenes | Solo `https`, hosts de una lista blanca, máx. 5 MB y 5 s, 10 por minuto por usuario |
| Tamaño de cuerpo de petición | 10 KB |
| Límite global | 300 solicitudes por minuto por IP |

### 4.2 Gestión de cambios

Los cambios llegan a `main` mediante Pull Request revisado por el
equipo. Antes de fusionar deben cumplirse: `npm test` sin fallas,
`npm audit` sin vulnerabilidades en `src/seguro/`, y `auditar.sh` en Fase
2 sin ningún `FAIL`. El historial de Git se conserva (no se reescribe).

## 5. Excepciones

Cualquier excepción a este marco debe quedar documentada en este archivo
con justificación y fecha de revisión. Las limitaciones siguientes se
aceptan para esta entrega académica y deben resolverse antes de un uso
real. Fecha de registro: 04-10-2026. Fecha de revisión: antes de la
entrega final.

| Limitación | Justificación | Mitigación futura |
|---|---|---|
| Los límites de tasa están en memoria | Es una aplicación de una sola instancia, sin servicios adicionales; se reinicia con el servidor | Almacén compartido (por ejemplo Redis) |
| El PIN por SMS está simulado en consola | No hay proveedor de mensajería en el entorno del laboratorio | Integrar un proveedor real y apagar `SMS_SIMULADO` |
| Los logs no rotan ni se envían a un SIEM | Fuera del alcance de la evaluación | Rotación y envío centralizado |
| La aplicación no termina HTTPS | Se espera un proxy inverso delante; HSTS se envía cuando la conexión es segura | Terminación TLS en el proxy |
| Las pruebas de descarga real de imágenes cubren la validación, no una descarga contra un host público | El laboratorio no garantiza salida a internet | Prueba de integración con acceso a la red |
| La evidencia de auditoría se generó desde el mismo equipo del servidor | Falta de una segunda máquina durante el desarrollo | Regenerar la evidencia desde una máquina auditora en la demostración |

## 6. Verificación del cumplimiento

El cumplimiento de este marco se comprueba con tres evidencias
independientes: las pruebas automatizadas (`src/seguro/test/`), la
auditoría `auditar.sh` y sus resultados en `auditoria/fase1/` y
`auditoria/fase2/`, y la revisión del equipo en cada Pull Request.
