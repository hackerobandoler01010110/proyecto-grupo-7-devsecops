# Perfil de Controles Específicos (ASC) — PropNet
### OWASP Top 10 → Control implementado → Verificación

| # | Riesgo | Control aplicado en `src/seguro/` | Cómo se verifica |
|---|---|---|---|
| A01 | Control de acceso roto (modificar propietarios/arriendos ajenos) | Middleware de autenticación + verificación de que el solicitante es dueño del recurso | `auditoria/fase2/A01_control_acceso.txt` → debe responder 401/403 |
| A02 | Tokens de contrato sin hash | Hash (SHA-256 o bcrypt) antes de guardar el token; nunca se devuelve en claro | `A02_criptografia.txt` → el token no aparece en texto plano en la respuesta |
| A03 | Inyección SQL en buscador | Consultas parametrizadas + lista blanca de comunas + regex en precio | `A03_sql_injection.txt` → la inyección no altera la consulta, responde 400 |
| A04 | Reserva duplicada en mismo horario | Restricción de unicidad (propiedad + fecha + hora) con validación previa | `A04_reserva_2.txt` → segunda reserva en el mismo horario responde 409 |
| A05 | Exposición de stack trace | Manejador de errores genérico al cliente; detalle solo en log interno | `A05_stack_trace.txt` → respuesta sin rutas de archivo |
| A06 | Dependencias vulnerables (mapas, conversión de moneda) | `npm audit fix` y actualización a versiones sin CVE conocidos | `A06_dependencias.txt` → 0 vulnerabilidades reportadas |
| A07 | PIN de 3 dígitos por SMS sin expiración | PIN de 6+ dígitos, expiración de 5 min, un solo uso, límite de intentos | `A07_login_pin.txt` → PIN expirado/reusado responde 401 |
| A08 | XSS persistente en descripción | Sanitización de HTML (`sanitize-html`) + escape de salida | `A08_xss.txt` → `<script>` no se guarda ni se ejecuta |
| A09 | Acceso a contratos sin registro | Logging de todo acceso (autorizado y denegado) a contratos confidenciales | Revisión de `access.log` tras `A09_logging.txt` |
| A10 | SSRF en descarga de imágenes | Lista blanca de dominios permitidos + bloqueo de IPs privadas/locales + sin seguir redirecciones | `A10_ssrf.txt` → solicitud a `127.0.0.1`/`169.254.x.x` responde 400 |

## Notas

- Este archivo se actualiza durante la Fase 2 (Refactorización) a medida
  que cada control queda implementado y probado.
- La columna "Cómo se verifica" debe apuntar a la evidencia real generada
  por `auditoria/auditar.sh` en `auditoria/fase2/`.
