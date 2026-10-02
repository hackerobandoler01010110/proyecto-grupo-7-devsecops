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
   obligatorios para cada uno (ver ASC.md).
2. **Diseño seguro** — *Zero Trust Input*: ninguna entrada del cliente se
   confía sin validar.
3. **Implementación** — listas blancas, expresiones regulares,
   parametrización de consultas, manejo de errores sin fuga de
   información.
4. **Verificación** — pruebas de penetración contra los 10 riesgos del
   OWASP Top 10, documentadas en `auditoria/`.
5. **Liberación y mantenimiento** — actualización periódica de
   dependencias (`npm audit`), monitoreo de logs de acceso.

## 4. Política general de controles

- Toda entrada de usuario se valida contra una lista blanca o una
  expresión regular antes de usarse.
- Ninguna credencial, token o secreto se almacena en texto plano.
- Los mensajes de error que ve el cliente nunca incluyen rutas de
  archivo, stack traces ni detalles de la base de datos.
- Todo acceso a datos confidenciales (contratos) queda registrado con
  fecha, hora, usuario y resultado (autorizado/denegado).
- Las dependencias se revisan con `npm audit` antes de cada liberación.

## 5. Excepciones

Cualquier excepción a este marco (por ejemplo, una dependencia que no
puede actualizarse de inmediato) debe quedar documentada en este archivo
con justificación y fecha de revisión.

*(Completa este documento con las decisiones específicas que tome tu
equipo durante el desarrollo.)*
