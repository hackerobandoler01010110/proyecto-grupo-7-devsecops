# PropNet API — Grupo 7 (DevSecOps)

Plataforma de gestión de propiedades y arriendos. Proyecto de la
evaluación "Ética, Gobernanza (ISO/IEC 27034) y Seguridad Aplicada
(OWASP Top 10)".

## Integrantes

- David Zamorano — rol
- Marcelo Astudillo — rol
- Giancarlo Guarda — rol

## Estructura del repositorio

```
gobierno-seguridad/   Manifiesto ético, ONF y ASC (ISO/IEC 27034)
src/vulnerable/        API con las 10 fallas OWASP Top 10 a propósito
src/seguro/             Misma API con los 10 controles implementados
auditoria/
  auditar.sh            Script que ejecuta las 10 pruebas (reutilizable)
  fase1/                Evidencia contra la API vulnerable
  fase2/                Evidencia contra la API segura (re-pruebas)
```

## Cómo ejecutar la API vulnerable

```bash
cd src/vulnerable
npm install
npm run seed      # crea propnet.db con datos de prueba
node server.js    # escucha en http://localhost:3000
```

Opcional, para probar el SSRF (A10) de forma controlada, en otra
terminal:

```bash
node metadata-mock.js   # simula un endpoint de metadatos en :9999
```

## Cómo ejecutar la auditoría

Desde la raíz del repositorio, con la API corriendo:

```bash
bash auditoria/auditar.sh http://localhost:3000 auditoria/fase1
```

El mismo comando se usa contra `src/seguro/` apuntando a
`auditoria/fase2` como carpeta de salida, una vez completada la
refactorización.

## Resumen de riesgos y mitigaciones

Ver tabla completa en `gobierno-seguridad/ASC.md`.

| # | Riesgo OWASP | Estado |
|---|---|---|
| A01 | Control de acceso roto | ⬜ Pendiente de refactorizar |
| A02 | Fallas criptográficas | ⬜ Pendiente |
| A03 | Inyección SQL | ⬜ Pendiente |
| A04 | Diseño inseguro (reservas) | ⬜ Pendiente |
| A05 | Mala configuración de seguridad | ⬜ Pendiente |
| A06 | Dependencias vulnerables | ⬜ Pendiente |
| A07 | Autenticación débil | ⬜ Pendiente |
| A08 | XSS persistente | ⬜ Pendiente |
| A09 | Fallas de registro y monitoreo | ⬜ Pendiente |
| A10 | SSRF | ⬜ Pendiente |

*(Actualiza el estado a medida que completes `src/seguro/` y vuelvas a
correr la auditoría.)*

## Advertencia

`src/vulnerable/` contiene fallas de seguridad introducidas a propósito
con fines académicos. No desplegar en producción ni exponer a redes
públicas.
