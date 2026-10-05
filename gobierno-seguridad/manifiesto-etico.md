# Manifiesto Ético — PropNet API

## Contexto

PropNet maneja datos especialmente sensibles: identidad de arrendatarios y
propietarios, montos de arriendo, contratos y coordinación de visitas a
inmuebles. Una falla de seguridad aquí no es abstracta — puede exponer la
dirección donde vive una persona, su situación financiera, o facilitar
fraudes sobre un contrato real.

## Principios que asume el equipo

1. **La seguridad no es responsabilidad de otro departamento.** Quien
   escribe el código que mueve datos de usuarios es responsable de las
   consecuencias de ese código, aunque el plazo de entrega sea ajustado.

2. **El dato ajeno se trata con el mismo cuidado que el propio.** No se
   almacena, transmite ni registra información más allá de lo
   estrictamente necesario para el funcionamiento del servicio
   (minimización de datos).

3. **Transparencia ante el fallo.** Si una vulnerabilidad compromete datos
   de usuarios, se informa de forma oportuna y clara a los afectados y a
   la organización, en vez de ocultarla o minimizarla.

4. **Seguridad por diseño, no como parche.** Los controles de acceso,
   cifrado y validación se piensan desde el diseño de cada funcionalidad,
   no se agregan después de un incidente.

5. **El atajo que ahorra una hora puede costarle a otro su privacidad.**
   Decisiones como guardar un token sin cifrar o enviar un PIN de 3
   dígitos por SMS parecen inofensivas en el corto plazo, pero trasladan
   el riesgo a personas que no pueden decidir sobre esa implementación.

## Cómo se refleja en PropNet

Estos principios no se quedan en declaraciones: cada uno tiene una
decisión concreta en el código de `src/seguro/`.

| Principio | Decisión en el código |
|---|---|
| Responsabilidad sobre el código propio | Cada cambio pasa por Pull Request y por pruebas automatizadas (`npm test`) antes de llegar a `main` |
| Minimización de datos | Los logs guardan identificadores, no el contenido de los contratos; el PIN y los tokens nunca se escriben en los logs ni viajan en las respuestas |
| Cuidado del dato ajeno | Solo las partes de un contrato pueden leerlo; el texto confidencial se guarda cifrado; un usuario solo modifica su propio perfil |
| Transparencia ante el fallo | Cada error interno genera un identificador de incidente que permite ubicar el detalle en `errores.log`, y todo acceso denegado queda registrado en lugar de silenciarse |
| Seguridad por diseño | La reserva de visitas se protege con una restricción `UNIQUE` en la base de datos, y no solo con una validación previa en el código |
| El atajo tiene un costo para otro | El PIN pasó de 3 a 6 dígitos con expiración y un solo uso, y los tokens se guardan como hash; ambos son los atajos que la versión vulnerable toma a propósito |

## Compromiso del equipo

Nos comprometemos a auditar nuestro propio código con el mismo rigor con
que auditaríamos el de un tercero, a documentar honestamente las
vulnerabilidades encontradas (incluidas las que nosotros mismos
introdujimos para esta evaluación) y a priorizar la corrección de los
riesgos de mayor impacto sobre los de menor esfuerzo.

En coherencia con ese compromiso, las limitaciones que aún tiene la
versión segura (límites de tasa en memoria, canal de PIN simulado, logs
sin rotación y evidencia generada desde el mismo equipo) no se ocultan:
están registradas como excepciones en `ONF.md`, sección 5.

También asumimos que `src/vulnerable/` se mantiene como material de
estudio y no se despliega ni se expone a redes públicas.

## Integrantes

| Integrante | Rol | Firma |
|---|---|---|
| David Zamorano | Líder técnico / DevSecOps | David |
| Giancarlo Guarda | Desarrollador | Gianca |
| Marcelo Astudillo | Auditor / Pentester | Marcelo |
