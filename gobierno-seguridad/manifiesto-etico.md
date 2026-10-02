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

## Compromiso del equipo

Nos comprometemos a auditar nuestro propio código con el mismo rigor con
que auditaríamos el de un tercero, a documentar honestamente las
vulnerabilidades encontradas (incluidas las que nosotros mismos
introdujimos para esta evaluación) y a priorizar la corrección de los
riesgos de mayor impacto sobre los de menor esfuerzo.

*(Este documento es un punto de partida. Complétalo con ejemplos propios
del caso PropNet y con la firma/nombre de cada integrante.)*
