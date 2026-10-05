#!/usr/bin/env bash
# auditar.sh - Pruebas de los 10 riesgos OWASP Top 10 contra PropNet API (Grupo 7).
#
# Uso:  bash auditoria/auditar.sh URL_API [carpeta_salida] [url_metadata_mock]
#
#   Fase 1 (API vulnerable):  bash auditoria/auditar.sh http://IP:3000 auditoria/fase1
#   Fase 2 (API segura):      bash auditoria/auditar.sh http://IP:3000 auditoria/fase2
#
# El modo se deduce de la carpeta de salida (si contiene "fase2" -> modo seguro) o se
# fuerza con FASE=fase1|fase2.
#
# MODO FASE 2: la API segura exige sesion, asi que el script inicia sesion como
# maria@propnet.cl (propietaria) y juan@propnet.cl (arrendatario). El PIN llega por "SMS"
# (consola del servidor). Formas de entregarlo, en este orden:
#   1) Variables de entorno PIN_MARIA / PIN_JUAN (un solo uso cada una).
#   2) SERVER_OUT=archivo : el servidor se arranco con  node server.js | tee salida.txt
#      y el script lee el PIN de ese archivo (demo en un solo equipo).
#   3) Interactivo: el script pide cada PIN por teclado.
# Otras variables opcionales:
#   SRC_DIR     carpeta con package.json para A06 (por defecto src/seguro o src/vulnerable)
#   LOG_ACCESO  ruta a access.log del servidor para verificar A09 (por defecto src/seguro/logs/access.log)
#
# Fase 2 devuelve codigo de salida 0 solo si TODAS las verificaciones pasan (PASS).
# Nota: los limitadores de tasa viven en memoria; si repites la auditoria varias veces
# seguidas (mas de ~3 en 15 min) reinicia el servidor para evitar respuestas 429 espurias.

set -u

BASE_URL="${1:-http://localhost:3000}"
BASE_URL="${BASE_URL%/}"
OUT_DIR="${2:-auditoria/fase1}"
METADATA_URL="${3:-http://127.0.0.1:9999/latest/meta-data/}"

RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
case "${FASE:-$OUT_DIR}" in
  *fase2*) MODO=fase2 ;;
  *)       MODO=fase1 ;;
esac

mkdir -p "$OUT_DIR"
RESUMEN="$OUT_DIR/resumen.txt"
{
  echo "Auditoria PropNet API - $(date)"
  echo "Modo: $MODO"
  echo "Base URL: $BASE_URL"
  echo "----------------------------------------"
} > "$RESUMEN"

# Comprobar que la API responde antes de gastar tiempo.
codigo_inicial="$(curl -s -m 5 -o /dev/null -w '%{http_code}' "$BASE_URL/" 2>/dev/null || true)"
if [ -z "$codigo_inicial" ] || [ "$codigo_inicial" = "000" ]; then
  echo "ERROR: no hay respuesta de $BASE_URL (¿esta corriendo la API y es accesible desde esta maquina?)" | tee -a "$RESUMEN"
  exit 2
fi

# ----------------------------------------------------------------------------
# A06: npm audit (comun a ambas fases). Devuelve por variable global A06_RESULTADO
#      = limpio | vulnerable | no_verificado
# ----------------------------------------------------------------------------
auditar_dependencias() {
  local archivo="$1" src salida
  if [ "$MODO" = fase2 ]; then src="${SRC_DIR:-$RAIZ/src/seguro}"; else src="${SRC_DIR:-$RAIZ/src/vulnerable}"; fi
  [ "$MODO" = fase2 ] || echo ">> Ejecutando A06 - Dependencias (npm audit en $src)"
  {
    echo "=== A06 - Dependencias vulnerables ==="
    echo "Fecha: $(date)"
    echo "Directorio: ${src#"$RAIZ"/}"
    echo
  } > "$OUT_DIR/$archivo"
  A06_RESULTADO="no_verificado"
  if [ ! -f "$src/package.json" ]; then
    echo "No se encontro $src/package.json. Ejecuta con SRC_DIR=/ruta/al/proyecto o corre manualmente: cd <proyecto> && npm audit" >> "$OUT_DIR/$archivo"
  elif ! command -v npm >/dev/null 2>&1; then
    echo "npm no esta instalado en esta maquina. Ejecuta manualmente: cd $src && npm audit" >> "$OUT_DIR/$archivo"
  else
    # npm audit necesita un package-lock.json; si falta se genera sin instalar nada.
    if [ ! -f "$src/package-lock.json" ]; then
      (cd "$src" && npm install --package-lock-only --ignore-scripts --no-audit >/dev/null 2>&1)
    fi
    # npm audit sale con codigo 1 cuando HAY vulnerabilidades: no es un error del script.
    salida="$(cd "$src" && npm audit 2>&1)"
    printf '%s\n' "$salida" >> "$OUT_DIR/$archivo"
    if printf '%s' "$salida" | grep -q "found 0 vulnerabilities"; then A06_RESULTADO="limpio"
    elif printf '%s' "$salida" | grep -qE "Severity:|vulnerabilit(y|ies)"; then A06_RESULTADO="vulnerable"
    fi
  fi
  head -n 12 "$OUT_DIR/$archivo" >> "$RESUMEN"
  echo "----------------------------------------" >> "$RESUMEN"
}

# ============================================================================
#  FASE 1 - API vulnerable: evidencia cruda de cada falla (comportamiento original)
# ============================================================================
run_test() {
  local nombre="$1" archivo="$2"
  shift 2
  echo ">> Ejecutando $nombre"
  {
    echo "=== $nombre ==="
    echo "Comando: curl $*"
    echo "--- Respuesta ---"
    curl -s -m 20 -w "\nHTTP_STATUS:%{http_code}\n" "$@"
    echo ""
  } > "$OUT_DIR/$archivo"
  tail -n 3 "$OUT_DIR/$archivo" >> "$RESUMEN"
  echo "----------------------------------------" >> "$RESUMEN"
}

auditar_fase1() {
  run_test "A01 - Control de acceso roto" "A01_control_acceso.txt" \
    -X PUT "$BASE_URL/arriendos/1" -H "Content-Type: application/json" -d '{"precio": 1}'
  run_test "A02 - Criptografia debil (token en claro)" "A02_criptografia.txt" \
    -X POST "$BASE_URL/contratos" -H "Content-Type: application/json" \
    -d '{"propiedad_id":1,"arrendatario_id":2,"confidencial":"Renta $450.000"}'
  run_test "A03 - Inyeccion SQL" "A03_sql_injection.txt" \
    -G "$BASE_URL/propiedades/buscar" --data-urlencode "comuna=' OR '1'='1" --data-urlencode "precio_max=999999999"
  run_test "A04 - Conflicto de reservas (reserva 1)" "A04_reserva_1.txt" \
    -X POST "$BASE_URL/visitas" -H "Content-Type: application/json" \
    -d '{"propiedad_id":1,"fecha":"2026-10-10","hora":"10:00","visitante":"Persona A"}'
  run_test "A04 - Conflicto de reservas (reserva 2, mismo horario)" "A04_reserva_2.txt" \
    -X POST "$BASE_URL/visitas" -H "Content-Type: application/json" \
    -d '{"propiedad_id":1,"fecha":"2026-10-10","hora":"10:00","visitante":"Persona B"}'
  run_test "A05 - Exposicion de errores (stack trace)" "A05_stack_trace.txt" \
    -G "$BASE_URL/propiedades/buscar" --data-urlencode "comuna=X" \
    --data-urlencode "precio_max=NOT_A_NUMBER); DROP TABLE propiedades;--"
  auditar_dependencias "A06_dependencias.txt"
  run_test "A07 - Login (solicitar PIN)" "A07_login_pin.txt" \
    -X POST "$BASE_URL/login" -H "Content-Type: application/json" -d '{"email":"juan@propnet.cl"}'
  run_test "A08 - XSS persistente" "A08_xss.txt" \
    -X POST "$BASE_URL/propiedades" -H "Content-Type: application/json" \
    -d '{"propietario_id":1,"titulo":"Depto con XSS","descripcion":"<script>alert(1)</script>","comuna":"Providencia","precio":400000}'
  run_test "A09 - Acceso sin registro a contrato" "A09_logging.txt" \
    -X GET "$BASE_URL/contratos/1"
  run_test "A10 - SSRF a metadatos internos" "A10_ssrf.txt" \
    -X POST "$BASE_URL/imagenes/descargar" -H "Content-Type: application/json" \
    -d "{\"url\": \"$METADATA_URL\"}"
}

# ============================================================================
#  FASE 2 - API segura: cada prueba declara el resultado esperado y emite PASS/FAIL
# ============================================================================
CONT_PASS=0; CONT_FAIL=0; CONT_OMIT=0
TOKEN_MARIA=""; TOKEN_JUAN=""
LAST_STATUS=""; LAST_BODY=""; PIN_OBTENIDO=""

ev_inicio() { { echo "=== $2 ==="; echo "Fecha: $(date)"; echo "Objetivo: $BASE_URL"; echo; } > "$OUT_DIR/$1"; }
ev_nota()   { printf '%s\n' "$2" >> "$OUT_DIR/$1"; }

# Oculta los tokens de sesion en la evidencia (la evidencia se sube a GitHub).
enmascarar() {
  local s="$*"
  [ -n "$TOKEN_MARIA" ] && s="${s//$TOKEN_MARIA/<TOKEN_MARIA>}"
  [ -n "$TOKEN_JUAN" ]  && s="${s//$TOKEN_JUAN/<TOKEN_JUAN>}"
  printf '%s' "$s"
}

# ev_curl archivo etiqueta [argumentos de curl...]  -> deja LAST_STATUS y LAST_BODY
ev_curl() {
  local archivo="$1" etiqueta="$2" crudo
  shift 2
  crudo="$(curl -s -m 20 -w '\nHTTP_STATUS:%{http_code}' "$@" 2>&1)"
  LAST_STATUS="$(printf '%s\n' "$crudo" | tail -n 1 | sed 's/^HTTP_STATUS://')"
  LAST_BODY="$(printf '%s\n' "$crudo" | sed '$d')"
  {
    echo "--- $etiqueta ---"
    echo "Comando: curl $(enmascarar "$@")"
    echo "Respuesta:"
    printf '%s\n' "$LAST_BODY" | sed -E 's/"token":"[a-f0-9]{64}"/"token":"<TOKEN_OCULTO>"/g'
    echo "HTTP_STATUS:$LAST_STATUS"
    echo
  } >> "$OUT_DIR/$archivo"
}

veredicto() { # archivo descripcion ok(1|0) [detalle]
  local linea
  if [ "$3" = "1" ]; then linea="[PASS] $2"; CONT_PASS=$((CONT_PASS+1))
  else linea="[FAIL] $2${4:+ ($4)}"; CONT_FAIL=$((CONT_FAIL+1)); fi
  printf '%s\n' "$linea" >> "$OUT_DIR/$1"
  printf '%s\n' "$linea" >> "$RESUMEN"
  echo "   $linea"
}
chk_estado() { # archivo descripcion esperado
  if [ "$LAST_STATUS" = "$3" ]; then veredicto "$1" "$2 -> HTTP $3" 1
  else veredicto "$1" "$2 -> esperado HTTP $3" 0 "obtenido HTTP ${LAST_STATUS:-?}"; fi
}
omitir() { # archivo descripcion motivo
  local linea="[OMITIDO] $2 ($3)"
  CONT_OMIT=$((CONT_OMIT+1))
  printf '%s\n' "$linea" >> "$OUT_DIR/$1"; printf '%s\n' "$linea" >> "$RESUMEN"; echo "   $linea"
}
seccion() { echo ">> Ejecutando $1"; { echo; echo "## $1"; } >> "$RESUMEN"; }

fecha_futura() { date -d "+$1 days" +%F 2>/dev/null || date -v+"$1"d +%F; }
JSON=(-H "Content-Type: application/json")
# Patrones que NUNCA deben verse en una respuesta de error (rutas, stack, ruta de archivos).
FUGAS='node_modules|\.js:[0-9]+|/home/|/usr/|/Users/|/var/|[A-Za-z]:\\|"stack"|SQLITE|syntax error'

obtener_pin() { # email antes -> deja PIN_OBTENIDO
  local email="$1" antes="${2:-0}" var pin="" i ahora
  PIN_OBTENIDO=""
  var="PIN_$(printf '%s' "${email%%@*}" | tr 'a-z' 'A-Z')"
  if [ -n "${!var:-}" ]; then PIN_OBTENIDO="${!var}"; unset "$var"; return 0; fi
  if [ -n "${SERVER_OUT:-}" ] && [ -f "$SERVER_OUT" ]; then
    for i in 1 2 3 4 5 6 7 8 9 10; do
      ahora="$(grep -cF "PIN para $email:" "$SERVER_OUT")"
      if [ "$ahora" -gt "$antes" ]; then
        pin="$(grep -F "PIN para $email:" "$SERVER_OUT" | tail -n 1 | sed -E 's/.*PIN para [^:]+: ([0-9]{6}).*/\1/')"
        break
      fi
      sleep 0.3
    done
    PIN_OBTENIDO="$pin"; [ -n "$pin" ] && return 0
  fi
  if [ -t 0 ]; then
    read -r -p "   Ingresa el PIN de $email (mira la consola del servidor): " PIN_OBTENIDO
    [ -n "$PIN_OBTENIDO" ] && return 0
  fi
  return 1
}

# iniciar_sesion email -> deja SESION_TOKEN y PIN_USADO_ULTIMO (variables globales: no usar $(...))
iniciar_sesion() {
  local email="$1" antes=0
  SESION_TOKEN=""; PIN_USADO_ULTIMO=""
  if [ -n "${SERVER_OUT:-}" ] && [ -f "$SERVER_OUT" ]; then antes="$(grep -cF "PIN para $email:" "$SERVER_OUT")"; fi
  ev_curl "A07_login_pin.txt" "Preparacion: solicitar PIN para $email" -X POST "$BASE_URL/login" "${JSON[@]}" -d "{\"email\":\"$email\"}"
  [ "$LAST_STATUS" = "200" ] || return 1
  obtener_pin "$email" "$antes" || return 1
  ev_curl "A07_login_pin.txt" "Preparacion: verificar PIN de $email (PIN = <PIN_ENTREGADO_POR_SMS>)" \
    -X POST "$BASE_URL/login/verificar" "${JSON[@]}" -d "{\"email\":\"$email\",\"pin\":\"$PIN_OBTENIDO\"}"
  [ "$LAST_STATUS" = "200" ] || return 1
  SESION_TOKEN="$(printf '%s' "$LAST_BODY" | sed -n 's/.*"token":"\([a-f0-9]\{64\}\)".*/\1/p')"
  [ -n "$SESION_TOKEN" ] || return 1
  PIN_USADO_ULTIMO="$PIN_OBTENIDO"
}

auditar_fase2() {
  ev_inicio "A07_login_pin.txt" "A07 - Autenticacion robusta (PIN 6 digitos, un solo uso, limite de intentos)"

  # --- Preparacion: sesiones --------------------------------------------------
  echo ">> Preparando sesiones (maria = propietaria, juan = arrendatario)"
  iniciar_sesion maria@propnet.cl; TOKEN_MARIA="$SESION_TOKEN"
  iniciar_sesion juan@propnet.cl;  TOKEN_JUAN="$SESION_TOKEN"; PIN_JUAN_USADO="$PIN_USADO_ULTIMO"
  if [ -z "$TOKEN_MARIA" ] || [ -z "$TOKEN_JUAN" ]; then
    echo "ERROR: no se pudo iniciar sesion. Entrega los PIN con PIN_MARIA/PIN_JUAN, SERVER_OUT=archivo, o en modo interactivo." | tee -a "$RESUMEN"
    echo "       (Si ya hiciste varias auditorias seguidas, reinicia el servidor: los limites de tasa estan en memoria.)" | tee -a "$RESUMEN"
    exit 2
  fi
  AUTH_M=(-H "Authorization: Bearer $TOKEN_MARIA")
  AUTH_J=(-H "Authorization: Bearer $TOKEN_JUAN")

  # --- A01 -------------------------------------------------------------------
  seccion "A01 - Control de acceso roto"
  f="A01_control_acceso.txt"; ev_inicio "$f" "A01 - Control de acceso (autenticacion + propiedad del recurso)"
  ev_curl "$f" "Sin sesion: modificar precio" -X PUT "$BASE_URL/arriendos/1" "${JSON[@]}" -d '{"precio":1}'
  chk_estado "$f" "Sin sesion no se puede cambiar el precio" 401
  ev_curl "$f" "Arrendatario intenta cambiar precio de propiedad ajena" -X PUT "$BASE_URL/arriendos/1" "${AUTH_J[@]}" "${JSON[@]}" -d '{"precio":100000}'
  chk_estado "$f" "Arrendatario no puede alterar el valor del arriendo" 403
  ev_curl "$f" "Arrendatario intenta modificar datos del propietario" -X PUT "$BASE_URL/usuarios/1" "${AUTH_J[@]}" "${JSON[@]}" -d '{"nombre":"Hackeado","telefono":"+56900000000"}'
  chk_estado "$f" "Arrendatario no puede modificar datos del propietario" 403
  ev_curl "$f" "Propietaria intenta cambiar precio de propiedad de otro propietario (id 3)" -X PUT "$BASE_URL/arriendos/3" "${AUTH_M[@]}" "${JSON[@]}" -d '{"precio":100000}'
  chk_estado "$f" "Un propietario no puede alterar propiedades de otro" 403
  ev_curl "$f" "Escalada de privilegios por mass assignment (campo rol)" -X PUT "$BASE_URL/usuarios/2" "${AUTH_J[@]}" "${JSON[@]}" -d '{"nombre":"Juan Perez","rol":"propietario"}'
  chk_estado "$f" "Campos no permitidos (rol) rechazados" 400
  ev_curl "$f" "Control positivo: la propietaria cambia el precio de SU propiedad" -X PUT "$BASE_URL/arriendos/1" "${AUTH_M[@]}" "${JSON[@]}" -d '{"precio":450000}'
  chk_estado "$f" "El dueño si puede modificar su propiedad (precio valido)" 200

  # --- A02 -------------------------------------------------------------------
  seccion "A02 - Fallas criptograficas"
  f="A02_criptografia.txt"; ev_inicio "$f" "A02 - Token de contrato: hash en reposo y nunca en la respuesta"
  ev_curl "$f" "Crear contrato (propietaria)" -X POST "$BASE_URL/contratos" "${AUTH_M[@]}" "${JSON[@]}" \
    -d '{"propiedad_id":1,"arrendatario_id":2,"confidencial":"Renta $450.000"}'
  chk_estado "$f" "Contrato creado" 201
  # Se busca una CLAVE JSON "token..." o un hex de 64 caracteres (el mensaje de texto puede decir "token").
  if printf '%s' "$LAST_BODY" | grep -qiE '"token[a-z_]*"|[a-f0-9]{64}'; then
    veredicto "$f" "La respuesta no contiene el token en claro" 0 "se detecto una clave 'token' o un hex de 64 caracteres"
  else veredicto "$f" "La respuesta no contiene el token en claro" 1; fi
  CONTRATO_ID="$(printf '%s' "$LAST_BODY" | sed -n 's/.*"contrato_id":\([0-9]*\).*/\1/p')"
  if [ -n "$CONTRATO_ID" ]; then
    ev_curl "$f" "Lectura del contrato por el arrendatario" "$BASE_URL/contratos/$CONTRATO_ID" "${AUTH_J[@]}"
    chk_estado "$f" "El arrendatario lee su contrato" 200
    if printf '%s' "$LAST_BODY" | grep -qiE '"token[a-z_]*"|"[a-z_]*hash"|[a-f0-9]{64}'; then
      veredicto "$f" "La lectura del contrato no expone token ni hash" 0
    else veredicto "$f" "La lectura del contrato no expone token ni hash" 1; fi
  fi
  ev_nota "$f" "Nota: en la base solo se guarda HMAC-SHA256 del token y el texto confidencial va cifrado (AES-256-GCM); se verifica en test/integracion.test.js."

  # --- A03 -------------------------------------------------------------------
  seccion "A03 - Inyeccion SQL"
  f="A03_sql_injection.txt"; ev_inicio "$f" "A03 - Buscador: consultas parametrizadas + lista blanca + regex"
  ev_curl "$f" "Payload clasico en comuna" -G "$BASE_URL/propiedades/buscar" --data-urlencode "comuna=' OR '1'='1" --data-urlencode "precio_max=999999999"
  chk_estado "$f" "' OR '1'='1 no altera la consulta" 400
  ev_curl "$f" "UNION SELECT en comuna" -G "$BASE_URL/propiedades/buscar" --data-urlencode "comuna=Providencia' UNION SELECT id,email,rol,telefono,1,2 FROM usuarios--"
  chk_estado "$f" "UNION SELECT rechazado" 400
  ev_curl "$f" "Inyeccion en precio_max" -G "$BASE_URL/propiedades/buscar" --data-urlencode "comuna=Providencia" --data-urlencode "precio_max=1 OR 1=1"
  chk_estado "$f" "precio_max no numerico rechazado" 400
  ev_curl "$f" "DROP TABLE en precio_max" -G "$BASE_URL/propiedades/buscar" --data-urlencode "comuna=X" --data-urlencode "precio_max=NOT_A_NUMBER); DROP TABLE propiedades;--"
  chk_estado "$f" "DROP TABLE rechazado" 400
  ev_curl "$f" "Control positivo: busqueda legitima" -G "$BASE_URL/propiedades/buscar" --data-urlencode "comuna=Providencia" --data-urlencode "precio_max=1000000"
  chk_estado "$f" "La busqueda legitima sigue funcionando" 200

  # --- A04 -------------------------------------------------------------------
  seccion "A04 - Diseño inseguro (reservas)"
  f1="A04_reserva_1.txt"; f2="A04_reserva_2.txt"
  ev_inicio "$f1" "A04 - Reserva 1 (propiedad 1, horario libre)"; ev_inicio "$f2" "A04 - Reserva 2 en el MISMO horario"
  intento=0; FECHA=""; HORA=""
  while [ "$intento" -lt 6 ]; do
    FECHA="$(fecha_futura $(( (RANDOM % 150) + 5 )))"; HORA="$(printf '%02d:00' $(( 9 + RANDOM % 10 )))"
    ev_curl "$f1" "Visita de Juan" -X POST "$BASE_URL/visitas" "${AUTH_J[@]}" "${JSON[@]}" \
      -d "{\"propiedad_id\":1,\"fecha\":\"$FECHA\",\"hora\":\"$HORA\",\"visitante\":\"Juan Arrendatario\"}"
    [ "$LAST_STATUS" = "201" ] && break
    intento=$((intento+1))   # el horario elegido ya estaba ocupado por una auditoria anterior: se prueba otro
  done
  chk_estado "$f1" "Primera reserva aceptada" 201
  ev_curl "$f2" "Visita de Maria, misma propiedad, fecha y hora" -X POST "$BASE_URL/visitas" "${AUTH_M[@]}" "${JSON[@]}" \
    -d "{\"propiedad_id\":1,\"fecha\":\"$FECHA\",\"hora\":\"$HORA\",\"visitante\":\"Maria Propietaria\"}"
  chk_estado "$f2" "Segunda reserva en el mismo horario" 409
  ev_curl "$f2" "Hora fuera de los bloques permitidos" -X POST "$BASE_URL/visitas" "${AUTH_J[@]}" "${JSON[@]}" \
    -d "{\"propiedad_id\":1,\"fecha\":\"$FECHA\",\"hora\":\"03:00\"}"
  chk_estado "$f2" "Hora 03:00 rechazada" 400
  ev_curl "$f2" "Fecha pasada" -X POST "$BASE_URL/visitas" "${AUTH_J[@]}" "${JSON[@]}" \
    -d '{"propiedad_id":1,"fecha":"2020-01-01","hora":"10:00"}'
  chk_estado "$f2" "Fecha pasada rechazada" 400
  ev_curl "$f2" "Sin sesion" -X POST "$BASE_URL/visitas" "${JSON[@]}" -d "{\"propiedad_id\":1,\"fecha\":\"$FECHA\",\"hora\":\"$HORA\"}"
  chk_estado "$f2" "Reservar exige sesion" 401

  # --- A05 -------------------------------------------------------------------
  seccion "A05 - Mala configuracion / exposicion de errores"
  f="A05_stack_trace.txt"; ev_inicio "$f" "A05 - Errores genericos y cabeceras de seguridad"
  ev_curl "$f" "Entrada que antes provocaba stack trace" -G "$BASE_URL/propiedades/buscar" --data-urlencode "comuna=X" --data-urlencode "precio_max=NOT_A_NUMBER); DROP TABLE propiedades;--"
  chk_estado "$f" "Entrada maliciosa" 400
  if printf '%s' "$LAST_BODY" | grep -qE "$FUGAS"; then veredicto "$f" "Sin rutas ni stack trace en la respuesta" 0 "fuga detectada"; else veredicto "$f" "Sin rutas ni stack trace en la respuesta" 1; fi
  ev_curl "$f" "JSON mal formado" -X POST "$BASE_URL/login" "${JSON[@]}" -d '{"email": '
  chk_estado "$f" "JSON invalido" 400
  if printf '%s' "$LAST_BODY" | grep -qE "$FUGAS"; then veredicto "$f" "Error de parseo sin detalles internos" 0; else veredicto "$f" "Error de parseo sin detalles internos" 1; fi
  ev_curl "$f" "Ruta inexistente" "$BASE_URL/admin/config"
  chk_estado "$f" "Ruta inexistente" 404
  ev_curl "$f" "Cabeceras de respuesta" -i "$BASE_URL/salud"
  if printf '%s' "$LAST_BODY" | grep -qi '^x-powered-by'; then veredicto "$f" "No se anuncia X-Powered-By" 0; else veredicto "$f" "No se anuncia X-Powered-By" 1; fi
  if printf '%s' "$LAST_BODY" | grep -qi '^x-content-type-options: *nosniff'; then veredicto "$f" "Cabecera X-Content-Type-Options: nosniff presente" 1; else veredicto "$f" "Cabecera X-Content-Type-Options: nosniff presente" 0; fi
  if printf '%s' "$LAST_BODY" | grep -qi '^content-security-policy:'; then veredicto "$f" "Cabecera Content-Security-Policy presente" 1; else veredicto "$f" "Cabecera Content-Security-Policy presente" 0; fi

  # --- A06 -------------------------------------------------------------------
  seccion "A06 - Dependencias vulnerables"
  auditar_dependencias "A06_dependencias.txt"
  case "$A06_RESULTADO" in
    limpio)      veredicto "A06_dependencias.txt" "npm audit: 0 vulnerabilidades" 1 ;;
    vulnerable)  veredicto "A06_dependencias.txt" "npm audit: 0 vulnerabilidades" 0 "se reportan vulnerabilidades" ;;
    *)           omitir   "A06_dependencias.txt" "npm audit" "no se pudo ejecutar (sin red, sin npm o sin package.json); correr manualmente" ;;
  esac

  # --- A07 -------------------------------------------------------------------
  seccion "A07 - Autenticacion debil"
  f="A07_login_pin.txt"
  ev_nota "$f" ""; ev_nota "$f" "##### Pruebas de endurecimiento #####"
  ev_curl "$f" "Solicitar PIN con correo registrado" -X POST "$BASE_URL/login" "${JSON[@]}" -d '{"email":"pedro@propnet.cl"}'
  chk_estado "$f" "Solicitud de PIN aceptada" 200
  RESP_REAL="$LAST_BODY"
  if printf '%s' "$LAST_BODY" | grep -qE '(^|[^0-9])[0-9]{6}([^0-9]|$)|"pin"'; then veredicto "$f" "El PIN no viaja en la respuesta HTTP" 0; else veredicto "$f" "El PIN no viaja en la respuesta HTTP" 1; fi
  ev_curl "$f" "Solicitar PIN con correo inexistente" -X POST "$BASE_URL/login" "${JSON[@]}" -d '{"email":"nadie@propnet.cl"}'
  if [ "$LAST_BODY" = "$RESP_REAL" ] && [ "$LAST_STATUS" = "200" ]; then veredicto "$f" "Misma respuesta exista o no el correo (sin enumeracion)" 1; else veredicto "$f" "Misma respuesta exista o no el correo (sin enumeracion)" 0; fi
  ev_curl "$f" "PIN de 3 digitos (formato antiguo)" -X POST "$BASE_URL/login/verificar" "${JSON[@]}" -d '{"email":"juan@propnet.cl","pin":"123"}'
  chk_estado "$f" "PIN de 3 digitos rechazado" 400
  if [ -n "$PIN_JUAN_USADO" ]; then
    ev_curl "$f" "Reutilizar el PIN que ya se uso para iniciar sesion (PIN = <PIN_YA_USADO>)" -X POST "$BASE_URL/login/verificar" "${JSON[@]}" -d "{\"email\":\"juan@propnet.cl\",\"pin\":\"$PIN_JUAN_USADO\"}"
    chk_estado "$f" "PIN de un solo uso: la reutilizacion es rechazada" 401
  else
    omitir "$f" "Reutilizacion de PIN" "no se conserva el PIN usado en la preparacion"
  fi
  ev_curl "$f" "Pedir un PIN nuevo para juan y adivinar a ciegas (fuerza bruta)" -X POST "$BASE_URL/login" "${JSON[@]}" -d '{"email":"juan@propnet.cl"}'
  codigos=""
  for i in 1 2 3 4 5 6; do
    ev_curl "$f" "Intento de fuerza bruta $i con PIN incorrecto" -X POST "$BASE_URL/login/verificar" "${JSON[@]}" -d '{"email":"juan@propnet.cl","pin":"000000"}'
    codigos="$codigos $LAST_STATUS"
  done
  if [ "${codigos# }" = "401 401 401 401 429 429" ]; then veredicto "$f" "Fuerza bruta bloqueada tras 5 intentos (401 x4, luego 429)" 1
  else veredicto "$f" "Fuerza bruta bloqueada tras 5 intentos (401 x4, luego 429)" 0 "codigos obtenidos:$codigos"; fi
  ev_nota "$f" "Nota: la expiracion (5 min) se verifica en test/integracion.test.js; no se espera 5 minutos en esta auditoria."

  # --- A08 -------------------------------------------------------------------
  seccion "A08 - XSS persistente"
  f="A08_xss.txt"; ev_inicio "$f" "A08 - Descripcion sin HTML + escape de salida + CSP"
  ev_curl "$f" "Publicar descripcion con <script>" -X POST "$BASE_URL/propiedades" "${AUTH_M[@]}" "${JSON[@]}" \
    -d '{"titulo":"Depto con XSS","descripcion":"<script>alert(1)</script>","comuna":"Providencia","precio":400000}'
  chk_estado "$f" "<script> no se guarda" 400
  ev_curl "$f" "Publicar titulo con <img onerror>" -X POST "$BASE_URL/propiedades" "${AUTH_M[@]}" "${JSON[@]}" \
    -d '{"titulo":"<img src=x onerror=alert(1)>","descripcion":"Texto normal","comuna":"Providencia","precio":400000}'
  chk_estado "$f" "<img onerror> rechazado" 400
  ev_curl "$f" "Control positivo: publicar propiedad legitima" -X POST "$BASE_URL/propiedades" "${AUTH_M[@]}" "${JSON[@]}" \
    -d '{"titulo":"Depto luminoso","descripcion":"Cerca del metro, gastos comunes aparte.","comuna":"Providencia","precio":400000}'
  chk_estado "$f" "Publicacion legitima aceptada" 201
  PROP_ID="$(printf '%s' "$LAST_BODY" | sed -n 's/.*"id":\([0-9]*\).*/\1/p')"
  if [ -n "$PROP_ID" ]; then
    ev_curl "$f" "Ver la propiedad (cabeceras + HTML)" -i "$BASE_URL/propiedades/$PROP_ID"
    if printf '%s' "$LAST_BODY" | grep -qi '<script'; then veredicto "$f" "La pagina no contiene <script>" 0; else veredicto "$f" "La pagina no contiene <script>" 1; fi
    if printf '%s' "$LAST_BODY" | grep -qi "^content-security-policy:.*default-src 'none'"; then veredicto "$f" "CSP restrictiva en la vista HTML" 1; else veredicto "$f" "CSP restrictiva en la vista HTML" 0; fi
  fi

  # --- A09 -------------------------------------------------------------------
  seccion "A09 - Registro y monitoreo"
  f="A09_logging.txt"; ev_inicio "$f" "A09 - Todo acceso a contratos queda registrado (autorizado y denegado)"
  LOG_A="${LOG_ACCESO:-$RAIZ/src/seguro/logs/access.log}"
  lineas_antes=0; [ -f "$LOG_A" ] && lineas_antes="$(wc -l < "$LOG_A" | tr -d ' ')"
  ev_curl "$f" "Sin sesion" "$BASE_URL/contratos/1"
  chk_estado "$f" "Acceso a contrato sin sesion" 401
  ev_curl "$f" "Arrendatario ajeno al contrato 2 (de Pedro)" "$BASE_URL/contratos/2" "${AUTH_J[@]}"
  chk_estado "$f" "Acceso a contrato ajeno" 403
  ev_curl "$f" "Arrendatario accede a SU contrato" "$BASE_URL/contratos/1" "${AUTH_J[@]}"
  chk_estado "$f" "Acceso a contrato propio" 200
  if [ -f "$LOG_A" ]; then
    nuevas="$(tail -n +"$((lineas_antes+1))" "$LOG_A")"
    { echo "--- Entradas nuevas en access.log ($LOG_A) ---"; printf '%s\n' "$nuevas"; echo; } >> "$OUT_DIR/$f"
    n_ok="$(printf '%s\n' "$nuevas" | grep -c '"resultado":"autorizado"')"
    n_den="$(printf '%s\n' "$nuevas" | grep -c '"resultado":"denegado"')"
    if [ "$n_den" -ge 2 ] && [ "$n_ok" -ge 1 ]; then veredicto "$f" "access.log registra 2 accesos denegados y 1 autorizado" 1
    else veredicto "$f" "access.log registra 2 accesos denegados y 1 autorizado" 0 "denegados=$n_den autorizados=$n_ok"; fi
  else
    omitir "$f" "Verificacion del access.log" "el log no es accesible desde esta maquina (esperado en $LOG_A); revisarlo en el servidor o usar LOG_ACCESO=ruta"
  fi

  # --- A10 -------------------------------------------------------------------
  seccion "A10 - SSRF"
  f="A10_ssrf.txt"; ev_inicio "$f" "A10 - Lista blanca + bloqueo de IP privadas + solo https"
  ev_curl "$f" "Sin sesion" -X POST "$BASE_URL/imagenes/descargar" "${JSON[@]}" -d "{\"url\":\"https://images.unsplash.com/a.jpg\"}"
  chk_estado "$f" "Descarga sin sesion" 401
  ev_curl "$f" "Arrendatario (rol no autorizado)" -X POST "$BASE_URL/imagenes/descargar" "${AUTH_J[@]}" "${JSON[@]}" -d "{\"url\":\"https://images.unsplash.com/a.jpg\"}"
  chk_estado "$f" "Descarga por un rol no autorizado" 403
  for destino in "$METADATA_URL" "http://169.254.169.254/latest/meta-data/" "http://localhost:3000/" \
                 "https://127.0.0.1/" "http://2130706433/" "file:///etc/passwd" "https://evil.example.com/x.png"; do
    ev_curl "$f" "SSRF hacia $destino" -X POST "$BASE_URL/imagenes/descargar" "${AUTH_M[@]}" "${JSON[@]}" -d "{\"url\":\"$destino\"}"
    chk_estado "$f" "Bloqueado: $destino" 400
    if printf '%s' "$LAST_BODY" | grep -qiE 'ECONN|127\.0\.0\.1|meta-data|AKIA|SecretAccessKey|"stack"'; then veredicto "$f" "Respuesta generica, sin detalle interno" 0; fi
  done
}

# ============================================================================
if [ "$MODO" = fase2 ]; then
  auditar_fase2
  {
    echo "----------------------------------------"
    echo "RESULTADO FASE 2: PASS=$CONT_PASS FAIL=$CONT_FAIL OMITIDO=$CONT_OMIT"
  } | tee -a "$RESUMEN"
  echo "Evidencias individuales en: $OUT_DIR/"
  [ "$CONT_FAIL" -eq 0 ]
else
  auditar_fase1
  echo ""
  echo "Auditoria completa. Resumen en: $RESUMEN"
  echo "Evidencias individuales en: $OUT_DIR/"
fi
