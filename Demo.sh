#!/usr/bin/env bash
# USAGE: bash Demo.sh
# REQUIRES: openssl
# DESCRIPTION: End-to-end PKI demo for Casa Monarca.
#   Generates a self-signed CA, issues an end-entity certificate,
#   signs a document, and verifies the signature — all with OpenSSL.
#   No step-ca or external tools required.

set -euo pipefail

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# ── Artefactos generados ──────────────────────────────────────────────────────
CA_KEY="ca.key"
CA_CERT="ca.crt"
SERVICE_KEY="servicio.key"
SERVICE_CSR="servicio.csr"
SERVICE_CERT="servicio.crt"
DOCUMENT="documento.txt"
SIGNATURE="firma.bin"

GENERATED_FILES=("$CA_KEY" "$CA_CERT" "$SERVICE_KEY" "$SERVICE_CSR" "$SERVICE_CERT" "$DOCUMENT" "$SIGNATURE")

# ── Verificar dependencias ────────────────────────────────────────────────────
check_deps() {
    if ! command -v openssl &>/dev/null; then
        echo -e "${RED}Error: openssl no está instalado o no está en PATH.${RESET}"
        echo "Instala con: brew install openssl  (macOS)  |  apt install openssl  (Debian/Ubuntu)"
        exit 1
    fi
    OPENSSL_VER=$(openssl version)
    echo -e "${CYAN}Usando: ${OPENSSL_VER}${RESET}"
}

# ── Función de limpieza ───────────────────────────────────────────────────────
cleanup() {
    echo ""
    echo -e "${YELLOW}══════════════════════════════════════════${RESET}"
    echo -e "${YELLOW}  Limpieza de archivos generados          ${RESET}"
    echo -e "${YELLOW}══════════════════════════════════════════${RESET}"
    echo ""
    echo "Los siguientes archivos fueron generados por este demo:"
    for f in "${GENERATED_FILES[@]}"; do
        if [[ -f "$f" ]]; then
            echo "  - $f"
        fi
    done
    echo ""
    read -rp "¿Eliminar todos los archivos generados? [s/N] " respuesta
    case "$respuesta" in
        [sS])
            for f in "${GENERATED_FILES[@]}"; do
                [[ -f "$f" ]] && rm "$f" && echo -e "  ${GREEN}Eliminado: $f${RESET}"
            done
            echo ""
            echo -e "${GREEN}Limpieza completada.${RESET}"
            ;;
        *)
            echo "Los archivos se conservan en el directorio actual."
            ;;
    esac
}

# ── Encabezado ────────────────────────────────────────────────────────────────
header() {
    echo ""
    echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════╗${RESET}"
    echo -e "${BOLD}${CYAN}║   Casa Monarca — Demo PKI de extremo a extremo  ║${RESET}"
    echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════╝${RESET}"
    echo ""
    echo -e "  ${BOLD}Flujo demostrado:${RESET}"
    echo "  1. Generar CA raíz interna (EC P-256)"
    echo "  2. Emitir certificado para un colaborador (RSA-2048)"
    echo "  3. Firmar un documento con la clave del colaborador (RSA-PSS)"
    echo "  4. Verificar la firma con la clave pública del certificado"
    echo ""
}

# ── Paso 1: Generar CA raíz ───────────────────────────────────────────────────
step_ca() {
    echo -e "${BOLD}[ Paso 1 ] Generando CA raíz de Casa Monarca (EC P-256)${RESET}"
    openssl ecparam -name prime256v1 -genkey -noout -out "$CA_KEY" 2>/dev/null
    openssl req -new -x509 -key "$CA_KEY" -out "$CA_CERT" -days 1825 \
        -subj "/C=MX/ST=Monterrey/O=Casa Monarca/OU=Autoridad Certificadora/CN=Casa Monarca Root CA" \
        2>/dev/null
    FINGERPRINT=$(openssl x509 -fingerprint -sha256 -noout -in "$CA_CERT" | cut -d= -f2)
    echo -e "  ${GREEN}✓ CA generada${RESET}  fingerprint: ${FINGERPRINT}"
    echo ""
}

# ── Paso 2: Emitir certificado de colaborador ─────────────────────────────────
step_cert() {
    echo -e "${BOLD}[ Paso 2 ] Emitiendo certificado para 'mariel_alvarez' (RSA-2048)${RESET}"
    openssl genrsa -out "$SERVICE_KEY" 2048 2>/dev/null
    openssl req -new -key "$SERVICE_KEY" -out "$SERVICE_CSR" \
        -subj "/C=MX/ST=Monterrey/O=Casa Monarca/OU=Administracion/CN=mariel_alvarez" \
        2>/dev/null
    openssl x509 -req -in "$SERVICE_CSR" -CA "$CA_CERT" -CAkey "$CA_KEY" \
        -CAcreateserial -out "$SERVICE_CERT" -days 365 -sha256 2>/dev/null
    CERT_SERIAL=$(openssl x509 -serial -noout -in "$SERVICE_CERT" | cut -d= -f2)
    CERT_EXPIRY=$(openssl x509 -enddate -noout -in "$SERVICE_CERT" | cut -d= -f2)
    echo -e "  ${GREEN}✓ Certificado emitido${RESET}"
    echo "    Serie:    $CERT_SERIAL"
    echo "    Expira:   $CERT_EXPIRY"
    echo ""
}

# ── Paso 3: Firmar documento ──────────────────────────────────────────────────
step_sign() {
    echo -e "${BOLD}[ Paso 3 ] Creando y firmando documento${RESET}"
    cat > "$DOCUMENT" <<'EOF'
Documento de prueba — Casa Monarca PKI Demo
Fecha: 2026-06-10
Acción: Registro de migrante ID-001
Firmante: mariel_alvarez (Nivel 1 — Administrador)
EOF
    openssl dgst -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 \
        -sign "$SERVICE_KEY" -out "$SIGNATURE" "$DOCUMENT" 2>/dev/null
    DOC_HASH=$(openssl dgst -sha256 "$DOCUMENT" | awk '{print $2}')
    echo -e "  ${GREEN}✓ Documento firmado${RESET}"
    echo "    Contenido: $(wc -l < "$DOCUMENT") líneas"
    echo "    SHA-256:   $DOC_HASH"
    echo "    Firma:     $SIGNATURE ($(wc -c < "$SIGNATURE") bytes)"
    echo ""
}

# ── Paso 4: Verificar firma ───────────────────────────────────────────────────
step_verify() {
    echo -e "${BOLD}[ Paso 4 ] Verificando firma con la clave pública del certificado${RESET}"
    PUBKEY_TMP="pubkey_tmp.pem"
    openssl x509 -pubkey -noout -in "$SERVICE_CERT" > "$PUBKEY_TMP" 2>/dev/null

    if openssl dgst -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 \
        -verify "$PUBKEY_TMP" -signature "$SIGNATURE" "$DOCUMENT" &>/dev/null; then
        echo -e "  ${GREEN}${BOLD}✓ FIRMA VÁLIDA${RESET} — Integridad y autenticidad confirmadas"
    else
        echo -e "  ${RED}${BOLD}✗ FIRMA INVÁLIDA${RESET} — El documento puede haber sido modificado"
    fi
    rm -f "$PUBKEY_TMP"
    echo ""
}

# ── Paso 5: Verificar cadena de confianza ─────────────────────────────────────
step_chain() {
    echo -e "${BOLD}[ Paso 5 ] Verificando cadena de confianza (cert → CA)${RESET}"
    if openssl verify -CAfile "$CA_CERT" "$SERVICE_CERT" &>/dev/null; then
        SUBJECT=$(openssl x509 -subject -noout -in "$SERVICE_CERT" | sed 's/subject=//')
        ISSUER=$(openssl x509 -issuer -noout -in "$SERVICE_CERT" | sed 's/issuer=//')
        echo -e "  ${GREEN}✓ Certificado válido y confiable${RESET}"
        echo "    Sujeto:  $SUBJECT"
        echo "    Emisor:  $ISSUER"
    else
        echo -e "  ${RED}✗ Verificación de cadena fallida${RESET}"
    fi
    echo ""
}

# ── Resumen ───────────────────────────────────────────────────────────────────
summary() {
    echo -e "${BOLD}${GREEN}══════════════════════════════════════════════════${RESET}"
    echo -e "${BOLD}${GREEN}  Demo completado exitosamente                    ${RESET}"
    echo -e "${BOLD}${GREEN}══════════════════════════════════════════════════${RESET}"
    echo ""
    echo -e "  ${BOLD}Archivos generados:${RESET}"
    for f in "${GENERATED_FILES[@]}"; do
        [[ -f "$f" ]] && echo "    $f"
    done
    echo ""
    echo -e "  ${BOLD}Para ejecutar la aplicación web completa:${RESET}"
    echo "    cd CriptoReto"
    echo "    python manage.py runserver"
    echo ""
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
    check_deps
    header
    step_ca
    step_cert
    step_sign
    step_verify
    step_chain
    summary
    cleanup
}

main "$@"
