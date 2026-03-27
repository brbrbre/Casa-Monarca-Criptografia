#!/bin/bash
# =============================================================================
# Experimento 1 - "Hola mundo" de certificados con step-ca
# Casa Monarca - Criptografia
# =============================================================================
# Este script levanta una CA interna, emite un certificado, lo verifica
# y firma un archivo simple para demostrar el flujo basico de PKI.
# =============================================================================

set -e  # Detener si cualquier comando falla

# Colores para output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # Sin color

echo -e "${BLUE}"
echo "============================================="
echo "  Experimento 1 - step-ca: Hola Mundo PKI"
echo "============================================="
echo -e "${NC}"

# -----------------------------------------------------------------------------
# PASO 0: Verificar dependencias
# -----------------------------------------------------------------------------
echo -e "${YELLOW}[0/5] Verificando dependencias...${NC}"

if ! command -v step &> /dev/null; then
    echo -e "${RED}ERROR: 'step' no esta instalado. Corre: brew install step${NC}"
    exit 1
fi

if ! command -v step-ca &> /dev/null; then
    echo -e "${RED}ERROR: 'step-ca' no esta instalado. Corre: brew install step-ca${NC}"
    exit 1
fi

echo -e "${GREEN}OK - Dependencias listas${NC}"
echo ""

# -----------------------------------------------------------------------------
# PASO 1: Inicializar la CA (solo si no existe ya)
# -----------------------------------------------------------------------------
echo -e "${YELLOW}[1/5] Inicializando la CA interna de Casa Monarca...${NC}"

if [ -f "$HOME/.step/config/ca.json" ]; then
    echo "AVISO: Ya existe una configuracion de step-ca en ~/.step"
    echo "       Si quieres empezar desde cero: rm -rf ~/.step"
    echo "       Continuando con la configuracion existente..."
else
    step ca init \
        --name "Casa-Monarca-CA" \
        --dns "localhost" \
        --address "127.0.0.1:8443" \
        --provisioner "admin@casamonarca.local" \
        --password-file <(echo "password-experimento-123")

    echo -e "${GREEN}OK - CA inicializada correctamente${NC}"
fi
echo ""

# -----------------------------------------------------------------------------
# PASO 2: Levantar la CA en segundo plano
# -----------------------------------------------------------------------------
echo -e "${YELLOW}[2/5] Levantando la CA en https://127.0.0.1:8443 ...${NC}"

# Matar cualquier instancia previa de step-ca
pkill -f "step-ca" 2>/dev/null || true
sleep 1

# Levantar step-ca en segundo plano
echo "password-experimento-123" | step-ca ~/.step/config/ca.json --password-file /dev/stdin &
CA_PID=$!
echo "   PID de step-ca: $CA_PID"

# Esperar a que levante
sleep 3

# Verificar que este corriendo
if ! kill -0 $CA_PID 2>/dev/null; then
    echo -e "${RED}ERROR: La CA no pudo iniciar. Revisa el puerto 8443.${NC}"
    exit 1
fi

echo -e "${GREEN}OK - CA corriendo (PID: $CA_PID)${NC}"
echo ""

# -----------------------------------------------------------------------------
# PASO 3: Emitir un certificado para un servicio
# -----------------------------------------------------------------------------
echo -e "${YELLOW}[3/5] Emitiendo certificado para 'servicio-documentos'...${NC}"

step ca certificate "servicio-documentos" servicio.crt servicio.key \
    --ca-url https://127.0.0.1:8443 \
    --root ~/.step/certs/root_ca.crt \
    --provisioner "admin@casamonarca.local" \
    --provisioner-password-file <(echo "password-experimento-123") \
    --not-after 24h

echo ""
echo "Contenido del certificado emitido:"
echo "--------------------------------------"
step certificate inspect servicio.crt | grep -E "(Subject|Issuer|Not Before|Not After|Serial)"
echo ""
echo -e "${GREEN}OK - Certificado emitido: servicio.crt${NC}"
echo ""

# -----------------------------------------------------------------------------
# PASO 4: Verificar el certificado contra la CA
# -----------------------------------------------------------------------------
echo -e "${YELLOW}[4/5] Verificando el certificado contra nuestra CA...${NC}"

step certificate verify servicio.crt \
    --roots ~/.step/certs/root_ca.crt

echo -e "${GREEN}OK - Certificado valido, la CA lo reconoce${NC}"
echo ""

# -----------------------------------------------------------------------------
# PASO 5: Firmar y verificar un archivo con la llave del certificado
# -----------------------------------------------------------------------------
echo -e "${YELLOW}[5/5] Firmando un documento con la llave privada del certificado...${NC}"

# Crear documento de prueba
echo "Documento oficial de Casa Monarca - $(date)" > documento.txt
echo "Este archivo fue firmado digitalmente para probar el flujo PKI." >> documento.txt

# Firmar con OpenSSL usando la llave privada
openssl dgst -sha256 -sign servicio.key -out firma.bin documento.txt
echo "Firma generada: firma.bin"

# Verificar la firma con la llave publica del certificado
echo ""
echo "Verificando la firma..."
openssl dgst -sha256 \
    -verify <(openssl x509 -in servicio.crt -pubkey -noout) \
    -signature firma.bin \
    documento.txt

echo ""

# -----------------------------------------------------------------------------
# RESUMEN FINAL
# -----------------------------------------------------------------------------
echo -e "${BLUE}"
echo "============================================="
echo "  Experimento completado exitosamente"
echo "============================================="
echo -e "${NC}"
echo "Archivos generados (NO subir al repo):"
echo "  servicio.crt  - certificado emitido por Casa-Monarca-CA"
echo "  servicio.key  - llave privada (mantener segura)"
echo "  documento.txt - archivo firmado"
echo "  firma.bin     - firma digital del documento"
echo ""
echo "La CA sigue corriendo en segundo plano (PID: $CA_PID)"
echo "Para detenerla: kill $CA_PID"
echo ""
echo "Lo que aprendimos:"
echo "  1. Una CA interna puede emitir certificados X.509 para servicios y usuarios"
echo "  2. Confiar en una CA significa aceptar como valido todo lo que ella firmo"
echo "  3. La llave privada firma; el certificado (llave publica) verifica"
echo "  4. Esta es la base de HTTPS, firma de correos y firma de documentos PDF"
