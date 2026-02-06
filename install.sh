#!/usr/bin/env bash
set -euo pipefail

REPO="rvielma/argos"
INSTALL_DIR="/usr/local/bin"

# Detect OS and architecture
OS="$(uname -s)"
ARCH="$(uname -m)"

case "${OS}" in
    Linux)  TARGET_OS="x86_64-unknown-linux-gnu" ;;
    Darwin)
        case "${ARCH}" in
            x86_64)  TARGET_OS="x86_64-apple-darwin" ;;
            arm64)   TARGET_OS="aarch64-apple-darwin" ;;
            *)       echo "Error: arquitectura no soportada: ${ARCH}"; exit 1 ;;
        esac
        ;;
    *)  echo "Error: OS no soportado: ${OS}"; exit 1 ;;
esac

echo "Detectado: ${OS} ${ARCH} -> ${TARGET_OS}"

# Get latest release tag
LATEST=$(curl -sSf "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')

if [ -z "${LATEST}" ]; then
    echo "Error: no se pudo obtener la última versión"
    exit 1
fi

echo "Versión: ${LATEST}"

ARCHIVE="argos-${LATEST}-${TARGET_OS}.tar.gz"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${LATEST}/${ARCHIVE}"
CHECKSUM_URL="${DOWNLOAD_URL}.sha256"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "${TMPDIR}"' EXIT

echo "Descargando ${ARCHIVE}..."
curl -sSfL "${DOWNLOAD_URL}" -o "${TMPDIR}/${ARCHIVE}"
curl -sSfL "${CHECKSUM_URL}" -o "${TMPDIR}/${ARCHIVE}.sha256"

# Verify checksum
echo "Verificando checksum..."
cd "${TMPDIR}"
if command -v sha256sum &> /dev/null; then
    sha256sum -c "${ARCHIVE}.sha256"
elif command -v shasum &> /dev/null; then
    shasum -a 256 -c "${ARCHIVE}.sha256"
else
    echo "Advertencia: no se encontró sha256sum ni shasum, saltando verificación"
fi

# Extract and install
echo "Instalando en ${INSTALL_DIR}..."
tar -xzf "${ARCHIVE}"

if [ -w "${INSTALL_DIR}" ]; then
    mv argos "${INSTALL_DIR}/argos"
else
    sudo mv argos "${INSTALL_DIR}/argos"
fi

chmod +x "${INSTALL_DIR}/argos"

echo "argos ${LATEST} instalado en ${INSTALL_DIR}/argos"
argos --version 2>/dev/null || true
