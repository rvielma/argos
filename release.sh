#!/usr/bin/env bash
set -euo pipefail

REPO="rvielma/argos"
VERSION="${1:-}"

if [ -z "${VERSION}" ]; then
    echo "Uso: ./release.sh <version>"
    echo "Ejemplo: ./release.sh 0.1.0"
    exit 1
fi

TAG="v${VERSION}"

# Detectar arquitectura local
ARCH="$(uname -m)"
case "${ARCH}" in
    x86_64)  TARGET="x86_64-apple-darwin" ;;
    arm64)   TARGET="aarch64-apple-darwin" ;;
    *)       echo "Error: arquitectura no soportada: ${ARCH}"; exit 1 ;;
esac

ARCHIVE="argos-${TAG}-${TARGET}.tar.gz"

echo "==> Compilando argos ${TAG} para ${TARGET}..."
cargo build --release

echo "==> Creando tarball ${ARCHIVE}..."
tar -czf "${ARCHIVE}" -C target/release argos

echo "==> Generando SHA256..."
shasum -a 256 "${ARCHIVE}" > "${ARCHIVE}.sha256"
cat "${ARCHIVE}.sha256"

echo "==> Creando release ${TAG}..."
if gh release view "${TAG}" &>/dev/null; then
    echo "    Release ${TAG} ya existe, subiendo assets..."
    gh release upload "${TAG}" "${ARCHIVE}" "${ARCHIVE}.sha256" --clobber
else
    gh release create "${TAG}" \
        --title "Argos ${TAG}" \
        --generate-notes \
        "${ARCHIVE}" "${ARCHIVE}.sha256"
fi

# Actualizar sha256 en Homebrew formula
SHA256=$(awk '{print $1}' "${ARCHIVE}.sha256")
echo "==> Actualizando Homebrew formula con sha256: ${SHA256}..."

FORMULA="Formula/argos.rb"
if [ -f "${FORMULA}" ]; then
    # Actualizar version
    sed -i '' "s/version \".*\"/version \"${VERSION}\"/" "${FORMULA}"

    # Insertar/actualizar sha256 según arquitectura
    case "${TARGET}" in
        aarch64-apple-darwin)
            sed -i '' "/aarch64-apple-darwin/{n;s|.*# sha256.*|      sha256 \"${SHA256}\"|;s|.*sha256 \".*\"|      sha256 \"${SHA256}\"|;}" "${FORMULA}"
            ;;
        x86_64-apple-darwin)
            sed -i '' "/x86_64-apple-darwin/{n;s|.*# sha256.*|      sha256 \"${SHA256}\"|;s|.*sha256 \".*\"|      sha256 \"${SHA256}\"|;}" "${FORMULA}"
            ;;
    esac
    echo "    Formula actualizada"
fi

# Limpiar tarball
rm -f "${ARCHIVE}" "${ARCHIVE}.sha256"

# Commit formula en repo principal
echo "==> Commiteando formula en repo principal..."
git add Formula/argos.rb
git commit -m "chore: actualizar formula ${TAG}" || true
git push origin master

# Publicar formula en homebrew-argos
echo "==> Publicando formula en homebrew-argos..."
TMPDIR="$(mktemp -d)"
git clone git@github_home:rvielma/homebrew-argos.git "${TMPDIR}/homebrew-argos"
cp Formula/argos.rb "${TMPDIR}/homebrew-argos/Formula/argos.rb"
cd "${TMPDIR}/homebrew-argos"
git add Formula/argos.rb
git commit -m "chore: actualizar formula ${TAG}"
git push origin main
cd -
rm -rf "${TMPDIR}"

echo ""
echo "==> Release ${TAG} completo: https://github.com/${REPO}/releases/tag/${TAG}"
echo "==> brew install rvielma/argos/argos"
