#!/usr/bin/env bash
#
# macos-package-and-notarize.sh
#
# Build a signed + notarized macOS PKG containing the Aetherix agent
# universal binary. Expected to run on a macOS GitHub runner that has
# already produced `aetherix-agent` (x86_64) and `aetherix-agent-arm64`
# (aarch64) under agent/dist/macos_pkg/.
#
# Required environment (all secrets sourced from GitHub Environments):
#   APPLE_DEVELOPER_ID_APPLICATION   — Developer ID Application cert, base64 .p12
#   APPLE_DEVELOPER_ID_INSTALLER     — Developer ID Installer cert,   base64 .p12
#   APPLE_CERT_PASSWORD              — password for both .p12 bundles
#   APPLE_KEYCHAIN_PASSWORD          — password for the throwaway login keychain
#   APPLE_TEAM_ID                    — 10-char Team ID (e.g. ABCDE12345)
#   APPLE_NOTARY_PROFILE_ID          — App-Specific password / API key issuer
#   APPLE_NOTARY_APPLE_ID            — Apple ID used for notarytool
#   APPLE_NOTARY_PASSWORD            — App-Specific password for notarytool
#   AETHERIX_VERSION                 — e.g. 0.4.1
#
# The script is intentionally fail-fast: any non-zero exit aborts the
# whole release. Set AETHERIX_INSTALLER_DRY_RUN=1 to skip the actual
# notarization upload (used by integration tests).

set -euo pipefail

require_env() {
  for var in "$@"; do
    if [ -z "${!var:-}" ]; then
      echo "FATAL: missing required env var: $var" >&2
      exit 2
    fi
  done
}

DRY_RUN="${AETHERIX_INSTALLER_DRY_RUN:-0}"
require_env AETHERIX_VERSION APPLE_TEAM_ID

if [ "$DRY_RUN" != "1" ]; then
  require_env APPLE_DEVELOPER_ID_APPLICATION APPLE_DEVELOPER_ID_INSTALLER \
              APPLE_CERT_PASSWORD APPLE_KEYCHAIN_PASSWORD \
              APPLE_NOTARY_APPLE_ID APPLE_NOTARY_PASSWORD
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DIST_DIR="$REPO_ROOT/agent/dist"
PKG_STAGING="$DIST_DIR/macos_pkg/staging"
PKG_OUTPUT="$DIST_DIR/macos_pkg/aetherix-agent-${AETHERIX_VERSION}.pkg"

X86_BIN="$DIST_DIR/macos_pkg/aetherix-agent"
ARM_BIN="$DIST_DIR/macos_pkg/aetherix-agent-arm64"

if [ ! -f "$X86_BIN" ] || [ ! -f "$ARM_BIN" ]; then
  echo "FATAL: missing per-arch binaries under $DIST_DIR/macos_pkg/" >&2
  ls -l "$DIST_DIR/macos_pkg/" || true
  exit 2
fi

echo "==> Creating universal binary"
mkdir -p "$PKG_STAGING/usr/local/bin"
lipo -create -output "$PKG_STAGING/usr/local/bin/aetherix-agent" "$X86_BIN" "$ARM_BIN"
chmod +x "$PKG_STAGING/usr/local/bin/aetherix-agent"

if [ "$DRY_RUN" = "1" ]; then
  echo "==> DRY_RUN: skipping keychain / codesign / notarization"
  pkgbuild --root "$PKG_STAGING" --identifier com.aetherix.agent \
           --version "$AETHERIX_VERSION" --install-location / \
           "$PKG_OUTPUT.unsigned"
  mv "$PKG_OUTPUT.unsigned" "$PKG_OUTPUT"
  echo "PKG (unsigned, dry-run): $PKG_OUTPUT"
  exit 0
fi

KEYCHAIN="aetherix-build.keychain-db"
echo "==> Provisioning ephemeral keychain"
security create-keychain -p "$APPLE_KEYCHAIN_PASSWORD" "$KEYCHAIN"
security set-keychain-settings -lut 7200 "$KEYCHAIN"
security unlock-keychain -p "$APPLE_KEYCHAIN_PASSWORD" "$KEYCHAIN"
security list-keychains -d user -s "$KEYCHAIN" "$(security list-keychains -d user | tr -d ' "')"

APP_P12="$(mktemp -t aetx-app.p12.XXXXXX)"
INSTALLER_P12="$(mktemp -t aetx-inst.p12.XXXXXX)"
trap 'rm -f "$APP_P12" "$INSTALLER_P12"; security delete-keychain "$KEYCHAIN" 2>/dev/null || true' EXIT

echo "$APPLE_DEVELOPER_ID_APPLICATION" | base64 --decode > "$APP_P12"
echo "$APPLE_DEVELOPER_ID_INSTALLER"   | base64 --decode > "$INSTALLER_P12"

security import "$APP_P12"       -k "$KEYCHAIN" -P "$APPLE_CERT_PASSWORD" -T /usr/bin/codesign -T /usr/bin/productsign
security import "$INSTALLER_P12" -k "$KEYCHAIN" -P "$APPLE_CERT_PASSWORD" -T /usr/bin/codesign -T /usr/bin/productsign
security set-key-partition-list -S apple-tool:,apple:,codesign:,productsign: \
                                -s -k "$APPLE_KEYCHAIN_PASSWORD" "$KEYCHAIN"

echo "==> Hardened-runtime codesign of agent binary"
codesign --force --options runtime --timestamp \
         --sign "Developer ID Application: ${APPLE_TEAM_ID}" \
         "$PKG_STAGING/usr/local/bin/aetherix-agent"
codesign --verify --strict --verbose=2 "$PKG_STAGING/usr/local/bin/aetherix-agent"

echo "==> Building component PKG"
pkgbuild --root "$PKG_STAGING" --identifier com.aetherix.agent \
         --version "$AETHERIX_VERSION" --install-location / \
         "$PKG_OUTPUT.unsigned"

echo "==> Signing PKG with Developer ID Installer"
productsign --sign "Developer ID Installer: ${APPLE_TEAM_ID}" \
            "$PKG_OUTPUT.unsigned" "$PKG_OUTPUT"
rm "$PKG_OUTPUT.unsigned"

echo "==> Submitting to Apple notary service"
xcrun notarytool submit "$PKG_OUTPUT" \
      --apple-id "$APPLE_NOTARY_APPLE_ID" \
      --team-id "$APPLE_TEAM_ID" \
      --password "$APPLE_NOTARY_PASSWORD" \
      --wait

echo "==> Stapling notarization ticket"
xcrun stapler staple "$PKG_OUTPUT"
xcrun stapler validate "$PKG_OUTPUT"

shasum -a 256 "$PKG_OUTPUT" | tee "$PKG_OUTPUT.sha256"
echo "Signed + notarized PKG ready: $PKG_OUTPUT"
