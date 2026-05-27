#!/usr/bin/env bash
#
# linux-package-and-sign.sh
#
# Build a Debian package for the Aetherix agent and GPG-sign it for apt
# repository distribution. Designed to run on an ubuntu-22.04 GitHub
# runner that has already produced
# agent/dist/linux_deb/aetherix-agent (x86_64 ELF).
#
# Required environment:
#   AETHERIX_VERSION                 — e.g. 0.4.1
#   AETHERIX_GPG_PRIVATE_KEY         — base64-encoded ASCII-armored private key
#   AETHERIX_GPG_KEY_ID              — long key id used by debsigs / dpkg-sig
#   AETHERIX_GPG_PASSPHRASE          — passphrase for the key
#
# AETHERIX_INSTALLER_DRY_RUN=1 skips GPG signing (build still produces
# the unsigned .deb).

set -euo pipefail

require_env() {
  for v in "$@"; do
    if [ -z "${!v:-}" ]; then
      echo "FATAL: missing env var: $v" >&2
      exit 2
    fi
  done
}

DRY_RUN="${AETHERIX_INSTALLER_DRY_RUN:-0}"
require_env AETHERIX_VERSION
if [ "$DRY_RUN" != "1" ]; then
  require_env AETHERIX_GPG_PRIVATE_KEY AETHERIX_GPG_KEY_ID AETHERIX_GPG_PASSPHRASE
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SRC_BIN="$REPO_ROOT/agent/dist/linux_deb/aetherix-agent"
OUT_DIR="$REPO_ROOT/agent/dist/linux_deb"
WORK="$(mktemp -d -t aetherix-deb.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

if [ ! -f "$SRC_BIN" ]; then
  echo "FATAL: $SRC_BIN missing — run cargo build first." >&2
  exit 2
fi

echo "==> Staging package tree under $WORK"
PKG_NAME="aetherix-agent_${AETHERIX_VERSION}_amd64"
PKG_DIR="$WORK/$PKG_NAME"
mkdir -p "$PKG_DIR/DEBIAN" \
         "$PKG_DIR/usr/local/bin" \
         "$PKG_DIR/lib/systemd/system"

install -m 0755 "$SRC_BIN" "$PKG_DIR/usr/local/bin/aetherix-agent"

cat >"$PKG_DIR/DEBIAN/control" <<EOF
Package: aetherix-agent
Version: $AETHERIX_VERSION
Section: admin
Priority: optional
Architecture: amd64
Maintainer: Aetherix Security <security@aetherix.io>
Description: Aetherix DLP and EDR enforcement agent.
 Deterministic-first endpoint agent that enforces tenant DLP and EDR
 policies and produces hash-chained evidence locally.
EOF

cat >"$PKG_DIR/lib/systemd/system/aetherix-agent.service" <<'EOF'
[Unit]
Description=Aetherix DLP and EDR Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/aetherix-agent
Restart=on-failure
RestartSec=5
User=root
Group=root
ProtectSystem=strict
ProtectHome=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

cat >"$PKG_DIR/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if [ -x /bin/systemctl ] || [ -x /usr/bin/systemctl ]; then
  systemctl daemon-reload || true
  systemctl enable aetherix-agent.service || true
  systemctl start  aetherix-agent.service || true
fi
exit 0
EOF
chmod 0755 "$PKG_DIR/DEBIAN/postinst"

cat >"$PKG_DIR/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
if [ -x /bin/systemctl ] || [ -x /usr/bin/systemctl ]; then
  systemctl stop    aetherix-agent.service || true
  systemctl disable aetherix-agent.service || true
fi
exit 0
EOF
chmod 0755 "$PKG_DIR/DEBIAN/prerm"

echo "==> Running dpkg-deb"
DEB_PATH="$OUT_DIR/${PKG_NAME}.deb"
dpkg-deb --build --root-owner-group "$PKG_DIR" "$DEB_PATH"

if [ "$DRY_RUN" = "1" ]; then
  echo "DRY_RUN: skipping GPG signing"
  sha256sum "$DEB_PATH" | tee "${DEB_PATH}.sha256"
  echo "Unsigned .deb: $DEB_PATH"
  exit 0
fi

echo "==> Importing GPG signing key"
GNUPGHOME="$(mktemp -d -t aetherix-gpg.XXXXXX)"
export GNUPGHOME
chmod 700 "$GNUPGHOME"
echo "$AETHERIX_GPG_PRIVATE_KEY" | base64 --decode | gpg --batch --import

echo "==> Signing .deb with dpkg-sig"
echo "$AETHERIX_GPG_PASSPHRASE" | dpkg-sig --gpg-options "--batch --pinentry-mode loopback --passphrase-fd 0" \
    -k "$AETHERIX_GPG_KEY_ID" --sign builder "$DEB_PATH"

echo "==> Verifying signature"
dpkg-sig --verify "$DEB_PATH"

sha256sum "$DEB_PATH" | tee "${DEB_PATH}.sha256"

rm -rf "$GNUPGHOME"
echo "Signed .deb: $DEB_PATH"
