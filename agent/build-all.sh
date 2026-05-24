#!/usr/bin/env bash
set -uo pipefail

# ─── Cross-compilation pipeline ──────────────────────────────────────────
# Builds the Aetherix agent for every supported platform and copies the
# resulting binary into agent/dist/<platform>/.
#
# Prerequisites:
#   brew install FiloSottile/musl-cross/musl-cross      # Linux musl
#   brew install mingw-w64                               # Windows (GNU)
#   cargo install cross --git https://github.com/cross-rs/cross
#   rustup target add aarch64-apple-darwin
#   rustup target add x86_64-unknown-linux-gnu
#   rustup target add x86_64-pc-windows-gnu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST_DIR="$SCRIPT_DIR/dist"
mkdir -p "$DIST_DIR"

# Map:  target-triple → platform-key → binary-name
# Multiple targets can map to the same platform (e.g. macOS Intel + ARM).
declare -A TARGETS
TARGETS[x86_64-apple-darwin]="macos_pkg:aetherix-agent"
TARGETS[aarch64-apple-darwin]="macos_pkg:aetherix-agent"
TARGETS[x86_64-unknown-linux-gnu]="linux_deb:aetherix-agent"
TARGETS[x86_64-unknown-linux-musl]="linux_rpm:aetherix-agent"
TARGETS[x86_64-pc-windows-gnu]="windows_exe:aetherix-agent.exe"

BUILD_OK=0
BUILD_FAIL=0

for TARGET in "${!TARGETS[@]}"; do
    IFS=: read -r PLATFORM BINARY <<< "${TARGETS[$TARGET]}"

    echo ""
    echo "═══ Building $TARGET → $PLATFORM ═══"

    # Decide which builder to use.
    # The host target (x86_64-apple-darwin) and aarch64-apple-darwin can
    # use plain cargo. Everything else delegates to `cross` (Docker).
    BUILDER="cargo"
    if [ "$TARGET" != "x86_64-apple-darwin" ] && [ "$TARGET" != "aarch64-apple-darwin" ]; then
        if command -v cross &>/dev/null; then
            BUILDER="cross"
        else
            echo "SKIP  $TARGET — cross not installed. Install with:"
            echo "      cargo install cross --git https://github.com/cross-rs/cross"
            BUILD_FAIL=$((BUILD_FAIL + 1))
            continue
        fi
    fi

    echo "  builder: $BUILDER"
    if ! (cd "$SCRIPT_DIR" && $BUILDER build --release --target "$TARGET"); then
        echo "FAIL  build command failed for $TARGET"
        BUILD_FAIL=$((BUILD_FAIL + 1))
        continue
    fi

    SRC="$SCRIPT_DIR/target/$TARGET/release/$BINARY"
    DEST="$DIST_DIR/$PLATFORM/"
    mkdir -p "$DEST"

    if [ -f "$SRC" ]; then
        # Differentiate arch within the platform directory
        case "$TARGET" in
            aarch64-apple-darwin)  DEST_BINARY="aetherix-agent-arm64" ;;
            x86_64-apple-darwin)   DEST_BINARY="aetherix-agent" ;;
            *)                     DEST_BINARY="$BINARY" ;;
        esac
        cp "$SRC" "$DEST/$DEST_BINARY"
        echo "OK    $(ls -lh "$DEST/$DEST_BINARY" | awk '{print $5}')  $DEST/$DEST_BINARY"
        BUILD_OK=$((BUILD_OK + 1))
    else
        echo "FAIL  binary not found at $SRC"
        BUILD_FAIL=$((BUILD_FAIL + 1))
    fi
done

echo ""
echo "══════════════════════════════════════════════════════════════════════"
echo "Done — $BUILD_OK succeeded, $BUILD_FAIL failed"
echo "Distributables in: $DIST_DIR"
ls -1 "$DIST_DIR"

exit $BUILD_FAIL
