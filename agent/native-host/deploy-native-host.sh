#!/usr/bin/env bash
# Deploy the Aetherix Native Messaging host manifest to the correct
# platform-specific location so Chrome can discover it.
#
# Usage:
#   ./deploy-native-host.sh [extension-id]
#
# If extension-id is omitted the manifest will accept any chrome-extension:// origin.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST_TEMPLATE="${SCRIPT_DIR}/com.aetherix.browser_bridge.json"
AGENT_BINARY="${SCRIPT_DIR}/../target/release/aetherix-agent"
EXTENSION_ID="${1:-*}"

if [ ! -f "$AGENT_BINARY" ]; then
    # Try debug build
    AGENT_BINARY="${SCRIPT_DIR}/../target/debug/aetherix-agent"
fi

if [ ! -f "$AGENT_BINARY" ]; then
    echo "Error: aetherix-agent binary not found. Build it first with 'cargo build --release'"
    exit 1
fi

AGENT_BINARY="$(cd "$(dirname "$AGENT_BINARY")" && pwd)/$(basename "$AGENT_BINARY")"

case "$(uname -s)" in
    Darwin)
        CHROME_HOST_DIR="$HOME/Library/Application Support/Google/Chrome/NativeMessagingHosts"
        CHROMIUM_HOST_DIR="$HOME/Library/Application Support/Chromium/NativeMessagingHosts"
        BRAVE_HOST_DIR="$HOME/Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts"
        EDGE_HOST_DIR="$HOME/Library/Application Support/Microsoft Edge/NativeMessagingHosts"
        ;;
    Linux)
        CHROME_HOST_DIR="$HOME/.config/google-chrome/NativeMessagingHosts"
        CHROMIUM_HOST_DIR="$HOME/.config/chromium/NativeMessagingHosts"
        BRAVE_HOST_DIR="$HOME/.config/BraveSoftware/Brave-Browser/NativeMessagingHosts"
        EDGE_HOST_DIR="$HOME/.config/microsoft-edge/NativeMessagingHosts"
        SYSTEM_HOST_DIR="/etc/opt/chrome/native-messaging-hosts"
        ;;
    *)
        echo "Unsupported platform: $(uname -s)"
        exit 1
        ;;
esac

# Render the manifest with the correct binary path and extension ID
MANIFEST=$(sed -e "s|__AETHERIX_AGENT_BINARY__|${AGENT_BINARY}|g" \
               -e "s|__AETHERIX_EXTENSION_ID__|${EXTENSION_ID}|g" \
               "$MANIFEST_TEMPLATE")

deploy() {
    local dir="$1"
    mkdir -p "$dir"
    echo "$MANIFEST" > "$dir/com.aetherix.browser_bridge.json"
    echo "  deployed to $dir"
}

echo "Deploying Aetherix Native Messaging host manifest..."
echo "  Agent binary: $AGENT_BINARY"
echo "  Extension ID: ${EXTENSION_ID:-*}"

# Deploy to each browser's host directory
for dir in "${CHROME_HOST_DIR:-}" "${CHROMIUM_HOST_DIR:-}" "${BRAVE_HOST_DIR:-}" "${EDGE_HOST_DIR:-}"; do
    [ -n "$dir" ] && deploy "$dir"
done

# Also try system-wide on Linux
if [ "$(uname -s)" = "Linux" ] && [ -d "${SYSTEM_HOST_DIR:-}" ]; then
    deploy "$SYSTEM_HOST_DIR"
fi

echo "Done. Restart the browser to pick up the new native messaging host."
