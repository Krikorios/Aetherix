# Aetherix Browser Extension (Phase 2)

Manifest V3 extension that enforces Aetherix Semantic DLP + GenAI Guardrails
policy directly in the browser. Pairs with the Rust agent (Phase 1) and the
Policy Engine v2 backend.

## Architecture

```
┌──────────────────────────┐    chrome.runtime.sendMessage
│  content.js (page world) │────────────────────────────────┐
│  ─ utils/intercept.js    │                                ▼
│  ─ utils/classify.js     │                  ┌────────────────────────────┐
│  ─ utils/toast.js        │                  │ background.js (service     │
│  paste/copy/upload/drop  │                  │ worker)                    │
└──────────────────────────┘                  │  ─ utils/policySync.js     │
                                              │  ─ utils/bridge.js         │
                                              │  decide() + evidence queue │
                                              └──────────────┬─────────────┘
                                                             │
                       Mode A: chrome.runtime.connectNative  │
                       Mode B: fetch http://127.0.0.1:8787   │
                                                             ▼
                                              ┌────────────────────────────┐
                                              │ Aetherix Rust agent        │
                                              │  GET /policy               │
                                              │  POST /dlp-event           │
                                              └──────────────┬─────────────┘
                                                             │ HMAC + agent_secret
                                                             ▼
                                              ┌────────────────────────────┐
                                              │ FastAPI control plane      │
                                              │  GET  /agent/policy        │
                                              │  POST /agent/dlp-evidence  │
                                              └────────────────────────────┘
```

The browser extension never talks to the FastAPI backend directly — all
authentication and evidence signing is delegated to the Rust agent, which
owns the enrolled `agent_id` + `agent_secret` and the HMAC chain.

## Files

| Path                      | Role                                                  |
| ------------------------- | ----------------------------------------------------- |
| `manifest.json`           | MV3 manifest (permissions, content scripts, etc.)     |
| `background.js`           | Service worker: policy sync, message bus, retry queue |
| `content.js`              | Content-script bootstrap (dynamic-imports ES modules) |
| `utils/intercept.js`      | Paste / copy / upload / drop interception             |
| `utils/classify.js`       | Local pre-classification + policy decision resolver   |
| `utils/destinations.js`   | Hostname → canonical GenAI slug                       |
| `utils/policySync.js`     | Effective-policy cache + offline fallback             |
| `utils/bridge.js`         | Native-messaging + localhost-HTTP bridge to agent     |
| `utils/hash.js`           | SHA-256 helper for evidence content hashing           |
| `utils/toast.js`          | Shadow-DOM toast UI                                   |
| `styles/toast.css`        | Toast styles (loaded inside shadow root)              |
| `popup.html` / `popup.js` | Toolbar popup (bridge status + manual resync)         |
| `options.html`            | Options page (status + covered destinations)          |

## Permissions

Minimal set: `storage`, `alarms`, `scripting`, `activeTab`. Host permissions
are restricted to the supported GenAI domains plus `http://127.0.0.1:8787/*`
for the HTTP fallback bridge.

Native messaging is opted in at runtime via `chrome.runtime.connectNative` —
no `nativeMessaging` permission is required when the host is registered for
this extension id.

## Bridge transports

The extension probes both transports at startup and caches the working one:

**Mode A — Native messaging** (preferred)

- Host id: `com.aetherix.browser_bridge`
- Wire protocol: JSON messages `{ requestId, op, payload }`
- Ops: `ping`, `get_policy`, `emit_evidence`

**Mode B — Localhost HTTP** (fallback)

- `GET  http://127.0.0.1:8787/health`
- `GET  http://127.0.0.1:8787/policy`   → `RuntimePolicy` (matches agent shape)
- `POST http://127.0.0.1:8787/dlp-event` → `204` on accept

The agent is responsible for binding strictly to `127.0.0.1`, validating the
content-type, and refusing CORS preflights from any origin other than the
known extension id.

## Evidence payload

Sent from the service worker to the agent for every paste / copy / upload
event that is not `allow`:

```json
{
  "action": "dlp.paste_blocked",
  "event_type": "paste",
  "destination": "claude.ai",
  "label_detected": "restricted",
  "signals": ["credit_card"],
  "content_hash": "sha256:...",
  "policy_action_field": "paste_sensitive",
  "decision": "block",
  "policy_version_hash": "v1:...",
  "source": "browser_extension",
  "extension_version": "0.1.0",
  "timestamp": "2026-05-23T12:34:56.000Z",
  "tab_url": "https://claude.ai/chat/..."
}
```

Raw paste / upload bodies **never** leave the browser. Only a SHA-256 hash
plus detector signals are emitted.

## Loading the extension

1. Run the Rust agent locally (Phase 1).
2. Visit `chrome://extensions`, enable Developer Mode.
3. Click **Load unpacked** and pick `apps/extension/`.
4. Navigate to <https://claude.ai> and try pasting a credit-card number to
   verify the toast + evidence flow.

## Tests

```
node --test apps/extension/test/unit.test.js
```

Unit tests cover the classifier and policy-decision resolver. Manual
E2E coverage on the four supported GenAI sites is required before each
release; a Playwright suite reusing `apps/console/playwright.config.ts` is
planned for Phase 2B.

## Roadmap

- **Phase 2A (this drop)** — MV3 scaffold, content-script interception,
  native + HTTP bridge, block/review enforcement, evidence queue, popup.
- **Phase 2B** — Options page to add custom GenAI destinations from the
  tenant policy; inline redaction (`redact` action) for paste flows;
  Playwright end-to-end suite; better toast UI with user override on
  `review`.
