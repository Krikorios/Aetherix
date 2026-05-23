# Agent-Side Semantic DLP + GenAI Guardrails Enforcement

This document describes Phase 1 on-device enforcement added to the Rust agent.

## Runtime Architecture

- Agent polls effective policy from `GET /agent/policy?endpoint_id=<agent_id>&token=<agent_secret>`.
- Agent caches the latest successful policy at `~/.aetherix/effective-policy.json` (last-known-good fallback).
- Agent monitors local DLP event sources:
  - Clipboard changes (endpoint source)
  - Local NDJSON queue file `~/.aetherix/dlp-events.ndjson` (browser extension or external producer)
- Agent evaluates events against `semantic_dlp` + `genai_guardrails` modules.
- Agent emits enforcement evidence to `POST /agent/dlp-evidence` with agent token auth.

## Supported Policy Fields

The Rust agent parser supports these policy fields under `resolved_policy.modules`:

- `semantic_dlp.enabled`
- `semantic_dlp.sensitivity_labels`
- `semantic_dlp.genai_destinations`
- `semantic_dlp.actions.paste_sensitive`
- `semantic_dlp.actions.upload_restricted`
- `semantic_dlp.actions.copy_to_genai`
- `semantic_dlp.detectors.presidio`
- `semantic_dlp.detectors.llm_semantic`
- `semantic_dlp.detectors.custom_classifiers`
- `genai_guardrails.enabled`
- `genai_guardrails.destinations`
- `genai_guardrails.browser_enforcement`
- `genai_guardrails.endpoint_enforcement`
- `genai_guardrails.actions.*`

## Action Semantics

- `allow`: no enforcement record unless explicitly configured upstream.
- `review`: action allowed but evidence is emitted with review context.
- `block`: local deny signal + evidence emission.
- `redact`: reserved for Phase 2 redaction pipeline.

## Evidence Endpoint

`POST /agent/dlp-evidence?endpoint_id=<agent_id>&token=<agent_secret>`

Payload fields:

- `action_type`
- `decision`
- `destination`
- `label_detected`
- `content_hash`
- `policy_version`
- `endpoint_id`
- `event_type`
- `policy_action_field`
- `process_name`

On success, backend writes an `evidence_events` row and returns `EvidenceEvent`.

## Agent Environment Flags

- `AETHERIX_ENABLE_DLP_ENFORCEMENT=1` enables DLP runtime loop.
- `AETHERIX_DLP_RUN_SECONDS=<n>` loop duration (`0` means continuous service mode).
- `AETHERIX_DLP_POLL_INTERVAL_SECONDS=<n>` event poll interval.
- `AETHERIX_POLICY_REFRESH_SECONDS=<n>` effective policy refresh interval.
- `AETHERIX_EFFECTIVE_POLICY_PATH=<path>` override cache location.
- `AETHERIX_DLP_EVENT_QUEUE=<path>` override local queue path.

## Browser Extension Integration (Phase 2 Hook)

The queue file accepts line-delimited JSON matching the agent event schema:

```json
{"event_type":"paste","source":"browser_extension","content":"...","destination":"https://claude.ai","process_name":"chrome"}
```

This enables extension-originated destination-aware decisions immediately, before native messaging/localhost API transport is added.

## Local Browser Bridge (Phase 2A)

The agent exposes a small loopback-only HTTP server (`tiny_http`, sync) so the
Aetherix browser extension can fetch the effective policy and submit DLP
evidence without holding any agent credentials. The bridge runs in a single
background thread named `aetherix-bridge` and shares the live policy with the
DLP enforcement loop via `Arc<RwLock<Option<RuntimePolicy>>>`, so policy
refreshes are reflected to the extension immediately.

### Endpoints (bound to `127.0.0.1` only)

| Method | Path          | Purpose |
|--------|---------------|---------|
| GET    | `/health`     | Returns `{ok, agent_id, policy_version_hash, has_policy}`. |
| GET    | `/policy`     | Returns the current `RuntimePolicy` JSON (same shape served at `/agent/policy`). |
| POST   | `/dlp-event`  | Accepts a browser evidence payload and forwards it to `POST /agent/dlp-evidence` with the enrolled `endpoint_id` and `token`. |

`POST /dlp-event` request body (`event_type` is required and must be non-empty; other fields are optional):

```json
{
  "action": "dlp.paste_block",
  "event_type": "paste",
  "destination": "claude",
  "label_detected": "restricted",
  "content_hash": "sha256:<hex>",
  "policy_action_field": "paste_sensitive",
  "decision": "block",
  "process_name": "Chrome"
}
```

Responses:

- `202 {ok:true, forwarded:true}` — relayed to the control plane successfully.
- `202 {ok:true, forwarded:false, queued:true}` — control plane unreachable or returned 5xx; payload appended to the on-disk DLP queue as `{"kind":"browser_evidence", "payload":..., "enqueued_at":...}` for retry.
- `4xx {ok:false, queued:false, backend_status:<n>}` — control plane rejected the payload as invalid; no queueing.
- `400 {ok:false, error:"event_type is required"}` — browser evidence omitted the required event type.

### Security

- Bind is hard-coded to `127.0.0.1`. Every accepted connection's peer IP is re-validated to be in the loopback range; any non-loopback peer gets `403 forbidden` and the connection closes.
- A per-IP token bucket (60 burst / 30 rps sustained) protects against runaway callers; over-limit requests get `429`.
- `Origin` is validated against the allow-list (`AETHERIX_LOCAL_BRIDGE_ORIGIN`). When the allow-list is empty, any `chrome-extension://*` or `moz-extension://*` origin is accepted; any other supplied origin is rejected with `403` and no `Access-Control-Allow-*` headers.
- `POST` body size is capped at 256 KiB. Larger bodies are rejected before JSON parsing.
- The agent secret never crosses the bridge boundary — the extension only talks to the loopback bridge and the agent re-signs the outbound call to the FastAPI control plane.

### Environment flags

- `AETHERIX_ENABLE_LOCAL_BRIDGE=1` — starts the bridge (requires enrolled credentials + API URL).
- `AETHERIX_LOCAL_BRIDGE_PORT=8787` — override the bind port (default `8787`).
- `AETHERIX_LOCAL_BRIDGE_ORIGIN=chrome-extension://abc,chrome-extension://def` — CSV exact-match allow-list. Leave unset to accept any extension origin.

