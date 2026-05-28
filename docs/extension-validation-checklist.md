# Aetherix Browser Extension — Live-Site Validation Checklist

This checklist drives the manual validation pass that complements the unit
tests in `apps/extension/test/unit.test.js`. It covers the four primary
GenAI destinations the agent's `genai_guardrails` and `semantic_dlp` modules
target. Run every row before tagging a new release of the extension.

The expected behaviour assumes a tenant policy where:

- `semantic_dlp.enabled = true`, `semantic_dlp.actions.paste_sensitive = review`,
  `semantic_dlp.actions.upload_restricted = block`.
- `genai_guardrails.enabled = true`, `genai_guardrails.actions.paste_sensitive
  = block` for restricted content.
- Destinations include all four sites.

For each scenario, capture a screenshot of (a) the toast surfaced by the
extension, and (b) the corresponding row in the Aetherix console's evidence
viewer. Attach both to the release PR.

## Reusable fixtures

Use these payloads to exercise the classifier deterministically:

| Fixture | Payload | Expected label |
|---|---|---|
| `RESTRICTED_CC` | `card 4111 1111 1111 1111 here` | `restricted` |
| `RESTRICTED_PEM` | `-----BEGIN RSA PRIVATE KEY-----\nMIIE...` | `restricted` |
| `RESTRICTED_AWS` | `AKIA1234567890ABCDEF` | `restricted` |
| `CONFIDENTIAL_JWT` | `eyJhbGciOi...padded.payload.signature` | `confidential` |
| `PUBLIC` | `hello world, how are you?` | `public` |

## ChatGPT (`chatgpt.com`, `chat.openai.com`)

| Step | Action | Expected |
|---|---|---|
| C1 | Open `https://chatgpt.com/` (home) | `destination_context.route = "home"`, `model` populated from picker |
| C2 | Start a new conversation, paste `RESTRICTED_CC` into the composer | Paste blocked; red toast; one `dlp.paste_block` evidence row with `destination_context.conversation_id` set |
| C3 | Type `RESTRICTED_AWS` and press Enter to submit | Submit allowed by the host (we do not block typed text), but a `dlp.paste_block` or `dlp.paste_review` evidence row is emitted with the typed content hash |
| C4 | Drag-drop a file with PEM contents into the composer | Drop blocked, evidence row with `event_type=upload` |
| C5 | Switch to a different model via the picker; verify model field updates on next event | New evidence rows carry the new model string |
| C6 | Navigate from `/c/<uuid>` back to `/` then into another conversation | `genai.navigation` evidence rows appear for each transition |

## Claude (`claude.ai`)

| Step | Action | Expected |
|---|---|---|
| L1 | Open `https://claude.ai/new` | `destination_context.route = "home"` |
| L2 | Paste `RESTRICTED_PEM` into the ProseMirror composer | Blocked; toast; evidence row |
| L3 | Upload a `.txt` file containing `RESTRICTED_CC` via the paperclip | `event_type=upload`, decision `block`; input element cleared |
| L4 | Open an existing chat `/chat/<uuid>` | `destination_context.conversation_id` set |
| L5 | Confirm `model` extracted from model picker (e.g. "Claude Sonnet 4") | Present on at least one evidence row |

## Gemini (`gemini.google.com`)

| Step | Action | Expected |
|---|---|---|
| G1 | Open `https://gemini.google.com/app` | Route `home` |
| G2 | Paste `RESTRICTED_CC` into the input | Blocked; toast |
| G3 | Paste inside a Gemini "Gem" (custom-instructed agent) — verify shadow-DOM bindings | Same block behaviour as G2; if no event fires, the shadow-DOM observer is failing — file a bug |
| G4 | Submit typed text via Enter | Evidence row emitted |
| G5 | Navigate between `/app/<id>` chats | `genai.navigation` row per transition |

## Microsoft Copilot (`copilot.microsoft.com`)

| Step | Action | Expected |
|---|---|---|
| M1 | Open `https://copilot.microsoft.com/` | Route `home`, `conversation_id` null (Copilot does not expose one in the URL) |
| M2 | Paste `RESTRICTED_AWS` into the prompt box | Blocked |
| M3 | Click the microphone / voice control then send typed text | Send click is detected via `onClickCapture`; evidence row emitted |
| M4 | Upload an image file (out-of-scope binary) | Evidence row recorded, decision per policy; no extension crash |

## Cross-cutting checks (run on at least one site)

- **Service-worker resilience**: kill the local agent (`pkill aetherix-agent`),
  paste `RESTRICTED_CC` — extension must enqueue the evidence to
  `chrome.storage.local`; after agent restart, the queue flushes within 60s.
- **Policy hot-reload**: change `paste_sensitive` from `block` to `review`
  via the console; within 30s (next policy sync) the toast on a paste of
  `RESTRICTED_CC` switches from red ("blocked") to yellow ("logged for
  review").
- **CSP / page errors**: open DevTools → Console; verify no errors from
  `content.js`, `intercept.js`, or `site_context.js`. The extension must
  never inject text into the host page's console other than the single
  `[Aetherix] guardrails active on …` debug line.
- **DOM resilience**: refresh the page mid-conversation; the `paste`
  listener must still fire on subsequent paste events (re-bootstrap via
  `document_start` content script).

---

## Automated validation script

`apps/extension/test/e2e-validation.spec.js` is a Playwright spec that
automates the checklist rows above. It uses Chromium's `--load-extension`
flag to load the real extension into a persistent context and spins up a
local HTTP stub for the Aetherix agent bridge (port 8787) so tests are
deterministic without a running agent.

### One-time setup

```bash
# Install Playwright Chromium (if not already installed)
npx playwright install chromium
```

### Run in CI / stub mode (no live sites)

```bash
SKIP_LIVE_SITES=1 npx playwright test \
  apps/extension/test/e2e-validation.spec.js \
  --config apps/extension/test/playwright.extension.config.js
```

This runs only the bridge-reachability and offline-queue tests. The
`@live-site` tests are automatically skipped.

### Run full manual validation (before every release tag)

```bash
npx playwright test \
  apps/extension/test/e2e-validation.spec.js \
  --config apps/extension/test/playwright.extension.config.js
```

A browser window opens. The script navigates to each live site and fires
synthetic paste/upload events. Results and evidence rows are written to
`apps/extension/test-results/e2e-evidence.json`.

### Interpreting selector-drift annotations

When a site changes its DOM and a composer selector no longer matches, the
test emits an `info.annotation` of type `selector_drift` describing which
selector set to update. After a run, check the annotations in the output:

```
Annotation: selector_drift — "chatgpt composer not found — update SELECTORS.chatgpt"
```

Fix selector drift by updating the `SELECTORS` map inside
`e2e-validation.spec.js` **and** the corresponding extractor function in
`apps/extension/utils/site_context.js`.

### Adding resilient MutationObserver fallbacks

If Gemini test G3 consistently fails with a `selector_drift` annotation
for shadow-DOM interception, add a `MutationObserver` in
`apps/extension/utils/intercept.js` that watches for new shadow hosts
and calls `_bindShadowRoot(el)` on each. The observer should be installed
once at `document_start` so it catches shadow roots added by SPA navigation.

Example skeleton (add to `intercept.js`):

```javascript
const _shadowObserver = new MutationObserver((mutations) => {
  for (const m of mutations) {
    for (const node of m.addedNodes) {
      if (node.nodeType !== 1) continue;
      if (node.shadowRoot && !_boundShadowRoots.has(node.shadowRoot)) {
        _bindShadowRoot(node.shadowRoot);
      }
      // Walk sub-tree for shadow hosts added in bulk
      node.querySelectorAll?.("*").forEach((el) => {
        if (el.shadowRoot && !_boundShadowRoots.has(el.shadowRoot)) {
          _bindShadowRoot(el.shadowRoot);
        }
      });
    }
  }
});
_shadowObserver.observe(document.documentElement, { childList: true, subtree: true });
```

---

## Sign-off

- Tester: __________________
- Date: ____________________
- Extension version: ______
- Agent version: __________
- Tenant policy hash: _____

A release is considered validated only when every row in every section is
either ✓ pass or has an accompanying bug link in the PR description.
