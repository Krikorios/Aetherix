// Per-site URL/DOM extractors that turn the current tab into a structured
// `destination` object: { site, model, conversation_id, route }.
//
// All extractors are best-effort: they fall back to null fields if the site
// changes its DOM, but they NEVER throw into the host page. The slug returned
// here MUST match agent/src/policy/mod.rs DEFAULT_GENAI_DESTINATIONS.

import { resolveDestinationSlug } from "./destinations.js";

// ---------- per-site extractors ----------

function extractChatGPT() {
  // chatgpt.com/c/<uuid>  or  chatgpt.com/g/g-xxxx/c/<uuid>  or  /
  const path = location.pathname;
  let conversation_id = null;
  let route = "home";
  const m = path.match(/\/c\/([0-9a-f-]{8,})/i);
  if (m) {
    conversation_id = m[1];
    route = "conversation";
  } else if (path.startsWith("/g/")) {
    route = "gpt";
  }
  // Model lives in a model-picker button. ChatGPT renders an attribute
  // `data-testid="model-switcher"` on the picker; the inner text is the
  // current model.
  let model = null;
  try {
    const picker = document.querySelector(
      '[data-testid="model-switcher-dropdown-button"], button[aria-label*="Model"]',
    );
    if (picker && picker.textContent) {
      model = picker.textContent.trim().slice(0, 64) || null;
    }
  } catch { /* ignore */ }
  return { conversation_id, model, route };
}

function extractClaude() {
  // claude.ai/chat/<uuid> or claude.ai/new
  const m = location.pathname.match(/\/chat\/([0-9a-f-]{8,})/i);
  const conversation_id = m ? m[1] : null;
  const route = conversation_id ? "conversation" : "home";
  let model = null;
  try {
    const sel = document.querySelector(
      '[data-testid="model-selector-dropdown"], button[aria-label*="model" i]',
    );
    if (sel && sel.textContent) model = sel.textContent.trim().slice(0, 64) || null;
  } catch { /* ignore */ }
  return { conversation_id, model, route };
}

function extractGemini() {
  // gemini.google.com/app/<id>  or  /app
  const m = location.pathname.match(/\/app\/([\w-]+)/i);
  const conversation_id = m ? m[1] : null;
  const route = conversation_id ? "conversation" : "home";
  let model = null;
  try {
    // Gemini model picker is `bard-mode-switcher` or a button containing
    // "1.5 Pro" / "2.0 Flash" etc.
    const sel = document.querySelector(
      'bard-mode-switcher, button[aria-label*="model" i], button[aria-label*="Gemini" i]',
    );
    if (sel && sel.textContent) model = sel.textContent.trim().slice(0, 64) || null;
  } catch { /* ignore */ }
  return { conversation_id, model, route };
}

function extractCopilot() {
  // copilot.microsoft.com  — conversation id is typically not in URL,
  // it's in a session token. We expose the route only.
  const route = location.pathname === "/" ? "home" : "conversation";
  let model = null;
  try {
    const sel = document.querySelector('button[aria-label*="GPT" i], button[aria-label*="model" i]');
    if (sel && sel.textContent) model = sel.textContent.trim().slice(0, 64) || null;
  } catch { /* ignore */ }
  return { conversation_id: null, model, route };
}

const EXTRACTORS = {
  chatgpt: extractChatGPT,
  claude: extractClaude,
  gemini: extractGemini,
  copilot: extractCopilot,
};

// ---------- public API ----------

export function getDestinationContext() {
  const site = resolveDestinationSlug(location.hostname);
  if (!site) return null;
  const fn = EXTRACTORS[site];
  let extracted = { conversation_id: null, model: null, route: null };
  try {
    if (fn) extracted = fn() || extracted;
  } catch { /* ignore */ }
  return {
    site,
    host: location.hostname,
    path: location.pathname,
    ...extracted,
  };
}

// Subscribe to SPA route changes by patching history methods. The patches
// dispatch a synthetic `aetherix:locationchange` event the interceptor
// listens for. Idempotent.
let _patched = false;
export function installLocationChangeWatcher(handler) {
  if (typeof handler !== "function") return;
  if (!_patched) {
    _patched = true;
    try {
      const wrap = (name) => {
        const orig = history[name];
        if (typeof orig !== "function") return;
        history[name] = function patched(...args) {
          const ret = orig.apply(this, args);
          window.dispatchEvent(new Event("aetherix:locationchange"));
          return ret;
        };
      };
      wrap("pushState");
      wrap("replaceState");
      window.addEventListener("popstate", () => {
        window.dispatchEvent(new Event("aetherix:locationchange"));
      });
    } catch { /* ignore */ }
  }
  window.addEventListener("aetherix:locationchange", () => {
    try { handler(); } catch { /* ignore */ }
  });
}
