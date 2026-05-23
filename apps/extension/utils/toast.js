// In-page toast UI. Shadow-DOM isolated to avoid leaking styles into the host
// page (GenAI sites aggressively restyle the document).

const HOST_ID = "__aetherix_toast_host__";

let hostEl = null;
let shadowRoot = null;

function ensureHost() {
  if (hostEl && document.body.contains(hostEl)) return shadowRoot;
  hostEl = document.createElement("div");
  hostEl.id = HOST_ID;
  hostEl.style.all = "initial";
  hostEl.style.position = "fixed";
  hostEl.style.top = "16px";
  hostEl.style.right = "16px";
  hostEl.style.zIndex = "2147483647";
  hostEl.style.pointerEvents = "none";
  shadowRoot = hostEl.attachShadow({ mode: "closed" });

  const style = document.createElement("link");
  style.rel = "stylesheet";
  style.href = chrome.runtime.getURL("styles/toast.css");
  shadowRoot.appendChild(style);

  const stack = document.createElement("div");
  stack.className = "aetherix-toast-stack";
  shadowRoot.appendChild(stack);

  (document.body || document.documentElement).appendChild(hostEl);
  return shadowRoot;
}

export function showToast({ kind = "review", title, body, ttlMs = 6_000 } = {}) {
  const root = ensureHost();
  const stack = root.querySelector(".aetherix-toast-stack");
  if (!stack) return;

  const card = document.createElement("div");
  card.className = `aetherix-toast aetherix-toast--${kind}`;
  card.setAttribute("role", "alert");

  const titleEl = document.createElement("div");
  titleEl.className = "aetherix-toast__title";
  titleEl.textContent = title || (kind === "block" ? "Blocked by Aetherix" : "Logged by Aetherix");

  const bodyEl = document.createElement("div");
  bodyEl.className = "aetherix-toast__body";
  bodyEl.textContent = body || "";

  const close = document.createElement("button");
  close.type = "button";
  close.className = "aetherix-toast__close";
  close.setAttribute("aria-label", "Dismiss");
  close.textContent = "×";
  close.addEventListener("click", () => card.remove());

  card.appendChild(close);
  card.appendChild(titleEl);
  if (body) card.appendChild(bodyEl);
  stack.appendChild(card);

  if (ttlMs > 0) {
    setTimeout(() => card.remove(), ttlMs);
  }
}
