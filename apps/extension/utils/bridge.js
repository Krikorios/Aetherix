// Bridge to the local Aetherix Rust agent.
//
// Two transports are supported:
//
//   Mode A — Native Messaging:  chrome.runtime.connectNative("com.aetherix.browser_bridge")
//                               (preferred; survives strict CSP and avoids
//                                cross-origin localhost issues)
//
//   Mode B — Localhost HTTP:    POST http://127.0.0.1:8787/dlp-event
//                               GET  http://127.0.0.1:8787/policy
//                               (fallback used when native host is not
//                                installed; the agent exposes a loopback
//                                listener bound to 127.0.0.1 only)
//
// All bridge calls are isolated here so the rest of the extension never has
// to care which transport is active.

const NATIVE_HOST = "com.aetherix.browser_bridge";
const HTTP_BASE = "http://127.0.0.1:8787";
const FETCH_TIMEOUT_MS = 4_000;

let preferredMode = null; // "native" | "http" — discovered lazily
let nativePort = null;
let nativePending = new Map(); // requestId -> { resolve, reject, timer }
let nativeReqSeq = 0;

function withTimeout(promise, ms, label) {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(`${label} timed out`)), ms);
    promise.then(
      (v) => { clearTimeout(t); resolve(v); },
      (e) => { clearTimeout(t); reject(e); },
    );
  });
}

// ---------- Native Messaging transport ----------

function ensureNativePort() {
  if (nativePort) return nativePort;
  try {
    nativePort = chrome.runtime.connectNative(NATIVE_HOST);
  } catch (err) {
    nativePort = null;
    throw err;
  }
  nativePort.onMessage.addListener((msg) => {
    const id = msg && msg.requestId;
    if (id && nativePending.has(id)) {
      const { resolve, timer } = nativePending.get(id);
      clearTimeout(timer);
      nativePending.delete(id);
      resolve(msg.payload ?? null);
    }
  });
  nativePort.onDisconnect.addListener(() => {
    const err = chrome.runtime.lastError;
    nativePort = null;
    for (const { reject, timer } of nativePending.values()) {
      clearTimeout(timer);
      reject(new Error(err?.message || "native host disconnected"));
    }
    nativePending.clear();
  });
  return nativePort;
}

function nativeCall(op, payload) {
  return new Promise((resolve, reject) => {
    let port;
    try { port = ensureNativePort(); } catch (e) { return reject(e); }
    const requestId = ++nativeReqSeq;
    const timer = setTimeout(() => {
      if (nativePending.has(requestId)) {
        nativePending.delete(requestId);
        reject(new Error(`native ${op} timed out`));
      }
    }, FETCH_TIMEOUT_MS);
    nativePending.set(requestId, { resolve, reject, timer });
    try {
      port.postMessage({ requestId, op, payload });
    } catch (e) {
      clearTimeout(timer);
      nativePending.delete(requestId);
      reject(e);
    }
  });
}

// ---------- HTTP transport ----------

async function httpGet(path) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(`${HTTP_BASE}${path}`, { signal: ctl.signal });
    if (!res.ok) throw new Error(`bridge ${path} -> HTTP ${res.status}`);
    return await res.json();
  } finally {
    clearTimeout(timer);
  }
}

async function httpPost(path, body) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(`${HTTP_BASE}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
      signal: ctl.signal,
    });
    if (!res.ok) throw new Error(`bridge ${path} -> HTTP ${res.status}`);
    return res.status === 204 ? null : await res.json().catch(() => null);
  } finally {
    clearTimeout(timer);
  }
}

// ---------- Mode resolution ----------

async function probeMode() {
  // Native first if the API surface is even available in this build of Chrome.
  if (chrome.runtime?.connectNative) {
    try {
      await withTimeout(nativeCall("ping", {}), 1_000, "native ping");
      return "native";
    } catch { /* fall through */ }
  }
  try {
    await withTimeout(httpGet("/health"), 1_000, "http health");
    return "http";
  } catch {
    return null;
  }
}

async function ensureMode() {
  if (preferredMode) return preferredMode;
  preferredMode = await probeMode();
  return preferredMode;
}

// ---------- Public API ----------

export async function getPolicy() {
  const mode = await ensureMode();
  if (mode === "native") return nativeCall("get_policy", {});
  if (mode === "http") return httpGet("/policy");
  throw new Error("agent bridge unavailable");
}

export async function sendEvidence(evidence) {
  const mode = await ensureMode();
  if (mode === "native") return nativeCall("emit_evidence", evidence);
  if (mode === "http") return httpPost("/dlp-event", evidence);
  throw new Error("agent bridge unavailable");
}

export async function bridgeStatus() {
  const mode = await ensureMode();
  return { connected: mode !== null, mode };
}

export function resetBridge() {
  preferredMode = null;
  if (nativePort) {
    try { nativePort.disconnect(); } catch { /* ignore */ }
    nativePort = null;
  }
}
