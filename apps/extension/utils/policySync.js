// Periodically refreshes the resolved policy from the local agent and keeps
// it cached in chrome.storage.session (fast, ephemeral) with a fallback copy
// in chrome.storage.local so that the extension keeps enforcing the last-known
// policy when the agent is temporarily offline.

import { getPolicy, bridgeStatus } from "./bridge.js";

const SYNC_ALARM = "aetherix.policySync";
const SYNC_INTERVAL_MIN = 0.5; // 30s
const SESSION_KEY = "policy.runtime";
const LOCAL_KEY = "policy.lastKnown";

const DEFAULT_POLICY = {
  endpoint_id: null,
  policy_version_hash: "default",
  evidence_controls: [],
  resolved: {
    semantic_dlp: {
      enabled: false,
      sensitivity_labels: ["public", "internal", "confidential", "restricted"],
      genai_destinations: ["claude", "chatgpt", "gemini", "copilot"],
      actions: {
        paste_sensitive: "review",
        upload_restricted: "block",
        copy_to_genai: "review",
      },
      detectors: { presidio: true, llm_semantic: true, custom_classifiers: [] },
    },
    genai_guardrails: {
      enabled: false,
      destinations: ["claude", "chatgpt", "gemini", "copilot"],
      browser_enforcement: true,
      endpoint_enforcement: true,
      actions: {
        paste_sensitive: "review",
        upload_restricted: "block",
        copy_to_genai: "review",
      },
    },
  },
  fetched_at: 0,
  source: "default",
};

// Deep merge two plain objects. Arrays and primitives from `source` replace
// those in `target`; plain objects are merged recursively. This ensures
// partial agent responses preserve nested defaults like `actions` and
// `detectors` that don't appear in the wire payload.
export function deepMerge(target, source) {
  if (source === null || typeof source !== "object") return source;
  const result = { ...target };
  for (const key of Object.keys(source)) {
    const sv = source[key];
    if (sv !== null && typeof sv === "object" && !Array.isArray(sv)) {
      result[key] = deepMerge(result[key] || {}, sv);
    } else {
      result[key] = sv;
    }
  }
  return result;
}

export function mergePolicy(agentPolicy) {
  return deepMerge(DEFAULT_POLICY, {
    ...agentPolicy,
    fetched_at: Date.now(),
    source: "agent",
  });
}

export function installPolicySyncAlarm() {
  chrome.alarms.create(SYNC_ALARM, { periodInMinutes: SYNC_INTERVAL_MIN });
}

export function isPolicySyncAlarm(alarm) {
  return alarm && alarm.name === SYNC_ALARM;
}

export async function syncPolicyNow() {
  try {
    const policy = await getPolicy();
    const enriched = mergePolicy(policy);
    await chrome.storage.session.set({ [SESSION_KEY]: enriched });
    await chrome.storage.local.set({ [LOCAL_KEY]: enriched });
    return enriched;
  } catch (err) {
    // Fall back to last-known policy so enforcement keeps working offline.
    const cached = await loadCachedPolicy();
    if (cached) {
      cached.source = "cached";
      await chrome.storage.session.set({ [SESSION_KEY]: cached });
      return cached;
    }
    const fallback = { ...DEFAULT_POLICY, source: "default", fetched_at: Date.now() };
    await chrome.storage.session.set({ [SESSION_KEY]: fallback });
    return fallback;
  }
}

export async function loadCachedPolicy() {
  const session = await chrome.storage.session.get(SESSION_KEY);
  if (session[SESSION_KEY]) return session[SESSION_KEY];
  const local = await chrome.storage.local.get(LOCAL_KEY);
  return local[LOCAL_KEY] || null;
}

export async function getRuntimePolicy() {
  const cached = await loadCachedPolicy();
  if (cached) return cached;
  return syncPolicyNow();
}

export async function getBridgeStatus() {
  return bridgeStatus();
}

export { DEFAULT_POLICY };
