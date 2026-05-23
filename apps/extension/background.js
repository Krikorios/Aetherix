// MV3 service worker. Owns:
//   • policy sync with the local Aetherix agent (every 30s + on demand)
//   • the message bus for content scripts (decide / emit evidence)
//   • a bounded retry queue for evidence emission when the agent is offline
//
// Note: service workers in MV3 are ephemeral. All persistent state lives in
// chrome.storage (.session for hot path, .local for offline fallback).

import {
  installPolicySyncAlarm,
  isPolicySyncAlarm,
  syncPolicyNow,
  getRuntimePolicy,
  getBridgeStatus,
} from "./utils/policySync.js";
import { sendEvidence } from "./utils/bridge.js";
import { resolveDecision } from "./utils/classify.js";

const MSG_DECIDE = "aetherix.decide";
const MSG_EVIDENCE = "aetherix.evidence";
const MSG_STATUS = "aetherix.status";
const MSG_RESYNC = "aetherix.resync";

const QUEUE_KEY = "evidence.queue";
const QUEUE_MAX = 500;
const QUEUE_ALARM = "aetherix.flushQueue";

// ---------- evidence queue ----------

async function loadQueue() {
  const { [QUEUE_KEY]: q } = await chrome.storage.local.get(QUEUE_KEY);
  return Array.isArray(q) ? q : [];
}

async function saveQueue(queue) {
  await chrome.storage.local.set({ [QUEUE_KEY]: queue.slice(-QUEUE_MAX) });
}

async function enqueueEvidence(evidence) {
  const queue = await loadQueue();
  queue.push({ evidence, enqueued_at: Date.now() });
  await saveQueue(queue);
  chrome.alarms.create(QUEUE_ALARM, { delayInMinutes: 0.25 }); // ~15s retry
}

async function flushQueue() {
  let queue = await loadQueue();
  if (queue.length === 0) return;
  const remaining = [];
  for (const item of queue) {
    try {
      await sendEvidence(item.evidence);
    } catch {
      remaining.push(item);
    }
  }
  await saveQueue(remaining);
  if (remaining.length > 0) {
    chrome.alarms.create(QUEUE_ALARM, { delayInMinutes: 1 });
  }
}

// ---------- decision + evidence helpers ----------

async function decide(request) {
  const policy = await getRuntimePolicy();
  const decision = resolveDecision(
    policy,
    request?.event_type,
    request?.label_detected || "public",
  );
  return {
    decision,
    policy_version_hash: policy?.policy_version_hash || null,
    policy_source: policy?.source || "default",
  };
}

async function emitEvidence(evidence) {
  // Enrich with policy hash so the backend can correlate to a version even
  // if the agent rewrites/expands the payload.
  const policy = await getRuntimePolicy();
  const enriched = {
    ...evidence,
    policy_version_hash: policy?.policy_version_hash || null,
    source: "browser_extension",
    extension_version: chrome.runtime.getManifest().version,
  };
  try {
    await sendEvidence(enriched);
  } catch {
    await enqueueEvidence(enriched);
  }
}

// ---------- lifecycle ----------

chrome.runtime.onInstalled.addListener(() => {
  installPolicySyncAlarm();
  syncPolicyNow().catch(() => {});
});

chrome.runtime.onStartup.addListener(() => {
  installPolicySyncAlarm();
  syncPolicyNow().catch(() => {});
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (isPolicySyncAlarm(alarm)) {
    syncPolicyNow().catch(() => {});
  } else if (alarm.name === QUEUE_ALARM) {
    flushQueue().catch(() => {});
  }
});

// ---------- message bus ----------

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (!msg || typeof msg.type !== "string") return false;

  switch (msg.type) {
    case MSG_DECIDE:
      decide(msg.payload || {}).then(sendResponse).catch((err) => {
        sendResponse({ decision: "allow", error: String(err) });
      });
      return true; // async

    case MSG_EVIDENCE:
      emitEvidence(msg.payload || {}).then(
        () => sendResponse({ ok: true }),
        (err) => sendResponse({ ok: false, error: String(err) }),
      );
      return true;

    case MSG_STATUS:
      Promise.all([getRuntimePolicy(), getBridgeStatus()])
        .then(([policy, status]) => sendResponse({ ok: true, policy, bridge: status }))
        .catch((err) => sendResponse({ ok: false, error: String(err) }));
      return true;

    case MSG_RESYNC:
      syncPolicyNow().then(
        (policy) => sendResponse({ ok: true, policy }),
        (err) => sendResponse({ ok: false, error: String(err) }),
      );
      return true;

    default:
      return false;
  }
});
