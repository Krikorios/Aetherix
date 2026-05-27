// Intercepts paste / upload / copy events on GenAI destinations, classifies
// the payload locally, and enforces the policy decision returned by the
// service worker (which owns the cached effective policy from the agent).
//
// Loaded as an ES module from content.js via dynamic import. All DOM
// listeners are registered with capture=true so we run BEFORE the GenAI
// site's own handlers and can preventDefault before the bytes leave the
// browser.

import { sha256Hex } from "./hash.js";
import { classifyText, policyActionFor } from "./classify.js";
import { resolveDestinationSlug } from "./destinations.js";
import { showToast } from "./toast.js";
import { getDestinationContext, installLocationChangeWatcher } from "./site_context.js";

const MSG_DECIDE = "aetherix.decide";
const MSG_EVIDENCE = "aetherix.evidence";

const MAX_TEXT_SCAN = 64 * 1024; // 64 KiB cap on local classification

let destination = null;
let destinationContext = null;
const _boundShadowRoots = new WeakSet();
let _lastSubmitDecisionAt = 0;
let _lastSubmitContentHash = null;

function refreshDestinationContext() {
  destinationContext = getDestinationContext();
  destination = destinationContext?.site || destination;
}

function sendMessage(type, payload) {
  return new Promise((resolve) => {
    try {
      chrome.runtime.sendMessage({ type, payload }, (response) => {
        if (chrome.runtime.lastError) {
          resolve({ ok: false, error: chrome.runtime.lastError.message });
        } else {
          resolve(response || { ok: false });
        }
      });
    } catch (e) {
      resolve({ ok: false, error: String(e) });
    }
  });
}

function extractClipboardText(clipboardData) {
  if (!clipboardData) return "";
  try {
    return clipboardData.getData("text/plain") || "";
  } catch {
    return "";
  }
}

function summarizeFiles(fileList) {
  const files = Array.from(fileList || []);
  return files.map((f) => ({
    name: f.name,
    size: f.size,
    type: f.type || "application/octet-stream",
  }));
}

async function notify({ decision, eventType, label }) {
  if (decision === "allow") return;
  const verb =
    eventType === "paste" ? "paste"
    : eventType === "upload" ? "upload"
    : "copy";
  if (decision === "block") {
    showToast({
      kind: "block",
      title: `Aetherix blocked this ${verb}`,
      body: `Content classified as ${label}. Contact your security admin if this is a false positive.`,
    });
  } else if (decision === "review") {
    showToast({
      kind: "review",
      title: `Aetherix logged this ${verb}`,
      body: `Content classified as ${label}. Event recorded for compliance review.`,
    });
  }
}

async function decideAndEmit({ eventType, sampleText, fileSummaries }) {
  const textForClassify = (sampleText || "").slice(0, MAX_TEXT_SCAN);
  const { label, signals } = classifyText(textForClassify);
  const contentHash = sampleText
    ? await sha256Hex(sampleText)
    : fileSummaries && fileSummaries.length
      ? await sha256Hex(JSON.stringify(fileSummaries))
      : "sha256:empty";

  refreshDestinationContext();
  const req = {
    event_type: eventType,
    destination,
    destination_context: destinationContext,
    label_detected: label,
    signals,
    policy_action_field: policyActionFor(eventType),
    content_hash: contentHash,
    tab_url: location.href,
    file_summaries: fileSummaries || null,
    timestamp: new Date().toISOString(),
  };

  const decisionResp = await sendMessage(MSG_DECIDE, req);
  const decision = decisionResp?.decision || "allow";

  // Evidence is fire-and-forget; the SW handles retry/queueing.
  sendMessage(MSG_EVIDENCE, {
    action: `dlp.${eventType}_${decision}`,
    event_type: eventType,
    destination,
    destination_context: destinationContext,
    label_detected: label,
    content_hash: contentHash,
    policy_action_field: req.policy_action_field,
    decision,
    signals,
    timestamp: req.timestamp,
    tab_url: req.tab_url,
    file_summaries: fileSummaries || null,
  });

  notify({ decision, eventType, label });
  return decision;
}

// ---------- paste ----------

function onPasteCapture(ev) {
  const text = extractClipboardText(ev.clipboardData);
  if (!text) return; // nothing we can classify here (image-only, etc.)

  // We must decide synchronously whether to block, but classification is
  // async. Strategy: preventDefault unconditionally, then re-dispatch the
  // paste programmatically only if the SW says `allow`/`review`. This is
  // the same "intercept then replay" pattern used by enterprise DLP MV3
  // extensions.
  const target = ev.target;
  if (!(target instanceof Element)) return;

  ev.preventDefault();
  ev.stopPropagation();

  decideAndEmit({ eventType: "paste", sampleText: text })
    .then((decision) => {
      if (decision === "block") return;
      replayPaste(target, text);
    })
    .catch(() => {
      // Fail-open on internal extension errors so we don't silently break
      // the user's workflow. The evidence pipeline will still attempt to
      // log the bypass.
      replayPaste(target, text);
    });
}

function replayPaste(target, text) {
  try {
    if (target.isContentEditable) {
      const sel = window.getSelection();
      if (sel && sel.rangeCount > 0) {
        const range = sel.getRangeAt(0);
        range.deleteContents();
        range.insertNode(document.createTextNode(text));
        range.collapse(false);
        sel.removeAllRanges();
        sel.addRange(range);
      } else {
        target.textContent += text;
      }
      target.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertFromPaste", data: text }));
    } else if (
      target instanceof HTMLTextAreaElement ||
      (target instanceof HTMLInputElement && /^(text|search|url|email|tel|password)$/i.test(target.type))
    ) {
      const start = target.selectionStart ?? target.value.length;
      const end = target.selectionEnd ?? target.value.length;
      target.value = target.value.slice(0, start) + text + target.value.slice(end);
      const caret = start + text.length;
      target.setSelectionRange(caret, caret);
      target.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertFromPaste", data: text }));
    }
  } catch {
    // last-resort, don't throw into the page
  }
}

// ---------- copy ----------

function onCopyCapture(ev) {
  // We only care about copy events when the page is a GenAI destination —
  // i.e. the user copied something FROM the GenAI tool. The agent's
  // `copy_to_genai` action is about classified content moving INTO GenAI,
  // so this listener is mostly an observation point in Phase 2A.
  const selection = window.getSelection()?.toString() || "";
  if (!selection) return;
  decideAndEmit({ eventType: "copy", sampleText: selection }).catch(() => {});
}

// ---------- upload ----------

async function handleFileSelection(input) {
  const files = summarizeFiles(input.files);
  if (!files.length) return;

  // We can't read file contents synchronously without permission prompts on
  // every site, but the agent's upload_restricted policy is mostly driven
  // by filename + MIME + size + classification of accompanying prompt text.
  // We still sample a small slice of text-like files to feed the local
  // classifier.
  let sampleText = "";
  for (const file of input.files) {
    if (file.size <= MAX_TEXT_SCAN && /^(text\/|application\/(json|xml|x-yaml))/.test(file.type)) {
      try { sampleText += await file.slice(0, MAX_TEXT_SCAN).text(); } catch { /* ignore */ }
      if (sampleText.length >= MAX_TEXT_SCAN) break;
    }
  }

  const decision = await decideAndEmit({
    eventType: "upload",
    sampleText,
    fileSummaries: files,
  });

  if (decision === "block") {
    try {
      input.value = ""; // clear the selection so the host page can't submit
      showToast({
        kind: "block",
        title: "Aetherix blocked this upload",
        body: `${files.length} file(s) classified as restricted. Upload prevented.`,
      });
    } catch { /* ignore */ }
  }
}

function onFileInputChange(ev) {
  const t = ev.target;
  if (t instanceof HTMLInputElement && t.type === "file") {
    handleFileSelection(t).catch(() => {});
  }
}

// ---------- drag & drop ----------

function onDropCapture(ev) {
  const dt = ev.dataTransfer;
  if (!dt) return;
  const files = dt.files;
  const text = dt.getData ? (dt.getData("text/plain") || "") : "";

  if (files && files.length) {
    ev.preventDefault();
    ev.stopPropagation();
    decideAndEmit({
      eventType: "upload",
      sampleText: text,
      fileSummaries: summarizeFiles(files),
    }).then((decision) => {
      if (decision !== "block") {
        // Replay drop is not safely supported across all GenAI sites —
        // surface guidance and ask the user to retry through the picker.
        showToast({
          kind: "info",
          title: "Aetherix scanned your drop",
          body: "Please re-select the files via the upload button to continue.",
        });
      }
    }).catch(() => {});
  } else if (text) {
    // Treat drag-text as a paste into the drop target.
    ev.preventDefault();
    ev.stopPropagation();
    decideAndEmit({ eventType: "paste", sampleText: text }).then((decision) => {
      if (decision !== "block" && ev.target instanceof Element) {
        replayPaste(ev.target, text);
      }
    }).catch(() => {});
  }
}

// ---------- bootstrap ----------

// ---------- composer submit safety net ----------
//
// Paste/upload/drop cover bytes the user introduces from elsewhere. They do
// NOT cover text the user TYPES into the composer. For typed text we have to
// observe the composer at submit time (Enter key / send-button click) and
// classify the buffered prompt before the host page actually sends it.
//
// Strategy: scan visible composer elements (contenteditable / textarea) when
// the user presses Enter without Shift, or when they click a send button.
// We do not block the host page submit (that would break too many SPAs);
// instead we always emit evidence with the classification, and on `block`
// we surface a toast asking the user to remove the content. This matches
// the deterministic-first principle: evidence-by-construction, with policy
// enforcement deferred to the agent's outbound network interceptor.

function findComposerNear(node) {
  let cur = node;
  while (cur && cur !== document.body) {
    if (cur instanceof HTMLElement && (
      cur.isContentEditable ||
      cur instanceof HTMLTextAreaElement
    )) {
      return cur;
    }
    cur = cur.parentElement;
  }
  // Fall back to the active element.
  const ae = document.activeElement;
  if (ae instanceof HTMLElement && (ae.isContentEditable || ae instanceof HTMLTextAreaElement)) {
    return ae;
  }
  return null;
}

function readComposerText(el) {
  if (!el) return "";
  if (el instanceof HTMLTextAreaElement) return el.value || "";
  if (el.isContentEditable) return el.innerText || el.textContent || "";
  return "";
}

async function handleComposerSubmit(composer) {
  const text = (readComposerText(composer) || "").trim();
  if (!text) return;
  // Debounce identical submits within 750ms (Enter + send-button fire both).
  const now = Date.now();
  const hash = await sha256Hex(text);
  if (hash === _lastSubmitContentHash && now - _lastSubmitDecisionAt < 750) return;
  _lastSubmitContentHash = hash;
  _lastSubmitDecisionAt = now;
  await decideAndEmit({ eventType: "paste", sampleText: text });
}

function onKeyDownCapture(ev) {
  if (ev.key !== "Enter" || ev.shiftKey || ev.isComposing) return;
  const composer = findComposerNear(ev.target instanceof Element ? ev.target : null);
  if (!composer) return;
  // Don't block — let the host page submit. Evidence is emitted async.
  handleComposerSubmit(composer).catch(() => {});
}

function onClickCapture(ev) {
  const t = ev.target;
  if (!(t instanceof Element)) return;
  // Heuristic: send button is usually an aria-label containing "send" or a
  // submit button inside a form near a composer. Cheap label check.
  const btn = t.closest('button, [role="button"]');
  if (!btn) return;
  const label = (btn.getAttribute("aria-label") || btn.textContent || "").toLowerCase();
  if (!/send|submit/.test(label)) return;
  const composer = findComposerNear(btn);
  if (!composer) return;
  handleComposerSubmit(composer).catch(() => {});
}

// ---------- shadow DOM rebinding ----------

function bindToRoot(root) {
  if (!root || _boundShadowRoots.has(root)) return;
  _boundShadowRoots.add(root);
  root.addEventListener("paste", onPasteCapture, true);
  root.addEventListener("copy", onCopyCapture, true);
  root.addEventListener("change", onFileInputChange, true);
  root.addEventListener("drop", onDropCapture, true);
  root.addEventListener("keydown", onKeyDownCapture, true);
  root.addEventListener("click", onClickCapture, true);
}

function scanForShadowRoots(node) {
  if (!node) return;
  if (node.shadowRoot) bindToRoot(node.shadowRoot);
  let walker;
  try {
    walker = document.createTreeWalker(node, NodeFilter.SHOW_ELEMENT);
  } catch {
    return;
  }
  let el = walker.nextNode();
  while (el) {
    if (el.shadowRoot) bindToRoot(el.shadowRoot);
    el = walker.nextNode();
  }
}

function installShadowObserver() {
  try {
    const obs = new MutationObserver((mutations) => {
      for (const m of mutations) {
        for (const added of m.addedNodes) {
          if (added instanceof Element) scanForShadowRoots(added);
        }
      }
    });
    obs.observe(document.documentElement, { childList: true, subtree: true });
    scanForShadowRoots(document.documentElement);
  } catch { /* ignore */ }
}

// ---------- bootstrap ----------

export function bootstrap() {
  destination = resolveDestinationSlug(location.hostname);
  if (!destination) return false;
  refreshDestinationContext();

  // capture=true so we run before the page's own handlers.
  document.addEventListener("paste", onPasteCapture, true);
  document.addEventListener("copy", onCopyCapture, true);
  document.addEventListener("change", onFileInputChange, true);
  document.addEventListener("drop", onDropCapture, true);
  document.addEventListener("keydown", onKeyDownCapture, true);
  document.addEventListener("click", onClickCapture, true);

  installShadowObserver();

  // Track SPA navigation so the agent has a per-conversation audit trail.
  installLocationChangeWatcher(() => {
    refreshDestinationContext();
    sendMessage(MSG_EVIDENCE, {
      action: "genai.navigation",
      event_type: "navigation",
      destination,
      destination_context: destinationContext,
      timestamp: new Date().toISOString(),
      tab_url: location.href,
    });
  });

  return true;
}
