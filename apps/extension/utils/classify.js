// Local pre-classification heuristics. The browser extension intentionally
// does NOT ship the full Presidio/LLM detector stack — that lives in the
// Rust agent + backend. Here we run cheap regex signals to:
//
//   1. decide if an event is "interesting enough" to escalate, and
//   2. attach hints to the evidence payload so the agent can short-circuit.
//
// Final policy decision is always anchored on the cached effective policy
// (`actions.paste_sensitive`, `actions.upload_restricted`, `actions.copy_to_genai`).

const SIGNAL_PATTERNS = [
  { name: "credit_card", re: /\b(?:\d[ -]?){13,19}\b/, label: "restricted" },
  { name: "ssn_us", re: /\b\d{3}-\d{2}-\d{4}\b/, label: "restricted" },
  { name: "aws_access_key", re: /\bAKIA[0-9A-Z]{16}\b/, label: "restricted" },
  { name: "private_key_pem", re: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/, label: "restricted" },
  { name: "jwt", re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/, label: "confidential" },
  { name: "email_bulk", re: /(?:[\w.+-]+@[\w-]+\.[\w.-]+[\s,;]+){3,}/, label: "confidential" },
];

const SENSITIVITY_ORDER = ["public", "internal", "confidential", "restricted"];

export function classifyText(text) {
  if (typeof text !== "string" || text.length === 0) {
    return { label: "public", signals: [] };
  }
  const signals = [];
  let label = "public";
  for (const { name, re, label: hit } of SIGNAL_PATTERNS) {
    if (re.test(text)) {
      signals.push(name);
      if (SENSITIVITY_ORDER.indexOf(hit) > SENSITIVITY_ORDER.indexOf(label)) {
        label = hit;
      }
    }
  }
  return { label, signals };
}

export function policyActionFor(eventType) {
  switch (eventType) {
    case "paste": return "paste_sensitive";
    case "upload": return "upload_restricted";
    case "copy": return "copy_to_genai";
    default: return "paste_sensitive";
  }
}

export function resolveDecision(policy, eventType, label) {
  const semantic = policy?.resolved?.semantic_dlp;
  const guardrails = policy?.resolved?.genai_guardrails;
  if (!semantic?.enabled && !guardrails?.enabled) return "allow";
  if (label === "public") return "allow";

  const field = policyActionFor(eventType);
  const action =
    guardrails?.actions?.[field] ||
    semantic?.actions?.[field] ||
    "review";

  // `redact` is a server-side action; in the browser we degrade to `review`
  // (let through, log evidence) until Phase 2B adds inline redaction.
  if (action === "redact") return "review";
  return action;
}
