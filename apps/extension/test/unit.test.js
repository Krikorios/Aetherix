// Lightweight Node unit tests for the pure logic modules. Run with:
//   node --test apps/extension/test/unit.test.js
//
// We deliberately avoid pulling in a test framework — these modules have no
// browser-only dependencies, so plain `node:test` is enough for CI.

import { test } from "node:test";
import assert from "node:assert/strict";

import { classifyText, resolveDecision, policyActionFor } from "../utils/classify.js";
import { resolveDestinationSlug, isKnownGenaiHost } from "../utils/destinations.js";
import { deepMerge, mergePolicy, DEFAULT_POLICY } from "../utils/policySync.js";

// ── deepMerge & policy merge ──────────────────────────────────────────

test("deepMerge preserves nested defaults when agent sends partial payload", () => {
  const agentPolicy = {
    endpoint_id: "agent-1",
    policy_version_hash: "v2",
    resolved: {
      semantic_dlp: { enabled: true },
      genai_guardrails: { enabled: true, destinations: ["chatgpt"] },
    },
  };
  const merged = mergePolicy(agentPolicy);
  // Nested actions retained from DEFAULT_POLICY
  assert.deepEqual(merged.resolved.semantic_dlp.actions, {
    paste_sensitive: "review",
    upload_restricted: "block",
    copy_to_genai: "review",
  });
  // Nested detectors retained
  assert.deepEqual(merged.resolved.semantic_dlp.detectors, {
    presidio: true,
    llm_semantic: true,
    custom_classifiers: [],
  });
  // Sensitivity labels retained from default
  assert.deepEqual(merged.resolved.semantic_dlp.sensitivity_labels, [
    "public",
    "internal",
    "confidential",
    "restricted",
  ]);
  // Guardrails actions retained
  assert.deepEqual(merged.resolved.genai_guardrails.actions, {
    paste_sensitive: "review",
    upload_restricted: "block",
    copy_to_genai: "review",
  });
  // Agent-supplied values are NOT overwritten
  assert.equal(merged.endpoint_id, "agent-1");
  assert.equal(merged.policy_version_hash, "v2");
  assert.equal(merged.resolved.semantic_dlp.enabled, true);
  assert.equal(merged.resolved.genai_guardrails.enabled, true);
  assert.deepEqual(merged.resolved.genai_guardrails.destinations, ["chatgpt"]);
  // Top-level synthetic fields
  assert.equal(merged.source, "agent");
  assert.ok(typeof merged.fetched_at === "number");
});

test("deepMerge replaces arrays from source (does not concatenate)", () => {
  const target = { tags: ["a", "b"], inner: { arr: [1, 2] } };
  const source = { tags: ["c"], inner: { arr: [3] } };
  const merged = deepMerge(target, source);
  assert.deepEqual(merged.tags, ["c"]);
  assert.deepEqual(merged.inner.arr, [3]);
});

test("deepMerge handles null and undefined source values", () => {
  const merged = deepMerge({ a: 1, b: { c: 2 } }, { a: null, b: undefined });
  assert.equal(merged.a, null);
  // undefined keys should not appear in result
  assert.equal("b" in merged, true);
});

test("deepMerge handles two levels of nested objects", () => {
  const target = { level1: { level2: { a: 1, b: 2 } } };
  const source = { level1: { level2: { b: 99 } } };
  const merged = deepMerge(target, source);
  assert.equal(merged.level1.level2.a, 1);
  assert.equal(merged.level1.level2.b, 99);
});

test("resolveDecision works with partial policy from deepMerge", () => {
  // Simulate what happens after deepMerge: semantic has no actions field,
  // guardrails only has enabled — all actions come from DEFAULT_POLICY
  const p = mergePolicy({
    resolved: {
      semantic_dlp: { enabled: true },
      genai_guardrails: { enabled: true },
    },
  });
  assert.equal(resolveDecision(p, "paste", "restricted"), "review");
  assert.equal(resolveDecision(p, "upload", "restricted"), "block");
  assert.equal(resolveDecision(p, "copy", "restricted"), "review");
});

// ── classify / resolveDecision ────────────────────────────────────────

test("classifyText flags credit card numbers as restricted", () => {
  const { label, signals } = classifyText("card 4111 1111 1111 1111 here");
  assert.equal(label, "restricted");
  assert.ok(signals.includes("credit_card"));
});

test("classifyText flags PEM private keys as restricted", () => {
  const { label, signals } = classifyText("-----BEGIN RSA PRIVATE KEY-----\nabc");
  assert.equal(label, "restricted");
  assert.ok(signals.includes("private_key_pem"));
});

test("classifyText returns public for benign text", () => {
  const { label, signals } = classifyText("just a friendly hello");
  assert.equal(label, "public");
  assert.deepEqual(signals, []);
});

test("policyActionFor maps event types to policy fields", () => {
  assert.equal(policyActionFor("paste"), "paste_sensitive");
  assert.equal(policyActionFor("upload"), "upload_restricted");
  assert.equal(policyActionFor("copy"), "copy_to_genai");
});

const policyWithBlock = {
  resolved: {
    semantic_dlp: {
      enabled: true,
      actions: { paste_sensitive: "review", upload_restricted: "block", copy_to_genai: "review" },
    },
    genai_guardrails: {
      enabled: true,
      actions: { paste_sensitive: "block", upload_restricted: "block", copy_to_genai: "review" },
    },
  },
};

test("resolveDecision prefers guardrails action over semantic", () => {
  assert.equal(resolveDecision(policyWithBlock, "paste", "restricted"), "block");
});

test("resolveDecision returns allow for public content", () => {
  assert.equal(resolveDecision(policyWithBlock, "paste", "public"), "allow");
});

test("resolveDecision degrades redact to review in the browser", () => {
  const p = JSON.parse(JSON.stringify(policyWithBlock));
  p.resolved.genai_guardrails.actions.paste_sensitive = "redact";
  assert.equal(resolveDecision(p, "paste", "confidential"), "review");
});

test("resolveDecision returns allow when both modules disabled", () => {
  const p = {
    resolved: {
      semantic_dlp: { enabled: false, actions: { paste_sensitive: "block" } },
      genai_guardrails: { enabled: false, actions: { paste_sensitive: "block" } },
    },
  };
  assert.equal(resolveDecision(p, "paste", "restricted"), "allow");
});

test("resolveDestinationSlug maps known GenAI hosts", () => {
  assert.equal(resolveDestinationSlug("claude.ai"), "claude");
  assert.equal(resolveDestinationSlug("chatgpt.com"), "chatgpt");
  assert.equal(resolveDestinationSlug("chat.openai.com"), "chatgpt");
  assert.equal(resolveDestinationSlug("gemini.google.com"), "gemini");
  assert.equal(resolveDestinationSlug("copilot.microsoft.com"), "copilot");
});

test("resolveDestinationSlug returns null for unknown hosts", () => {
  assert.equal(resolveDestinationSlug("example.com"), null);
  assert.equal(isKnownGenaiHost("example.com"), false);
});

test("bridgeStatus falls back to HTTP when native host is unavailable", async () => {
  globalThis.chrome = { runtime: {} };
  const calls = [];
  globalThis.fetch = async (url, options = {}) => {
    calls.push({ url: String(url), method: options.method || "GET" });
    return {
      ok: true,
      status: 200,
      json: async () => String(url).endsWith("/policy")
        ? { policy_version_hash: "hash-http" }
        : { ok: true },
    };
  };

  const bridge = await import(`../utils/bridge.js?http-fallback-${Date.now()}`);
  bridge.resetBridge();

  assert.deepEqual(await bridge.bridgeStatus(), { connected: true, mode: "http" });
  assert.equal((await bridge.getPolicy()).policy_version_hash, "hash-http");
  await bridge.sendEvidence({ event_type: "paste", decision: "review" });
  assert.deepEqual(calls.map((call) => call.method), ["GET", "GET", "POST"]);
});

test("bridgeStatus reports disconnected when native and HTTP are unavailable", async () => {
  globalThis.chrome = { runtime: {} };
  globalThis.fetch = async () => {
    throw new Error("offline");
  };

  const bridge = await import(`../utils/bridge.js?offline-${Date.now()}`);
  bridge.resetBridge();

  assert.deepEqual(await bridge.bridgeStatus(), { connected: false, mode: null });
  await assert.rejects(() => bridge.getPolicy(), /agent bridge unavailable/);
});
