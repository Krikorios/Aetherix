import { FormEvent, useEffect, useRef, useState } from "react";
import { ChevronDown, ChevronRight, Plus, X } from "lucide-react";
import { apiGet, apiPost } from "../api";
import type {
  PolicyDocument,
  PolicyDocumentDraft,
  PolicyRule,
  PolicyRuleKind,
  PolicyAction,
  PolicySimulationResponse,
  RiskBand,
} from "../api";
import { ErrorBanner, LoadingRow, EmptyState, RiskBadge, ActionBadge, PageHeader } from "../components";
import { formatDate } from "../utils";

const ENTITY_TYPES = [
  "PERSON",
  "EMAIL_ADDRESS",
  "PHONE_NUMBER",
  "CREDIT_CARD",
  "IBAN_CODE",
  "IP_ADDRESS",
  "DATE_TIME",
  "LOCATION",
  "US_SSN",
  "US_BANK_NUMBER",
  "CRYPTO",
  "NRP",
  "MEDICAL_LICENSE",
  "URL",
];

type DraftRule = {
  _key: string;
  kind: PolicyRuleKind;
  action: PolicyAction;
  entity_type: string;
  pattern: string;
  description: string;
};

function makeDraftRule(): DraftRule {
  return {
    _key: crypto.randomUUID(),
    kind: "entity",
    action: "review",
    entity_type: ENTITY_TYPES[0],
    pattern: "",
    description: "",
  };
}

export function PolicyPage() {
  const [documents, setDocuments] = useState<PolicyDocument[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [promoteOpen, setPromoteOpen] = useState(false);
  const mountedRef = useRef(true);

  // Promote form state
  const [draftName, setDraftName] = useState("Default Policy");
  const [draftMode, setDraftMode] = useState<PolicyDocumentDraft["mode_default"]>("monitor");
  const [draftEscalate, setDraftEscalate] = useState<RiskBand>("high");
  const [draftGenAI, setDraftGenAI] = useState(true);
  const [draftRules, setDraftRules] = useState<DraftRule[]>([makeDraftRule()]);
  const [isPromoting, setIsPromoting] = useState(false);

  // Simulation state
  const [simSamples, setSimSamples] = useState("");
  const [simResult, setSimResult] = useState<PolicySimulationResponse | null>(null);
  const [isSimulating, setIsSimulating] = useState(false);

  async function load() {
    try {
      const docs = await apiGet<PolicyDocument[]>("/policies/documents");
      if (mountedRef.current) {
        setDocuments(docs);
        setError(null);
        // Pre-fill form from current active doc
        if (docs.length > 0) {
          const latest = docs[0];
          setDraftName(latest.name);
          setDraftMode(latest.mode_default);
          setDraftEscalate(latest.escalate_at);
          setDraftGenAI(latest.genai_guardrail);
          if (latest.rules.length > 0) {
            setDraftRules(
              latest.rules.map((r) => ({
                _key: crypto.randomUUID(),
                kind: r.kind,
                action: r.action,
                entity_type: r.entity_type ?? ENTITY_TYPES[0],
                pattern: r.pattern ?? "",
                description: r.description ?? "",
              })),
            );
          }
        }
      }
    } catch (err) {
      if (mountedRef.current) {
        setError(err instanceof Error ? err.message : "Failed to load policy documents");
      }
    } finally {
      if (mountedRef.current) setIsLoading(false);
    }
  }

  useEffect(() => {
    mountedRef.current = true;
    void load();
    return () => { mountedRef.current = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function buildDraft(): PolicyDocumentDraft {
    return {
      name: draftName,
      mode_default: draftMode,
      escalate_at: draftEscalate,
      genai_guardrail: draftGenAI,
      rules: draftRules.map((r, i) => {
        const rule: PolicyRule = {
          id: `rule-${i + 1}`,
          kind: r.kind,
          action: r.action,
        };
        if (r.kind === "entity") {
          rule.entity_type = r.entity_type;
        } else {
          rule.pattern = r.pattern;
        }
        if (r.description) rule.description = r.description;
        return rule;
      }),
    };
  }

  async function promote(event: FormEvent) {
    event.preventDefault();
    setIsPromoting(true);
    setError(null);
    setSuccess(null);

    try {
      await apiPost<PolicyDocument>("/policies/document", buildDraft());
      setSuccess("Policy promoted successfully.");
      setPromoteOpen(false);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Promote failed");
    } finally {
      setIsPromoting(false);
    }
  }

  async function simulate(event: FormEvent) {
    event.preventDefault();
    setIsSimulating(true);
    setError(null);
    setSimResult(null);

    const samples = simSamples
      .split("\n")
      .map((s) => s.trim())
      .filter((s) => s.length > 0)
      .slice(0, 20)
      .map((text) => ({ text, language: "en" }));

    if (samples.length === 0) {
      setError("Enter at least one sample text (one per line).");
      setIsSimulating(false);
      return;
    }

    try {
      const result = await apiPost<PolicySimulationResponse>("/policies/document/simulate", {
        draft: buildDraft(),
        samples,
      });
      setSimResult(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Simulation failed");
    } finally {
      setIsSimulating(false);
    }
  }

  function addRule() {
    setDraftRules((prev) => [...prev, makeDraftRule()]);
  }

  function removeRule(key: string) {
    setDraftRules((prev) => prev.filter((r) => r._key !== key));
  }

  function updateRule(key: string, patch: Partial<DraftRule>) {
    setDraftRules((prev) => prev.map((r) => (r._key === key ? { ...r, ...patch } : r)));
  }

  const activeDoc = documents[0] ?? null;

  return (
    <>
      <PageHeader
        eyebrow="Security policy"
        title="Policy Management"
        subtitle={activeDoc ? `Active: ${activeDoc.name} · v${activeDoc.version}` : "No active policy"}
      />

      {error ? <ErrorBanner message={error} /> : null}
      {success ? <div className="successBanner">{success}</div> : null}

      {/* Active policy card */}
      {activeDoc ? (
        <section className="policyCard">
          <div className="panelHeader" style={{ marginBottom: 0 }}>
            <div>
              <h2 style={{ margin: 0 }}>{activeDoc.name}</h2>
              <span>Version {activeDoc.version} · promoted {formatDate(activeDoc.created_at)}</span>
            </div>
            <span className={`modeLabel mode-${activeDoc.mode_default}`}>{activeDoc.mode_default}</span>
          </div>

          <div className="policyMeta">
            <div className="metaItem">
              <span>Mode</span>
              <strong className={`mode-${activeDoc.mode_default}`}>{activeDoc.mode_default}</strong>
            </div>
            <div className="metaItem">
              <span>Escalate at</span>
              <strong><RiskBadge band={activeDoc.escalate_at} /></strong>
            </div>
            <div className="metaItem">
              <span>GenAI guardrail</span>
              <strong>{activeDoc.genai_guardrail ? "Enabled" : "Disabled"}</strong>
            </div>
            <div className="metaItem">
              <span>Rules</span>
              <strong>{activeDoc.rules.length}</strong>
            </div>
            <div className="metaItem">
              <span>Signed by</span>
              <strong>{activeDoc.signed_by}</strong>
            </div>
          </div>

          {activeDoc.rules.length > 0 ? (
            <div className="rulesList">
              <div className="ruleRow header">
                <span>Kind</span>
                <span>Entity / Pattern</span>
                <span>Action</span>
                <span>Description</span>
                <span />
              </div>
              {activeDoc.rules.map((rule) => (
                <div className="ruleRow" key={rule.id}>
                  <span>{rule.kind}</span>
                  <span>{rule.entity_type ?? rule.pattern ?? "—"}</span>
                  <span><ActionBadge action={rule.action} /></span>
                  <span style={{ color: "var(--muted)", fontSize: "13px" }}>{rule.description ?? "—"}</span>
                  <span />
                </div>
              ))}
            </div>
          ) : (
            <p style={{ margin: "12px 0 0", color: "var(--muted)" }}>No rules defined in this policy.</p>
          )}
        </section>
      ) : (
        !isLoading ? (
          <div className="panel" style={{ padding: "28px", textAlign: "center", color: "var(--muted)", marginBottom: "18px" }}>
            No active policy. Promote a new policy document to activate enforcement.
          </div>
        ) : null
      )}

      {isLoading ? (
        <div className="panel" style={{ padding: "20px" }}>
          <LoadingRow label="Loading policy documents" />
        </div>
      ) : null}

      {/* Promote new policy */}
      <div className="promoteSection">
        <button
          className="promoteSectionHeader"
          onClick={() => setPromoteOpen((o) => !o)}
          aria-expanded={promoteOpen}
        >
          <h3>Promote New Policy</h3>
          {promoteOpen ? <ChevronDown aria-hidden="true" /> : <ChevronRight aria-hidden="true" />}
        </button>

        {promoteOpen ? (
          <div className="promoteSectionBody">
            <form onSubmit={promote}>
              <div className="formGrid2">
                <div className="formRow">
                  <label htmlFor="policyName">Policy name</label>
                  <input
                    id="policyName"
                    type="text"
                    required
                    value={draftName}
                    onChange={(e) => setDraftName(e.target.value)}
                  />
                </div>
                <div className="formRow">
                  <label htmlFor="policyMode">Default mode</label>
                  <select
                    id="policyMode"
                    value={draftMode}
                    onChange={(e) => setDraftMode(e.target.value as PolicyDocumentDraft["mode_default"])}
                  >
                    <option value="monitor">Monitor</option>
                    <option value="review">Review</option>
                    <option value="block">Block</option>
                  </select>
                </div>
                <div className="formRow">
                  <label htmlFor="escalateAt">Escalate at risk band</label>
                  <select
                    id="escalateAt"
                    value={draftEscalate}
                    onChange={(e) => setDraftEscalate(e.target.value as RiskBand)}
                  >
                    <option value="low">Low</option>
                    <option value="medium">Medium</option>
                    <option value="high">High</option>
                    <option value="critical">Critical</option>
                  </select>
                </div>
                <div className="formRow" style={{ justifyContent: "end", alignContent: "end" }}>
                  <label className="toggleRow">
                    <input
                      type="checkbox"
                      checked={draftGenAI}
                      onChange={(e) => setDraftGenAI(e.target.checked)}
                    />
                    GenAI guardrail
                  </label>
                </div>
              </div>

              {/* Rules */}
              <h4 style={{ margin: "16px 0 10px" }}>Rules</h4>
              <div className="rulesList">
                {draftRules.length > 0 ? (
                  <div className="ruleRow header">
                    <span>Kind</span>
                    <span>Action</span>
                    <span>Entity / Pattern</span>
                    <span>Description</span>
                    <span />
                  </div>
                ) : null}

                {draftRules.map((rule) => (
                  <div className="newRuleRow" key={rule._key}>
                    <select
                      value={rule.kind}
                      onChange={(e) => updateRule(rule._key, { kind: e.target.value as PolicyRuleKind })}
                      aria-label="Rule kind"
                    >
                      <option value="entity">Entity</option>
                      <option value="keyword">Keyword</option>
                      <option value="regex">Regex</option>
                    </select>

                    <select
                      value={rule.action}
                      onChange={(e) => updateRule(rule._key, { action: e.target.value as PolicyAction })}
                      aria-label="Rule action"
                    >
                      <option value="allow">Allow</option>
                      <option value="review">Review</option>
                      <option value="block">Block</option>
                    </select>

                    {rule.kind === "entity" ? (
                      <select
                        value={rule.entity_type}
                        onChange={(e) => updateRule(rule._key, { entity_type: e.target.value })}
                        aria-label="Entity type"
                      >
                        {ENTITY_TYPES.map((t) => (
                          <option key={t} value={t}>{t.replaceAll("_", " ")}</option>
                        ))}
                      </select>
                    ) : (
                      <input
                        type="text"
                        placeholder={rule.kind === "regex" ? "Regex pattern…" : "Keyword…"}
                        value={rule.pattern}
                        onChange={(e) => updateRule(rule._key, { pattern: e.target.value })}
                        aria-label="Pattern"
                      />
                    )}

                    <input
                      type="text"
                      placeholder="Description (optional)"
                      value={rule.description}
                      onChange={(e) => updateRule(rule._key, { description: e.target.value })}
                      aria-label="Description"
                    />

                    <button
                      type="button"
                      className="btnIcon"
                      onClick={() => removeRule(rule._key)}
                      aria-label="Remove rule"
                    >
                      <X size={14} />
                    </button>
                  </div>
                ))}
              </div>

              <button
                type="button"
                className="btnSecondary"
                style={{ marginTop: "10px", fontSize: "13px", height: "36px" }}
                onClick={addRule}
              >
                <Plus size={14} />
                Add rule
              </button>

              <div className="formActions">
                <button type="submit" className="btnPrimary" disabled={isPromoting || draftName.trim().length === 0}>
                  {isPromoting ? "Promoting…" : "Promote policy"}
                </button>
              </div>
            </form>

            {/* Simulation */}
            <hr style={{ margin: "24px 0 20px", border: "none", borderTop: "1px solid var(--line)" }} />
            <h4 style={{ margin: "0 0 12px" }}>Simulate Against Samples</h4>
            <p style={{ margin: "0 0 12px", color: "var(--muted)", fontSize: "14px" }}>
              Test how the draft policy above would respond to sample texts before promoting it.
              Enter one sample per line.
            </p>
            <form onSubmit={simulate}>
              <div className="formRow">
                <label htmlFor="simSamples">Sample texts (one per line, max 20)</label>
                <textarea
                  id="simSamples"
                  placeholder={"My email is alice@example.com\nSSN: 123-45-6789\nHello world"}
                  value={simSamples}
                  onChange={(e) => setSimSamples(e.target.value)}
                  style={{ minHeight: "96px" }}
                />
              </div>
              <button
                type="submit"
                className="btnSecondary"
                disabled={isSimulating || simSamples.trim().length === 0}
              >
                {isSimulating ? "Simulating…" : "Run simulation"}
              </button>
            </form>

            {simResult ? (
              <div style={{ marginTop: "16px" }}>
                <div className="simResult">
                  <div className="simStat">
                    <strong>{simResult.summary.total}</strong>
                    <span>Total samples</span>
                  </div>
                  <div className="simStat">
                    <strong>{simResult.summary.changed}</strong>
                    <span>Would change</span>
                  </div>
                  <div className="simStat">
                    <strong>{simResult.summary.would_block}</strong>
                    <span>Would block</span>
                  </div>
                  <div className="simStat">
                    <strong>{simResult.summary.would_review}</strong>
                    <span>Would review</span>
                  </div>
                  <div className="simStat">
                    <strong>{simResult.summary.would_allow}</strong>
                    <span>Would allow</span>
                  </div>
                </div>

                {simResult.results.some((r) => r.changed) ? (
                  <div className="rulesList" style={{ marginTop: "14px" }}>
                    <div className="ruleRow header">
                      <span>Before</span>
                      <span>After</span>
                      <span>Entities</span>
                      <span>Source</span>
                      <span />
                    </div>
                    {simResult.results
                      .filter((r) => r.changed)
                      .map((r, i) => (
                        <div className="ruleRow" key={i}>
                          <span><ActionBadge action={r.before.action} /></span>
                          <span><ActionBadge action={r.after.action} /></span>
                          <span style={{ fontSize: "13px", color: "var(--muted)" }}>
                            {r.after.entity_types.join(", ") || "—"}
                          </span>
                          <span style={{ fontSize: "13px", color: "var(--muted)" }}>{r.source ?? "—"}</span>
                          <span />
                        </div>
                      ))}
                  </div>
                ) : (
                  <p style={{ marginTop: "12px", color: "var(--muted)", fontSize: "14px" }}>
                    No samples would change outcome compared to current policy.
                  </p>
                )}
              </div>
            ) : null}
          </div>
        ) : null}
      </div>

      {/* Policy history */}
      <section style={{ marginTop: "18px" }}>
        <h2 style={{ fontSize: "18px", margin: "0 0 14px" }}>Version History</h2>
        <div className="docList">
          {documents.map((doc, i) => (
            <div className={`docItem${i === 0 ? " current" : ""}`} key={doc.id}>
              <span className="docVersion">v{doc.version}</span>
              <div>
                <strong>{doc.name}</strong>
                <p style={{ margin: "4px 0 0", fontSize: "13px", color: "var(--muted)" }}>
                  {doc.mode_default} · escalate at {doc.escalate_at} ·{" "}
                  {doc.rules.length} {doc.rules.length === 1 ? "rule" : "rules"} ·{" "}
                  {formatDate(doc.created_at)} by {doc.signed_by}
                </p>
              </div>
              {i === 0 ? (
                <span className="modeLabel mode-monitor" style={{ color: "var(--accent)", fontSize: "13px" }}>
                  Active
                </span>
              ) : (
                <span style={{ fontSize: "13px", color: "var(--muted)" }}>Superseded</span>
              )}
            </div>
          ))}
          {!isLoading && documents.length === 0 ? (
            <EmptyState>No policy documents have been promoted yet.</EmptyState>
          ) : null}
        </div>
      </section>
    </>
  );
}
