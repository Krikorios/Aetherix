import React, { useState, useEffect } from "react";
import {
  Brain,
  RefreshCw,
  Play,
  CheckCircle,
  AlertTriangle,
  Clock,
  Loader2,
  ChevronRight,
  Shield,
  Eye,
  Cpu,
  GitMerge,
  ThumbsUp,
  ThumbsDown,
} from "lucide-react";
import { LoadingState } from "../components/protection/EmptyState";
import { ConsolePage, ErrorBanner, PageHeader, SuccessBanner } from "../components";
import { apiGet, apiPost, type MeResponse } from "../api";

export type InvestigationStatus = "open" | "in_progress" | "awaiting_approval" | "resolved" | "dismissed";
export type ConfidenceLevel = "low" | "medium" | "high" | "confirmed";

export interface InvestigationStep {
  id: string;
  description: string;
  completed: boolean;
  timestamp?: string | null;
  evidence?: string | null;
}

export interface AgentCase {
  id: string;
  customer_id?: string | null;
  title: string;
  summary: string;
  status: InvestigationStatus;
  confidence: ConfidenceLevel;
  confidence_pct: number;
  severity: "low" | "medium" | "high" | "critical";
  affected_endpoints: string[];
  related_events: number;
  mitre_tactics: string[];
  recommended_response: string;
  steps: InvestigationStep[];
  created_at: string;
  updated_at: string;
  resolved_at?: string | null;
}

const CONFIDENCE_COLOR: Record<ConfidenceLevel, string> = {
  low: "var(--muted)",
  medium: "var(--warning)",
  high: "var(--accent)",
  confirmed: "var(--success)",
};

const STATUS_COLOR: Record<InvestigationStatus, string> = {
  open: "var(--muted)",
  in_progress: "var(--accent)",
  awaiting_approval: "var(--warning)",
  resolved: "var(--success)",
  dismissed: "var(--muted)",
};

export function AgenticAiPage({ me }: { me: MeResponse }) {
  const [isLoading, setIsLoading] = useState(true);
  const [isSyncing, setIsSyncing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [cases, setCases] = useState<AgentCase[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [isApproving, setIsApproving] = useState(false);

  const selectedCase = cases.find((c) => c.id === selectedId) ?? null;

  useEffect(() => {
    async function load() {
      try {
        const data = await apiGet<AgentCase[]>("/agentic/cases");
        setCases(data);
        if (data.length > 0) setSelectedId(data[0].id);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load agentic investigation cases.");
      } finally {
        setIsLoading(false);
      }
    }
    void load();
  }, [me]);

  const handleApprove = async () => {
    if (!selectedCase) return;
    setIsApproving(true);
    try {
      const result = await apiPost<{ case: AgentCase }>(`/agentic/cases/${selectedCase.id}/approve`, {});
      setCases((prev) => prev.map((c) => (c.id === selectedCase.id ? result.case : c)));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to approve response.");
      setIsApproving(false);
      return;
    }
    setSuccess(`Response approved and staged for: ${selectedCase.title}`);
    setIsApproving(false);
  };

  const handleDismiss = async () => {
    if (!selectedCase) return;
    setIsApproving(true);
    try {
      const result = await apiPost<{ case: AgentCase }>(`/agentic/cases/${selectedCase.id}/dismiss`, {});
      setCases((prev) => prev.map((c) => (c.id === selectedCase.id ? result.case : c)));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to dismiss case.");
      setIsApproving(false);
      return;
    }
    setSuccess(`Case dismissed: ${selectedCase.title}`);
    setIsApproving(false);
  };

  const open = cases.filter((c) => c.status === "open" || c.status === "in_progress").length;
  const awaitingApproval = cases.filter((c) => c.status === "awaiting_approval").length;
  const resolved = cases.filter((c) => c.status === "resolved").length;

  if (isLoading) {
    return (
      <div style={{ padding: "40px", width: "100%" }}>
        <LoadingState message="Loading investigation cases…" />
      </div>
    );
  }

  return (
    <ConsolePage>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: "12px", marginBottom: "20px" }}>
        <PageHeader eyebrow="Autonomous Response" title="Agentic AI" subtitle="AI-driven investigation and response agents that correlate endpoint telemetry, DLP events, and threat intelligence." />
        <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
          <button className="btn" onClick={() => setIsSyncing(true)} disabled={isSyncing}>
            <RefreshCw size={14} className={isSyncing ? "spin" : ""} />
            {isSyncing ? "Syncing…" : "Refresh"}
          </button>
        </div>
      </div>

      {error && <ErrorBanner message={error} />}
      {success && <SuccessBanner message={success} />}

      {/* Counters */}
      <section
        style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: "14px", marginBottom: "24px" }}
        aria-label="Agent Metrics"
      >
        {[
          { label: "Active Cases", value: open, icon: <Cpu size={18} />, color: "var(--accent)" },
          { label: "Awaiting Approval", value: awaitingApproval, icon: <AlertTriangle size={18} />, color: "var(--warning)" },
          { label: "Resolved", value: resolved, icon: <CheckCircle size={18} />, color: "var(--success)" },
          { label: "Total Cases", value: cases.length, icon: <Brain size={18} />, color: "var(--muted)" },
        ].map(({ label, value, icon, color }) => (
          <div key={label} className="panel" style={{ padding: "14px 16px", display: "flex", alignItems: "center", gap: "12px" }}>
            <div style={{ color }}>{icon}</div>
            <div>
              <div style={{ fontSize: "11px", color: "var(--muted)" }}>{label}</div>
              <strong style={{ fontSize: "16px" }}>{value}</strong>
            </div>
          </div>
        ))}
      </section>

      {/* Main layout */}
      <div style={{ display: "flex", gap: "16px", flex: 1, flexWrap: "wrap", alignItems: "stretch" }}>
        {/* Case list */}
        <div className="panel" style={{ flex: "1 1 300px", minWidth: "260px", display: "flex", flexDirection: "column" }}>
          <h3 style={{ margin: "0 0 0 0", fontSize: "13px", fontWeight: 600, padding: "16px 16px 12px" }}>
            Investigation Cases
          </h3>
          <div style={{ flex: 1, overflowY: "auto" }}>
            {cases.map((c) => {
              const isSelected = selectedId === c.id;
              return (
                <button
                  key={c.id}
                  onClick={() => setSelectedId(c.id)}
                  style={{
                    width: "100%",
                    textAlign: "left",
                    background: isSelected ? "rgba(var(--accent-rgb), 0.07)" : "transparent",
                    border: "none",
                    borderLeft: isSelected ? "3px solid var(--accent)" : "3px solid transparent",
                    padding: "12px 16px",
                    cursor: "pointer",
                    display: "flex",
                    flexDirection: "column",
                    gap: "5px",
                  }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: "8px" }}>
                    <span
                      style={{
                        fontSize: "10px",
                        fontWeight: 600,
                        color: STATUS_COLOR[c.status],
                        textTransform: "uppercase",
                        letterSpacing: "0.05em",
                      }}
                    >
                      {c.status.replace("_", " ")}
                    </span>
                    <span
                      style={{
                        fontSize: "10px",
                        color: CONFIDENCE_COLOR[c.confidence],
                        fontWeight: 600,
                      }}
                    >
                      {c.confidence_pct}% confidence
                    </span>
                  </div>
                  <div style={{ fontSize: "13px", fontWeight: 500, lineHeight: 1.3 }}>{c.title}</div>
                  <div style={{ fontSize: "11px", color: "var(--muted)" }}>
                    {c.affected_endpoints.join(", ")} · {c.related_events} events
                  </div>
                </button>
              );
            })}
          </div>
        </div>

        {/* Case detail */}
        <div className="panel" style={{ flex: "2 1 420px", minWidth: "320px", padding: "20px", display: "flex", flexDirection: "column", gap: "18px", overflowY: "auto" }}>
          {selectedCase ? (
            <>
              <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: "12px" }}>
                <div>
                  <div style={{ fontSize: "11px", color: STATUS_COLOR[selectedCase.status], textTransform: "uppercase", fontWeight: 600, marginBottom: "3px" }}>
                    {selectedCase.status.replace("_", " ")}
                  </div>
                  <h2 style={{ margin: 0, fontSize: "15px" }}>{selectedCase.title}</h2>
                </div>
                {selectedCase.status === "awaiting_approval" && (
                  <div style={{ display: "flex", gap: "6px" }}>
                    <button className="btn" onClick={handleDismiss} disabled={isApproving}>
                      <ThumbsDown size={13} /> Dismiss
                    </button>
                    <button className="btn btnPrimary" onClick={handleApprove} disabled={isApproving}>
                      <ThumbsUp size={13} /> Approve Response
                    </button>
                  </div>
                )}
              </div>

              <p style={{ margin: 0, fontSize: "13px", color: "var(--muted)", lineHeight: 1.6 }}>{selectedCase.summary}</p>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "10px" }}>
                {[
                  { label: "Severity", value: selectedCase.severity.toUpperCase() },
                  { label: "Confidence", value: `${selectedCase.confidence_pct}% (${selectedCase.confidence})` },
                  { label: "Endpoints", value: selectedCase.affected_endpoints.join(", ") },
                  { label: "Related Events", value: selectedCase.related_events },
                  { label: "MITRE Tactics", value: selectedCase.mitre_tactics.join(", ") },
                  { label: "Opened", value: new Date(selectedCase.created_at).toLocaleString() },
                ].map(({ label, value }) => (
                  <div key={label} className="panel" style={{ padding: "10px 12px", gridColumn: label === "MITRE Tactics" || label === "Endpoints" ? "1 / -1" : "auto" }}>
                    <div style={{ fontSize: "11px", color: "var(--muted)" }}>{label}</div>
                    <strong style={{ fontSize: "12px" }}>{value}</strong>
                  </div>
                ))}
              </div>

              {/* Recommended response */}
              <div
                style={{
                  background: "rgba(var(--accent-rgb), 0.05)",
                  border: "1px solid rgba(var(--accent-rgb), 0.15)",
                  borderRadius: "8px",
                  padding: "12px 14px",
                }}
              >
                <div style={{ fontSize: "11px", fontWeight: 600, textTransform: "uppercase", color: "var(--accent)", marginBottom: "6px", display: "flex", alignItems: "center", gap: "5px" }}>
                  <Brain size={12} /> AI Recommendation
                </div>
                <div style={{ fontSize: "12px", color: "var(--muted)", lineHeight: 1.6 }}>{selectedCase.recommended_response}</div>
              </div>

              {/* Investigation timeline */}
              <div>
                <h4 style={{ margin: "0 0 12px 0", fontSize: "12px", fontWeight: 600, textTransform: "uppercase", color: "var(--muted)" }}>
                  Reasoning Timeline
                </h4>
                <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
                  {selectedCase.steps.map((step, i) => (
                    <div key={step.id} style={{ display: "flex", gap: "10px" }}>
                      <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: "0" }}>
                        <div
                          style={{
                            width: "20px",
                            height: "20px",
                            borderRadius: "50%",
                            background: step.completed ? "var(--success)" : "rgba(100,116,139,0.3)",
                            display: "flex",
                            alignItems: "center",
                            justifyContent: "center",
                            flexShrink: 0,
                          }}
                        >
                          {step.completed ? (
                            <CheckCircle size={12} color="#fff" />
                          ) : i === selectedCase.steps.findIndex((s) => !s.completed) ? (
                            <Loader2 size={12} color="#fff" className="spin" />
                          ) : (
                            <Clock size={12} color="rgba(255,255,255,0.5)" />
                          )}
                        </div>
                        {i < selectedCase.steps.length - 1 && (
                          <div style={{ width: "1px", height: "20px", background: step.completed ? "var(--success)" : "rgba(100,116,139,0.2)" }} />
                        )}
                      </div>
                      <div style={{ paddingBottom: "6px", flex: 1 }}>
                        <div style={{ fontSize: "12px", fontWeight: 500, color: step.completed ? "inherit" : "var(--muted)" }}>
                          {step.description}
                        </div>
                        {step.evidence && (
                          <div style={{ fontSize: "11px", color: "var(--muted)", marginTop: "2px", fontStyle: "italic" }}>{step.evidence}</div>
                        )}
                        {step.timestamp && (
                          <div style={{ fontSize: "10px", color: "var(--muted)", marginTop: "2px" }}>
                            {new Date(step.timestamp).toLocaleTimeString()}
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </>
          ) : (
            <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center", color: "var(--muted)", fontSize: "13px" }}>
              Select a case to view the investigation timeline
            </div>
          )}
        </div>
      </div>
    </ConsolePage>
  );
}
