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
import { ErrorBanner, SuccessBanner } from "../components";
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

const DEMO_CASES: AgentCase[] = [
  {
    id: "case-001",
    customer_id: null,
    title: "Potential Lateral Movement — WIN-WORK-042",
    summary:
      "Correlated 3 events: abnormal SMB enumeration from WIN-WORK-042, credential access attempt on WIN-SRV-DC01, and an unusually-timed process execution (conhost.exe spawned by svchost.exe). Timeline suggests staged compromise attempt.",
    status: "awaiting_approval",
    confidence: "high",
    confidence_pct: 87,
    severity: "critical",
    affected_endpoints: ["WIN-WORK-042", "WIN-SRV-DC01"],
    related_events: 8,
    mitre_tactics: ["Discovery", "Lateral Movement", "Credential Access"],
    recommended_response: "Isolate WIN-WORK-042, rotate credentials for jdoe@northgate.internal, review DC01 auth logs.",
    steps: [
      { id: "s1", description: "Ingested endpoint telemetry from WIN-WORK-042", completed: true, timestamp: new Date(Date.now() - 3600000 * 2).toISOString() },
      { id: "s2", description: "Correlated SMB enumeration events with user activity", completed: true, timestamp: new Date(Date.now() - 3600000 * 1.5).toISOString() },
      { id: "s3", description: "Cross-referenced DLP events for data staging signals", completed: true, timestamp: new Date(Date.now() - 3600000).toISOString(), evidence: "No DLP events matched — staging not confirmed" },
      { id: "s4", description: "Queried threat intel for IP 192.168.4.88", completed: true, timestamp: new Date(Date.now() - 1800000).toISOString(), evidence: "Internal IP — no external IoC match" },
      { id: "s5", description: "Generated response recommendation", completed: true, timestamp: new Date(Date.now() - 900000).toISOString() },
      { id: "s6", description: "Awaiting operator approval for isolation action", completed: false, timestamp: null },
    ],
    created_at: new Date(Date.now() - 3600000 * 3).toISOString(),
    updated_at: new Date(Date.now() - 900000).toISOString(),
    resolved_at: null,
  },
  {
    id: "case-002",
    customer_id: null,
    title: "Suspicious Scheduled Task Creation",
    summary:
      "Agent detected scheduled task created via schtasks.exe with a base64-encoded payload. Process lineage: explorer.exe → cmd.exe → schtasks.exe. Pattern is consistent with persistence via scheduled tasks (T1053.005).",
    status: "in_progress",
    confidence: "medium",
    confidence_pct: 64,
    severity: "high",
    affected_endpoints: ["WIN-WORK-017"],
    related_events: 5,
    mitre_tactics: ["Persistence", "Execution"],
    recommended_response: "Decode and analyse scheduled task payload, check for network callbacks, consider isolation.",
    steps: [
      { id: "s1", description: "Detected scheduled task creation event", completed: true, timestamp: new Date(Date.now() - 7200000).toISOString() },
      { id: "s2", description: "Analysing process lineage and parent chain", completed: true, timestamp: new Date(Date.now() - 6000000).toISOString() },
      { id: "s3", description: "Decoding Base64 payload", completed: false, timestamp: null },
      { id: "s4", description: "Correlating with network telemetry", completed: false, timestamp: null },
    ],
    created_at: new Date(Date.now() - 7200000).toISOString(),
    updated_at: new Date(Date.now() - 6000000).toISOString(),
    resolved_at: null,
  },
  {
    id: "case-003",
    customer_id: null,
    title: "False Positive: IT Asset Management Script",
    summary:
      "Flagged PowerShell-based asset discovery script run by IT admin. After correlating with scheduled maintenance window and admin identity context, agent assessed this as authorized activity.",
    status: "resolved",
    confidence: "confirmed",
    confidence_pct: 98,
    severity: "low",
    affected_endpoints: ["WIN-WORK-001"],
    related_events: 2,
    mitre_tactics: ["Discovery"],
    recommended_response: "No action required — add to allowlist to reduce future alerts.",
    steps: [
      { id: "s1", description: "Initial PowerShell execution alert", completed: true, timestamp: new Date(Date.now() - 86400000).toISOString() },
      { id: "s2", description: "Correlated with maintenance window schedule", completed: true, timestamp: new Date(Date.now() - 86400000 + 600000).toISOString(), evidence: "Matched approved maintenance window MW-2024-06-12" },
      { id: "s3", description: "Verified admin identity and intent", completed: true, timestamp: new Date(Date.now() - 86400000 + 1200000).toISOString() },
      { id: "s4", description: "Closed as authorized activity", completed: true, timestamp: new Date(Date.now() - 86400000 + 1800000).toISOString() },
    ],
    created_at: new Date(Date.now() - 86400000).toISOString(),
    updated_at: new Date(Date.now() - 86400000 + 1800000).toISOString(),
    resolved_at: new Date(Date.now() - 86400000 + 1800000).toISOString(),
  },
];

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
      } catch {
        setCases(DEMO_CASES);
        setSelectedId(DEMO_CASES[0].id);
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
      await apiPost(`/agentic/cases/${selectedCase.id}/approve`, {});
    } catch {
      // offline
    }
    setCases((prev) =>
      prev.map((c) => (c.id === selectedCase.id ? { ...c, status: "resolved" as InvestigationStatus, resolved_at: new Date().toISOString() } : c)),
    );
    setSuccess(`Response approved and staged for: ${selectedCase.title}`);
    setIsApproving(false);
  };

  const handleDismiss = async () => {
    if (!selectedCase) return;
    setIsApproving(true);
    try {
      await apiPost(`/agentic/cases/${selectedCase.id}/dismiss`, {});
    } catch {
      // offline
    }
    setCases((prev) =>
      prev.map((c) => (c.id === selectedCase.id ? { ...c, status: "dismissed" as InvestigationStatus } : c)),
    );
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
    <div style={{ display: "flex", flexDirection: "column", flex: 1, padding: "24px", boxSizing: "border-box" }}>
      {/* Header */}
      <div style={{ marginBottom: "20px" }}>
        <div style={{ fontSize: "11px", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--muted)", marginBottom: "4px" }}>
          Autonomous Response
        </div>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: "12px" }}>
          <div>
            <h1 style={{ margin: 0, fontSize: "22px", fontWeight: 700 }}>Agentic AI</h1>
            <p style={{ margin: "4px 0 0 0", fontSize: "12px", color: "var(--muted)" }}>
              Investigation agents correlate telemetry, DLP events, and threat intel into auditable timelines with confidence-scored recommendations.
            </p>
          </div>
          <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
            <button className="btn" onClick={() => setIsSyncing(true)} disabled={isSyncing}>
              <RefreshCw size={14} className={isSyncing ? "spin" : ""} />
              {isSyncing ? "Syncing…" : "Refresh"}
            </button>
          </div>
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
    </div>
  );
}
