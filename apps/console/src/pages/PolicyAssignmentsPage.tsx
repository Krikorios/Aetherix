import React, { useState, useEffect } from "react";
import {
  Settings2,
  RefreshCw,
  ChevronRight,
  Building2,
  Users,
  Cpu,
  GitBranch,
  Eye,
  Edit3,
  AlertTriangle,
} from "lucide-react";
import { LoadingState } from "../components/protection/EmptyState";
import { ConsolePage, ErrorBanner, PageHeader, SuccessBanner } from "../components";
import { apiGet, apiPost, type MeResponse } from "../api";

export type AssignmentScope = "platform" | "partner" | "company" | "group" | "endpoint";

export interface PolicyAssignment {
  id: string;
  scope: AssignmentScope;
  scope_id: string;
  scope_name: string;
  policy_id: string;
  policy_name: string;
  policy_version: string;
  inherited: boolean;
  override: boolean;
  effective_since: string;
  last_diff?: string | null;
  pending_diff?: string | null;
  endpoint_count: number;
  drift_count: number;
}

const SCOPE_ICON: Record<AssignmentScope, React.ReactNode> = {
  platform: <Settings2 size={14} />,
  partner: <Building2 size={14} />,
  company: <Building2 size={14} />,
  group: <Users size={14} />,
  endpoint: <Cpu size={14} />,
};

const SCOPE_LABEL: Record<AssignmentScope, string> = {
  platform: "Platform",
  partner: "Partner",
  company: "Company",
  group: "Group",
  endpoint: "Endpoint",
};

export function PolicyAssignmentsPage({ me }: { me: MeResponse }) {
  const [isLoading, setIsLoading] = useState(true);
  const [isSyncing, setIsSyncing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [assignments, setAssignments] = useState<PolicyAssignment[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [isWorking, setIsWorking] = useState(false);
  const [showDiff, setShowDiff] = useState(false);

  const selectedAssignment = assignments.find((a) => a.id === selectedId) ?? null;

  useEffect(() => {
    async function load() {
      try {
        const data = await apiGet<PolicyAssignment[]>("/policy/assignments");
        setAssignments(data);
        if (data.length > 0) setSelectedId(data[0].id);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load policy assignments.");
      } finally {
        setIsLoading(false);
      }
    }
    void load();
  }, [me]);

  const handleSync = async () => {
    setIsSyncing(true);
    try {
      const data = await apiGet<PolicyAssignment[]>("/policy/assignments");
      setAssignments(data);
      setSuccess("Policy assignments synced from Policy Engine.");
    } catch {
      setError("Sync failed.");
    } finally {
      setIsSyncing(false);
    }
  };

  const handleApplyDiff = async () => {
    if (!selectedAssignment?.pending_diff) return;
    setIsWorking(true);
    try {
      await apiPost(`/policy/assignments/${selectedAssignment.id}/apply`, {});
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to apply policy diff.");
      setIsWorking(false);
      return;
    }
    setAssignments((prev) =>
      prev.map((a) =>
        a.id === selectedAssignment.id ? { ...a, pending_diff: null, last_diff: new Date().toISOString() } : a,
      ),
    );
    setSuccess(`Policy diff applied for ${selectedAssignment.scope_name}.`);
    setIsWorking(false);
  };

  const totalDrift = assignments.reduce((s, a) => s + a.drift_count, 0);
  const withOverride = assignments.filter((a) => a.override).length;
  const pendingDiffs = assignments.filter((a) => a.pending_diff).length;

  if (isLoading) {
    return (
      <div style={{ padding: "40px", width: "100%" }}>
        <LoadingState message="Loading policy assignments…" />
      </div>
    );
  }

  return (
    <ConsolePage>
      <PageHeader eyebrow="PROTECTION" title="Policy Assignments" />
      <div style={{ display: "flex", justifyContent: "flex-end", marginBottom: "24px" }}>
        <button className="btn" onClick={handleSync} disabled={isSyncing}>
          <RefreshCw size={14} className={isSyncing ? "spin" : ""} />
          {isSyncing ? "Syncing…" : "Sync"}
        </button>
      </div>

      {error && <ErrorBanner message={error} />}
      {success && <SuccessBanner message={success} />}

      {/* Counters */}
      <section
        style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: "14px", marginBottom: "24px" }}
        aria-label="Policy Assignment Metrics"
      >
        {[
          { label: "Total Assignments", value: assignments.length, icon: <Settings2 size={18} />, color: "var(--accent)" },
          { label: "Policy Overrides", value: withOverride, icon: <GitBranch size={18} />, color: "var(--warning)" },
          { label: "Pending Diffs", value: pendingDiffs, icon: <AlertTriangle size={18} />, color: "var(--warning)" },
          { label: "Drift Count", value: totalDrift, icon: <AlertTriangle size={18} />, color: totalDrift > 0 ? "var(--danger)" : "var(--success)" },
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
        {/* Assignment list */}
        <div className="panel" style={{ flex: "1 1 320px", minWidth: "260px", display: "flex", flexDirection: "column" }}>
          <h3 style={{ margin: "0 0 0 0", fontSize: "13px", fontWeight: 600, padding: "16px 16px 12px" }}>
            Scope Hierarchy
          </h3>
          <div style={{ flex: 1, overflowY: "auto" }}>
            {assignments.map((a) => {
              const isSelected = selectedId === a.id;
              return (
                <button
                  key={a.id}
                  onClick={() => setSelectedId(a.id)}
                  style={{
                    width: "100%",
                    textAlign: "left",
                    background: isSelected ? "rgba(var(--accent-rgb), 0.07)" : "transparent",
                    border: "none",
                    borderLeft: isSelected ? "3px solid var(--accent)" : "3px solid transparent",
                    padding: "12px 16px",
                    cursor: "pointer",
                    display: "flex",
                    alignItems: "center",
                    gap: "10px",
                  }}
                >
                  <div style={{ color: "var(--muted)" }}>{SCOPE_ICON[a.scope]}</div>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: "12px", color: "var(--muted)", textTransform: "uppercase", letterSpacing: "0.05em" }}>
                      {SCOPE_LABEL[a.scope]}
                    </div>
                    <div style={{ fontSize: "13px", fontWeight: 500, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                      {a.scope_name}
                    </div>
                    <div style={{ fontSize: "11px", color: "var(--muted)" }}>{a.policy_name}</div>
                  </div>
                  <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: "3px" }}>
                    {a.override && (
                      <span style={{ fontSize: "9px", padding: "1px 5px", borderRadius: "3px", background: "rgba(180,80,24,0.12)", color: "var(--warning)", fontWeight: 700 }}>
                        OVERRIDE
                      </span>
                    )}
                    {a.drift_count > 0 && (
                      <span style={{ fontSize: "9px", padding: "1px 5px", borderRadius: "3px", background: "rgba(239,68,68,0.1)", color: "var(--danger)", fontWeight: 700 }}>
                        {a.drift_count} DRIFT
                      </span>
                    )}
                    {a.pending_diff && (
                      <span style={{ fontSize: "9px", padding: "1px 5px", borderRadius: "3px", background: "rgba(var(--accent-rgb),0.1)", color: "var(--accent)", fontWeight: 700 }}>
                        PENDING
                      </span>
                    )}
                  </div>
                  <ChevronRight size={14} style={{ color: "var(--muted)", flexShrink: 0 }} />
                </button>
              );
            })}
          </div>
        </div>

        {/* Assignment detail */}
        <div className="panel" style={{ flex: "2 1 380px", minWidth: "300px", padding: "20px", display: "flex", flexDirection: "column", gap: "20px" }}>
          {selectedAssignment ? (
            <>
              <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: "12px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                  <div style={{ color: "var(--accent)" }}>{SCOPE_ICON[selectedAssignment.scope]}</div>
                  <div>
                    <div style={{ fontSize: "11px", color: "var(--muted)", textTransform: "uppercase" }}>
                      {SCOPE_LABEL[selectedAssignment.scope]}
                    </div>
                    <h2 style={{ margin: 0, fontSize: "16px" }}>{selectedAssignment.scope_name}</h2>
                  </div>
                </div>
                <div style={{ display: "flex", gap: "6px" }}>
                  <button className="btn" onClick={() => setShowDiff(!showDiff)}>
                    <Eye size={13} /> {showDiff ? "Hide" : "View"} Diff
                  </button>
                  <button className="btn" disabled title="Assignment editing is not available yet">
                    <Edit3 size={13} /> Edit
                  </button>
                </div>
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "10px" }}>
                {[
                  { label: "Policy", value: selectedAssignment.policy_name },
                  { label: "Version", value: selectedAssignment.policy_version },
                  { label: "Inheritance", value: selectedAssignment.inherited ? "Inherited" : "Direct" },
                  { label: "Override", value: selectedAssignment.override ? "Yes" : "No" },
                  { label: "Effective Since", value: new Date(selectedAssignment.effective_since).toLocaleDateString() },
                  { label: "Endpoints", value: selectedAssignment.endpoint_count },
                  { label: "Drift Count", value: selectedAssignment.drift_count },
                  { label: "Last Diff", value: selectedAssignment.last_diff ? new Date(selectedAssignment.last_diff).toLocaleDateString() : "—" },
                ].map(({ label, value }) => (
                  <div key={label} className="panel" style={{ padding: "10px 12px" }}>
                    <div style={{ fontSize: "11px", color: "var(--muted)" }}>{label}</div>
                    <strong style={{ fontSize: "13px" }}>{value}</strong>
                  </div>
                ))}
              </div>

              {selectedAssignment.pending_diff && (
                <div
                  style={{
                    background: "rgba(var(--accent-rgb), 0.06)",
                    border: "1px solid rgba(var(--accent-rgb), 0.18)",
                    borderRadius: "8px",
                    padding: "14px 16px",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    gap: "12px",
                  }}
                >
                  <div>
                    <div style={{ fontSize: "12px", fontWeight: 600, color: "var(--accent)", marginBottom: "3px" }}>Pending Diff</div>
                    <div style={{ fontSize: "12px", color: "var(--muted)" }}>{selectedAssignment.pending_diff}</div>
                  </div>
                  <button className="btn btnPrimary" onClick={handleApplyDiff} disabled={isWorking}>
                    Apply Diff
                  </button>
                </div>
              )}

              {showDiff && (
                <div>
                  <h4 style={{ margin: "0 0 8px 0", fontSize: "12px", fontWeight: 600, textTransform: "uppercase", color: "var(--muted)" }}>
                    Effective Policy Diff
                  </h4>
                  <div
                    style={{
                      background: "#0f172a",
                      color: "#94a3b8",
                      fontFamily: "ui-monospace, Menlo, monospace",
                      fontSize: "11px",
                      padding: "12px 14px",
                      borderRadius: "6px",
                      border: "1px solid var(--line)",
                      lineHeight: 1.7,
                    }}
                  >
                    <div style={{ color: "#22d3ee" }}>--- baseline/{selectedAssignment.scope_name}</div>
                    <div style={{ color: "#22d3ee" }}>+++ effective/{selectedAssignment.scope_name}@{selectedAssignment.policy_version}</div>
                    <br />
                    {selectedAssignment.override ? (
                      <>
                        <div style={{ color: "#86efac" }}>+ "usb_storage_block": true</div>
                        <div style={{ color: "#86efac" }}>+ "approval_required": true</div>
                        <div style={{ color: "#fca5a5" }}>- "usb_storage_block": false</div>
                      </>
                    ) : (
                      <div style={{ color: "#64748b" }}>// Inherited policy — no local overrides</div>
                    )}
                  </div>
                </div>
              )}
            </>
          ) : (
            <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center", color: "var(--muted)", fontSize: "13px" }}>
              Select an assignment to view details
            </div>
          )}
        </div>
      </div>
    </ConsolePage>
  );
}
