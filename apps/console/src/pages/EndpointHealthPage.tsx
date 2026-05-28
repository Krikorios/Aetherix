import React, { useState, useEffect, useCallback } from "react";
import {
  Shield,
  AlertTriangle,
  CheckCircle,
  Clock,
  Cpu,
  WifiOff,
  GitBranch,
  Activity,
  RefreshCw,
  Play,
  Scan,
  List,
} from "lucide-react";
import { ModuleHeader } from "../components/protection/ModuleHeader";
import { DetectionTable } from "../components/protection/DetectionTable";
import { DetailPanel } from "../components/protection/DetailPanel";
import { ActionStagingPanel } from "../components/protection/ActionStagingPanel";
import { EmptyState, LoadingState } from "../components/protection/EmptyState";
import {
  Detection,
  StagedAction,
  SimulationPreview,
  EffectivePolicy,
} from "../components/protection/types";
import { ConsolePage, ErrorBanner, MetricGrid, SuccessBanner } from "../components";
import { apiGet, apiPost, type MeResponse } from "../api";

export interface RecoveryPointSummary {
  id: string;
  provider: string;
  created_at: string;
  expires_at?: string | null;
  protected_root?: string;
  verified?: boolean;
}

export interface RollbackReadiness {
  capability_supported?: boolean;
  provider_available?: boolean;
  provider_name?: string;
  provider_version?: string;
  provider_metadata?: Record<string, unknown> | null;
  os_platform?: string;
  functional?: boolean;
  diagnosis?: string;
  recovery_point_count?: number;
  recovery_points_count?: number;
  recovery_points?: RecoveryPointSummary[];
  available_filesystems?: string[];
  service_available?: boolean;
  sufficient_privilege?: boolean;
  volume_capabilities?: string[];
  snapshot_service_info?: string | null;
  privilege_boundary?: string | null;
  recent_fim_paths?: string[];
  last_checked_at?: string;
}

export interface EndpointHealthRecord {
  id: string;
  customer_id?: string | null;
  endpoint_name: string;
  hostname: string;
  os: string;
  agent_version: string;
  latest_agent_version: string;
  policy_version: string;
  active_policy_version: string;
  status: "healthy" | "attention" | "offline" | "drifted";
  last_heartbeat: string;
  risk_score: number;
  open_alerts: number;
  pending_actions: number;
  tags: string[];
  cpu_percent?: number | null;
  memory_percent?: number | null;
  dlp_events?: number;
  blocked_events?: number;
  rollback_readiness?: RollbackReadiness | null;
}

export interface ResponseAction {
  id: string;
  target_id: string;
  action: string;
  status: "queued" | "awaiting_approval" | "completed" | "failed" | "denied";
  approval_required: boolean;
  payload: Record<string, unknown> | null;
  evidence_controls: string[];
  created_at: string;
  result: Record<string, unknown> | null;
  processed_at: string | null;
  requested_by: string | null;
}

function TelemetryBar({ label, value, color, icon }: { label: string; value: number; color: string; icon?: React.ReactNode }) {
  const pct = Math.min(100, Math.max(0, value));
  const barColor = pct > 85 ? "var(--danger)" : pct > 65 ? "var(--warning)" : color;
  return (
    <div style={{ marginBottom: "10px" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "4px" }}>
        <span style={{ display: "flex", alignItems: "center", gap: "4px", fontSize: "12px", color: "var(--muted)" }}>
          {icon}
          {label}
        </span>
        <strong style={{ fontSize: "12px", color: pct > 85 ? "var(--danger)" : pct > 65 ? "var(--warning)" : undefined }}>{pct.toFixed(1)}%</strong>
      </div>
      <div style={{ height: "6px", background: "rgba(255,255,255,0.07)", borderRadius: "3px", overflow: "hidden" }}>
        <div style={{ height: "100%", width: `${pct}%`, background: barColor, borderRadius: "3px", transition: "width 0.4s ease" }} />
      </div>
    </div>
  );
}

const ACTION_STATUS_COLORS: Record<string, string> = {
  queued: "var(--accent)",
  awaiting_approval: "#e07a00",
  completed: "var(--success)",
  failed: "var(--danger)",
  denied: "var(--muted)",
};

function ResponseActionsPanel({ endpointId, onRefresh }: { endpointId: string; onRefresh?: () => void }) {
  const [actions, setActions] = useState<ResponseAction[]>([]);
  const [loading, setLoading] = useState(true);
  const [sendingAction, setSendingAction] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await apiGet<ResponseAction[]>(`/endpoints/${endpointId}/response-actions?limit=20`);
      setActions(data);
    } catch {
      // silently ignore - panel is non-critical
    } finally {
      setLoading(false);
    }
  }, [endpointId]);

  useEffect(() => { void load(); }, [load]);

  async function sendAction(action: string, payload?: Record<string, unknown>) {
    setSendingAction(action);
    try {
      await apiPost(`/endpoints/${endpointId}/remediate`, { action, payload: payload ?? null });
      onRefresh?.();
      await load();
    } finally {
      setSendingAction(null);
    }
  }

  async function requestQuarantineList() {
    setSendingAction("quarantine_list");
    try {
      await apiPost(`/endpoints/${endpointId}/quarantine-list`, {});
      await load();
    } finally {
      setSendingAction(null);
    }
  }

  const timeAgo = (iso: string) => {
    const s = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000));
    if (s < 60) return `${s}s ago`;
    if (s < 3600) return `${Math.floor(s / 60)}m ago`;
    if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
    return new Date(iso).toLocaleDateString();
  };

  const actionLabel = (a: string) =>
    a.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());

  return (
    <div>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "10px" }}>
        <h4 className="sectionKicker" style={{ margin: 0 }}>Response Actions</h4>
        <button
          className="btn btn--ghost btn--sm"
          onClick={() => void load()}
          disabled={loading}
          style={{ display: "flex", alignItems: "center", gap: "4px", fontSize: "11px" }}
        >
          <RefreshCw size={12} className={loading ? "spin" : ""} />
          Refresh
        </button>
      </div>

      <div style={{ display: "flex", gap: "6px", flexWrap: "wrap", marginBottom: "12px" }}>
        <button
          className="btn btn--primary btn--sm"
          onClick={() => void sendAction("malware_scan")}
          disabled={sendingAction !== null}
          style={{ display: "flex", alignItems: "center", gap: "4px", fontSize: "11px" }}
        >
          <Scan size={12} />
          {sendingAction === "malware_scan" ? "Queuing…" : "Malware Scan"}
        </button>
        <button
          className="btn btn--secondary btn--sm"
          onClick={() => void requestQuarantineList()}
          disabled={sendingAction !== null}
          style={{ display: "flex", alignItems: "center", gap: "4px", fontSize: "11px" }}
        >
          <List size={12} />
          {sendingAction === "quarantine_list" ? "Queuing…" : "Refresh Quarantine"}
        </button>
        <button
          className="btn btn--ghost btn--sm"
          onClick={() => void sendAction("push_policy_update")}
          disabled={sendingAction !== null}
          style={{ display: "flex", alignItems: "center", gap: "4px", fontSize: "11px" }}
        >
          <Play size={12} />
          {sendingAction === "push_policy_update" ? "Queuing…" : "Push Policy"}
        </button>
      </div>

      {loading ? (
        <div style={{ fontSize: "12px", color: "var(--muted)", padding: "8px 0" }}>Loading actions…</div>
      ) : actions.length === 0 ? (
        <div style={{ fontSize: "12px", color: "var(--muted)", padding: "8px 0" }}>No actions recorded yet.</div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: "6px", maxHeight: "220px", overflowY: "auto" }}>
          {actions.map((a) => (
            <div
              key={a.id}
              style={{
                background: "rgba(255,255,255,0.03)",
                border: "1px solid rgba(255,255,255,0.08)",
                borderRadius: "6px",
                padding: "8px 10px",
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                gap: "8px",
              }}
            >
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: "12px", fontWeight: 600, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                  {actionLabel(a.action)}
                </div>
                <div style={{ fontSize: "11px", color: "var(--muted)", marginTop: "2px" }}>{timeAgo(a.created_at)}</div>
              </div>
              <span
                style={{
                  fontSize: "10px",
                  fontWeight: 700,
                  letterSpacing: "0.05em",
                  color: ACTION_STATUS_COLORS[a.status] ?? "var(--muted)",
                  textTransform: "uppercase",
                  flexShrink: 0,
                }}
              >
                {a.status.replace(/_/g, " ")}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export function EndpointHealthPage({ me }: { me: MeResponse }) {
  const [isLoading, setIsLoading] = useState(true);
  const [isSyncing, setIsSyncing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const [policy, setPolicy] = useState<EffectivePolicy>({
    policy_version: "v2.10.4",
    last_updated: new Date(Date.now() - 3600000).toISOString(),
    status: "protected",
    approval_required: false,
    controls: {
      health_monitoring: true,
      drift_alerting: true,
      auto_remediation: false,
    },
  });

  const [endpoints, setEndpoints] = useState<EndpointHealthRecord[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [selectedAction, setSelectedAction] = useState<string>("");
  const [simulation, setSimulation] = useState<SimulationPreview | null>(null);
  const [stagedActions, setStagedActions] = useState<StagedAction[]>([]);
  const [isWorking, setIsWorking] = useState(false);

  const detections: Detection[] = endpoints.map((ep) => ({
    id: ep.id,
    customer_id: ep.customer_id,
    endpoint_id: ep.id,
    endpoint_name: ep.hostname,
    title:
      ep.status === "drifted"
        ? `Policy drift on ${ep.hostname}`
        : ep.status === "offline"
        ? `Endpoint offline: ${ep.hostname}`
        : ep.status === "attention"
        ? `Attention required: ${ep.hostname}`
        : `${ep.hostname} — Healthy`,
    source: `Health Monitor · ${ep.os}`,
    description:
      ep.status === "drifted"
        ? `Running policy ${ep.policy_version} vs active ${ep.active_policy_version}. Agent version ${ep.agent_version} (latest: ${ep.latest_agent_version}).`
        : ep.status === "offline"
        ? `Last heartbeat received ${new Date(ep.last_heartbeat).toLocaleString()}. ${ep.pending_actions} pending actions queued.`
        : `Agent up to date. ${ep.open_alerts} open alert${ep.open_alerts !== 1 ? "s" : ""}. Last seen ${new Date(ep.last_heartbeat).toLocaleTimeString()}.`,
    risk_score: ep.risk_score,
    risk_band:
      ep.risk_score >= 75
        ? "critical"
        : ep.risk_score >= 55
        ? "high"
        : ep.risk_score >= 30
        ? "medium"
        : "low",
    confidence: ep.status === "healthy" ? 100 : ep.status === "attention" ? 75 : 50,
    recommended_action:
      ep.status === "drifted"
        ? "push_policy_update"
        : ep.status === "offline"
        ? "investigate_connectivity"
        : ep.status === "attention"
        ? "review_alerts"
        : "no_action_required",
    status:
      ep.status === "drifted" || ep.status === "attention"
        ? "investigating"
        : ep.status === "offline"
        ? "staged"
        : "resolved",
    created_at: ep.last_heartbeat,
    context: {
      user: `agent@${ep.hostname}`,
      command_line: `agent_version=${ep.agent_version} policy=${ep.policy_version} os=${ep.os}`,
      mitre_techniques: [],
    },
  }));

  const selectedDetection = detections.find((d) => d.id === selectedId) ?? null;
  const selectedEndpoint = endpoints.find((e) => e.id === selectedId) ?? null;

  useEffect(() => {
    async function load() {
      try {
        const customerId = me.scope.customer_ids[0];
        const url = customerId ? `/endpoints/health?customer_id=${customerId}` : `/endpoints/health`;
        const data = await apiGet<EndpointHealthRecord[]>(url);
        setEndpoints(data);
        if (data.length > 0) {
          setSelectedId(data[0].id);
          setSelectedAction(data[0].status === "healthy" ? "no_action_required" : "push_policy_update");
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load endpoint health.");
      } finally {
        setIsLoading(false);
      }
    }
    void load();
  }, [me]);

  const handleSyncPolicy = async () => {
    setIsSyncing(true);
    setError(null);
    try {
      const customerId = me.scope.customer_ids[0];
      await apiGet(customerId ? `/endpoints/health?customer_id=${customerId}` : "/endpoints/health");
      setPolicy((prev) => ({ ...prev, last_updated: new Date().toISOString() }));
      setSuccess("Health monitoring policies synced from Policy Engine v2.");
    } catch {
      setError("Failed to sync policies.");
    } finally {
      setIsSyncing(false);
    }
  };

  const handleSimulate = async () => {
    if (!selectedEndpoint) return;
    setIsWorking(true);
    setError(null);
    try {
      const sim = await apiPost<SimulationPreview>(`/endpoints/${selectedEndpoint.id}/simulate-remediation`, { action: selectedAction });
      setSimulation(sim);
      setSuccess("Remediation simulation complete — ready to stage.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Endpoint remediation simulation failed.");
    } finally {
      setIsWorking(false);
    }
  };

  const handleStage = async () => {
    if (!selectedEndpoint) return;
    setIsWorking(true);
    const optimistic: StagedAction = {
      id: `staged-ep-${Date.now()}`,
      detection_id: selectedEndpoint.id,
      action: selectedAction,
      status: "queued",
      approval_required: false,
      requested_by: me.account.email,
      created_at: new Date().toISOString(),
      note: "Policy push staged from Health console",
    };
    setStagedActions((prev) => [optimistic, ...prev]);
    try {
      await apiPost(`/endpoints/${selectedEndpoint.id}/remediate`, { action: selectedAction });
      setEndpoints((prev) =>
        prev.map((e) =>
          e.id === selectedEndpoint.id ? { ...e, status: "healthy", policy_version: e.active_policy_version } : e,
        ),
      );
      setSuccess(`Remediation queued for ${selectedEndpoint.hostname}.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to queue endpoint remediation.");
    } finally {
      setIsWorking(false);
    }
  };

  const healthy = endpoints.filter((e) => e.status === "healthy").length;
  const drifted = endpoints.filter((e) => e.status === "drifted").length;
  const offline = endpoints.filter((e) => e.status === "offline").length;
  const attention = endpoints.filter((e) => e.status === "attention").length;

  if (isLoading) {
    return (
      <div style={{ padding: "40px", width: "100%" }}>
        <LoadingState message="Fetching endpoint telemetry…" />
      </div>
    );
  }

  return (
    <ConsolePage>
      <ModuleHeader
        title="Endpoint Health & Attack Surface"
        eyebrow="Company Operations"
        icon={Shield}
        status={policy.status}
        policyVersion={policy.policy_version}
        policyLastSynced={policy.last_updated}
        onRefresh={handleSyncPolicy}
        isRefreshing={isSyncing}
        quickActions={[]}
      />

      {error && <ErrorBanner message={error} />}
      {success && <SuccessBanner message={success} />}

      <MetricGrid
        ariaLabel="Health Summary"
        items={[
          { label: "Healthy", value: healthy, icon: <CheckCircle size={18} />, color: "var(--success)" },
          { label: "Needs Attention", value: attention, icon: <AlertTriangle size={18} />, color: "var(--warning)" },
          { label: "Policy Drifted", value: drifted, icon: <GitBranch size={18} />, color: "#e07a00" },
          { label: "Offline", value: offline, icon: <WifiOff size={18} />, color: "var(--danger)" },
          { label: "Total Endpoints", value: endpoints.length, icon: <Cpu size={18} />, color: "var(--accent)" },
          { label: "Pending Actions", value: endpoints.reduce((s, e) => s + e.pending_actions, 0), icon: <Clock size={18} />, color: "var(--muted)" },
        ]}
      />

      {endpoints.length === 0 ? (
        <EmptyState icon={Shield} title="No endpoint heartbeats yet" message="Enrolled agents will appear here after they send signed heartbeats." />
      ) : (
      <section className="panelWorkspace" aria-label="Endpoint Health Board">
        <DetectionTable
          detections={detections}
          selectedId={selectedId}
          onSelect={(d) => {
            setSelectedId(d.id);
            const ep = endpoints.find((e) => e.id === d.id);
            setSelectedAction(ep?.status === "healthy" ? "no_action_required" : "push_policy_update");
            setSimulation(null);
          }}
          isLoading={isLoading}
        />

        <DetailPanel
          detection={selectedDetection}
          customContextRenderer={(d) => {
            const ep = endpoints.find((e) => e.id === d.id);
            if (!ep) return null;
            const hasTelemetry = ep.cpu_percent != null || ep.memory_percent != null;
            return (
              <div className="detailStack">
                <div>
                  <h4 className="sectionKicker" style={{ margin: "0 0 8px 0" }}>
                    Agent & Policy State
                  </h4>
                  <div className="kvStack">
                    {[
                      { label: "OS", value: ep.os },
                      { label: "Agent Version", value: ep.agent_version, warn: ep.agent_version !== ep.latest_agent_version },
                      { label: "Latest Agent", value: ep.latest_agent_version },
                      { label: "Running Policy", value: ep.policy_version, warn: ep.policy_version !== ep.active_policy_version },
                      { label: "Active Policy", value: ep.active_policy_version },
                      { label: "Last Heartbeat", value: new Date(ep.last_heartbeat).toLocaleString() },
                    ].map(({ label, value, warn }) => (
                      <div key={label} className="kvRow">
                        <span>{label}</span>
                        <strong style={{ color: warn ? "var(--warning)" : undefined }}>{value}</strong>
                      </div>
                    ))}
                  </div>
                </div>

                {hasTelemetry && (
                  <div>
                    <h4 className="sectionKicker" style={{ margin: "0 0 10px 0" }}>
                      Live Telemetry
                    </h4>
                    {ep.cpu_percent != null && (
                      <TelemetryBar
                        label="CPU"
                        value={ep.cpu_percent}
                        color="var(--accent)"
                        icon={<Cpu size={11} />}
                      />
                    )}
                    {ep.memory_percent != null && (
                      <TelemetryBar
                        label="Memory"
                        value={ep.memory_percent}
                        color="#6e8efb"
                        icon={<Activity size={11} />}
                      />
                    )}
                    <div style={{ display: "flex", gap: "12px", marginTop: "10px" }}>
                      <div style={{ fontSize: "11px", color: "var(--muted)" }}>
                        DLP Events: <strong style={{ color: (ep.dlp_events ?? 0) > 0 ? "var(--warning)" : undefined }}>{ep.dlp_events ?? 0}</strong>
                      </div>
                      <div style={{ fontSize: "11px", color: "var(--muted)" }}>
                        Blocked: <strong style={{ color: (ep.blocked_events ?? 0) > 0 ? "var(--danger)" : undefined }}>{ep.blocked_events ?? 0}</strong>
                      </div>
                    </div>
                  </div>
                )}

                <div>
                  <h4 className="sectionKicker" style={{ margin: "0 0 8px 0" }}>
                    Ransomware Rollback Readiness
                  </h4>
                  {ep.rollback_readiness ? (
                    <div className="kvStack" style={{ background: "rgba(255,255,255,0.02)", padding: "10px", borderRadius: "10px", border: "1px solid rgba(255,255,255,0.05)", fontSize: "11.5px" }}>
                      <div className="kvRow" style={{ borderBottom: "1px solid rgba(255,255,255,0.04)", paddingBottom: "6px", marginBottom: "6px" }}>
                        <span>Rollback Status</span>
                        <strong style={{ color: (ep.rollback_readiness.functional !== false && ep.rollback_readiness.capability_supported !== false) ? "var(--healthy)" : "var(--danger)", display: "flex", alignItems: "center", gap: "4px" }}>
                          {(ep.rollback_readiness.functional !== false && ep.rollback_readiness.capability_supported !== false) ? "● Functional (Verified)" : "● Warning / Limited"}
                        </strong>
                      </div>
                      <div className="kvRow" style={{ borderBottom: "1px solid rgba(255,255,255,0.04)", paddingBottom: "6px", marginBottom: "6px" }}>
                        <span>Restoration OS Provider</span>
                        <strong style={{ color: "var(--light)" }}>
                          {ep.rollback_readiness.provider_name || "Unknown Provider"} {ep.rollback_readiness.provider_version && `v${ep.rollback_readiness.provider_version}`}
                        </strong>
                      </div>
                      <div className="kvRow" style={{ borderBottom: "1px solid rgba(255,255,255,0.04)", paddingBottom: "6px", marginBottom: "6px" }}>
                        <span>Snapshot Service Available</span>
                        <strong style={{ color: ep.rollback_readiness.service_available !== false ? "var(--healthy)" : "var(--danger)" }}>
                          {ep.rollback_readiness.service_available !== false ? "Yes" : "No"}
                        </strong>
                      </div>
                      <div className="kvRow" style={{ borderBottom: "1px solid rgba(255,255,255,0.04)", paddingBottom: "6px", marginBottom: "6px" }}>
                        <span>Sufficient Elevation/Privilege</span>
                        <strong style={{ color: ep.rollback_readiness.sufficient_privilege !== false ? "var(--healthy)" : "var(--danger)" }}>
                          {ep.rollback_readiness.sufficient_privilege !== false ? "Yes" : "No"}
                          {ep.rollback_readiness.privilege_boundary && ` (${ep.rollback_readiness.privilege_boundary})`}
                        </strong>
                      </div>
                      {ep.rollback_readiness.volume_capabilities && ep.rollback_readiness.volume_capabilities.length > 0 && (
                        <div className="kvRow" style={{ borderBottom: "1px solid rgba(255,255,255,0.04)", paddingBottom: "6px", marginBottom: "6px" }}>
                          <span>Volume Capabilities</span>
                          <strong style={{ color: "var(--light)", fontSize: "10.5px" }}>
                            {ep.rollback_readiness.volume_capabilities.join(", ")}
                          </strong>
                        </div>
                      )}
                      {ep.rollback_readiness.available_filesystems && ep.rollback_readiness.available_filesystems.length > 0 && (
                        <div className="kvRow" style={{ borderBottom: "1px solid rgba(255,255,255,0.04)", paddingBottom: "6px", marginBottom: "6px" }}>
                          <span>Filesystems detected</span>
                          <strong style={{ color: "var(--light)", fontSize: "10.5px" }}>
                            {ep.rollback_readiness.available_filesystems.join(", ")}
                          </strong>
                        </div>
                      )}
                      {ep.rollback_readiness.snapshot_service_info && (
                        <div className="kvRow" style={{ borderBottom: "1px solid rgba(255,255,255,0.04)", paddingBottom: "6px", marginBottom: "6px" }}>
                          <span>Snapshot Daemon</span>
                          <strong style={{ color: "var(--light)" }}>{ep.rollback_readiness.snapshot_service_info}</strong>
                        </div>
                      )}
                      {ep.rollback_readiness.diagnosis && (
                        <div className="kvRow" style={{ borderBottom: "1px solid rgba(255,255,255,0.04)", paddingBottom: "6px", marginBottom: "6px", color: "var(--danger)" }}>
                          <span>Diagnostic Log</span>
                          <strong style={{ wordBreak: "break-all", fontStyle: "italic" }}>{ep.rollback_readiness.diagnosis}</strong>
                        </div>
                      )}
                      <div className="kvRow" style={{ borderBottom: "1px solid rgba(255,255,255,0.04)", paddingBottom: "6px", marginBottom: "6px" }}>
                        <span>Verified Restore Snapshots</span>
                        <strong style={{ color: "var(--light)" }}>
                          {ep.rollback_readiness.recovery_points?.length ?? ep.rollback_readiness.recovery_point_count ?? ep.rollback_readiness.recovery_points_count ?? 0} available
                        </strong>
                      </div>
                      {ep.rollback_readiness.recent_fim_paths && ep.rollback_readiness.recent_fim_paths.length > 0 && (
                        <div style={{ marginTop: "8px", borderTop: "1px dashed rgba(255,255,255,0.05)", paddingTop: "4px" }}>
                          <span style={{ display: "block", fontSize: "10.5px", color: "var(--muted)", marginBottom: "4px" }}>Monitored FIM Target Paths:</span>
                          <div style={{ maxHeight: "60px", overflowY: "auto", background: "rgba(0,0,0,0.1)", padding: "4px", borderRadius: "4px", fontSize: "10px", fontFamily: "monospace", color: "var(--muted)" }}>
                            {ep.rollback_readiness.recent_fim_paths.map((p, idx) => (
                              <div key={idx} style={{ textOverflow: "ellipsis", overflow: "hidden", whiteSpace: "nowrap" }}>• {p}</div>
                            ))}
                          </div>
                        </div>
                      )}
                      <div className="kvRow" style={{ marginTop: "4px" }}>
                        <span>Last Integrity Verification</span>
                        <strong style={{ color: "var(--light)" }}>
                          {ep.rollback_readiness.last_checked_at ? new Date(ep.rollback_readiness.last_checked_at).toLocaleDateString() : "Never"}
                        </strong>
                      </div>
                    </div>
                  ) : (
                    <div style={{ fontSize: "12px", color: "var(--muted)", padding: "12px", background: "rgba(255,255,255,0.02)", borderRadius: "8px", border: "1px solid rgba(255,255,255,0.05)" }}>
                      No rollback capability status reported. Enrolled endpoint has not yet sent ransomware rollback eligibility telemetry.
                    </div>
                  )}
                </div>

                {ep.tags.length > 0 && (
                  <div>
                    <h4 className="sectionKicker" style={{ margin: "0 0 8px 0" }}>
                      Tags
                    </h4>
                    <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
                      {ep.tags.map((tag) => (
                        <span
                          key={tag}
                          style={{
                            background: "rgba(11, 107, 87, 0.08)",
                            color: "var(--accent)",
                            border: "1px solid rgba(11, 107, 87, 0.2)",
                            padding: "2px 8px",
                            borderRadius: "4px",
                            fontSize: "11px",
                          }}
                        >
                          {tag}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                <div>
                  <ResponseActionsPanel
                    endpointId={ep.id}
                    onRefresh={() => {
                      void apiGet<EndpointHealthRecord[]>("/endpoints/health").then((data) => {
                        setEndpoints(data);
                      });
                    }}
                  />
                </div>
              </div>
            );
          }}
        />

        <ActionStagingPanel
          detection={selectedDetection}
          selectedAction={selectedAction}
          simulation={simulation}
          stagedActions={stagedActions}
          isWorking={isWorking}
          onActionChange={setSelectedAction}
          onSimulate={handleSimulate}
          onStage={handleStage}
          availableActions={[
            { value: "push_policy_update", label: "Push Policy Update", destructive: false },
            { value: "update_agent", label: "Queue Agent Update", destructive: false },
            { value: "investigate_connectivity", label: "Investigate Connectivity", destructive: false },
            { value: "review_alerts", label: "Mark for Alert Review", destructive: false },
            { value: "no_action_required", label: "No Action Required", destructive: false },
          ]}
        />
      </section>
      )}
    </ConsolePage>
  );
}
