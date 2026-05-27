import React, { useState, useEffect } from "react";
import {
  Shield,
  AlertTriangle,
  CheckCircle,
  Clock,
  Cpu,
  WifiOff,
  GitBranch,
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
