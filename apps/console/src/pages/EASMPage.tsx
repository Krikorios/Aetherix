import React, { useState, useEffect, useMemo, useCallback } from "react";
import { Plus, AlertTriangle, Globe2, ScanEye } from "lucide-react";
import { ModuleHeader } from "../components/protection/ModuleHeader";
import { DetectionTable } from "../components/protection/DetectionTable";
import { DetailPanel } from "../components/protection/DetailPanel";
import { ActionStagingPanel } from "../components/protection/ActionStagingPanel";
import { LoadingState } from "../components/protection/EmptyState";
import { Detection, StagedAction, SimulationPreview, EffectivePolicy, DetectionStatus } from "../components/protection/types";
import { ConsolePage, ErrorBanner, MetricGrid, SuccessBanner } from "../components";
import { apiGet, apiPost, type EASMExposure, type MeResponse, type RiskBand } from "../api";

const SEVERITY_TO_BAND: Record<string, RiskBand> = {
  low: "low",
  medium: "medium",
  high: "high",
  critical: "critical",
};

const EASM_STATUS_TO_DETECTION: Record<string, DetectionStatus> = {
  new: "new",
  investigating: "investigating",
  confirmed: "investigating",
  remediated: "resolved",
  false_positive: "resolved",
};

const EASM_ACTIONS = [
  { value: "investigate", label: "Open Investigation", destructive: false },
  { value: "remediate", label: "Mark Remediated", destructive: true },
  { value: "mark_reviewed", label: "Mark as Reviewed / Accept Risk", destructive: false },
];

function exposureToDetection(exposure: EASMExposure): Detection {
  const portInfo = exposure.open_ports.length ? ` (ports: ${exposure.open_ports.join(", ")})` : "";
  const recommended =
    exposure.status === "remediated" || exposure.status === "false_positive"
      ? "mark_reviewed"
      : exposure.severity === "high" || exposure.severity === "critical"
        ? "remediate"
        : "investigate";
  return {
    id: exposure.id,
    customer_id: exposure.customer_id,
    endpoint_id: exposure.asset_id,
    endpoint_name: exposure.asset_display_name || exposure.fqdn || exposure.ip_address || "External asset",
    title: exposure.title,
    source: `EASM · ${exposure.exposure_type.replaceAll("_", " ")}`,
    description: exposure.summary,
    risk_score: exposure.risk_score,
    risk_band: SEVERITY_TO_BAND[exposure.severity] ?? "medium",
    confidence: exposure.confidence_score,
    recommended_action: recommended,
    status: EASM_STATUS_TO_DETECTION[exposure.status] ?? "new",
    created_at: exposure.created_at,
    context: {
      user: exposure.cloud_provider ? `Cloud · ${exposure.cloud_provider}` : "External Surface",
      command_line:
        [exposure.fqdn, exposure.ip_address].filter(Boolean).join(" · ") + portInfo || exposure.asset_display_name,
      mitre_techniques: [],
    },
  };
}

export function EASMPage({ me, embedded = false }: { me?: MeResponse; embedded?: boolean }) {
  const [isLoading, setIsLoading] = useState(true);
  const [isSyncing, setIsSyncing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const [policy, setPolicy] = useState<EffectivePolicy>(() => ({
    policy_version: "v2.1.0",
    last_updated: new Date(Date.now() - 3600000).toISOString(),
    status: "protected",
    approval_required: true,
    controls: {
      "continuous_port_scanning": true,
      "certificate_lifecycle_monitoring": true,
      "cloud_storage_exposure": true,
      "subdomain_takeover_prevention": true,
    },
  }));

  const [detections, setDetections] = useState<Detection[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [selectedAction, setSelectedAction] = useState<string>("");
  const [simulation, setSimulation] = useState<SimulationPreview | null>(null);
  const [stagedActions, setStagedActions] = useState<StagedAction[]>([]);
  const [isWorking, setIsWorking] = useState(false);
  const [confirmRequest, setConfirmRequest] = useState<{ detection: Detection; action: string } | null>(null);

  const customerId = me?.scope?.customer_ids?.[0] ?? null;
  const partnerId = me?.scope?.partner_ids?.[0] ?? null;

  const scopedQuery = useMemo(() => {
    const params = new URLSearchParams();
    if (customerId) params.set("customer_id", customerId);
    else if (partnerId) params.set("partner_id", partnerId);
    const raw = params.toString();
    return raw ? `?${raw}` : "";
  }, [customerId, partnerId]);

  const loadExposures = useCallback(
    async (silent = false) => {
      if (!silent) setIsLoading(true);
      try {
        const rows = await apiGet<EASMExposure[]>(`/easm/exposures${scopedQuery}`);
        const detections = rows.map(exposureToDetection);
        setDetections(detections);
        if (detections.length > 0) {
          setSelectedId((current) => current ?? detections[0].id);
          setSelectedAction((current) => current || detections[0].recommended_action);
        } else {
          setSelectedId(null);
        }
        setError(null);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load EASM exposures.");
      } finally {
        if (!silent) setIsLoading(false);
      }
    },
    [scopedQuery],
  );

  useEffect(() => {
    queueMicrotask(() => void loadExposures());
  }, [loadExposures]);

  const selectedDetection = detections.find((d) => d.id === selectedId) || null;

  const handleSyncPolicy = async () => {
    setIsSyncing(true);
    setError(null);
    try {
      await loadExposures(true);
      setPolicy((prev) => ({
        ...prev,
        last_updated: new Date().toISOString(),
      }));
      setSuccess("EASM exposures refreshed from continuous discovery.");
    } catch {
      setError("Failed to fetch fresh EASM asset inventory.");
    } finally {
      setIsSyncing(false);
    }
  };

  const simulateAction = async () => {
    if (!selectedDetection) return;
    setIsWorking(true);
    setSuccess(null);
    setError(null);
    try {
      const destructive = selectedAction === "remediate";
      const simulated: SimulationPreview = {
        id: `sim-run-${Date.now()}`,
        detection_id: selectedDetection.id,
        action: selectedAction,
        destructive,
        approval_required: policy.approval_required || destructive,
        affected_systems: 1,
        estimated_impact: [
          `Action: ${selectedAction.replaceAll("_", " ")} will be applied to ${selectedDetection.endpoint_name}.`,
          destructive
            ? "Marks exposure as remediated and emits an evidence event."
            : selectedAction === "investigate"
              ? "Moves the exposure into the active investigation queue."
              : "Records analyst acceptance of risk; no state change to upstream asset.",
        ],
        evidence_controls: ["nist-csf-2.0:PR.AC", "iso27001-2022:A.8.20"],
        created_at: new Date().toISOString(),
      };
      setSimulation(simulated);
      setSuccess("Remediation simulation preview generated.");
    } catch {
      setError("Simulation trigger failed.");
    } finally {
      setIsWorking(false);
    }
  };

  const stageAction = async (confirmed = false) => {
    if (!selectedDetection) return;

    const isDestructive = selectedAction === "remediate";
    if (isDestructive && !confirmed) {
      setConfirmRequest({ detection: selectedDetection, action: selectedAction });
      return;
    }

    setIsWorking(true);
    setSuccess(null);
    setError(null);

    const optimistic: StagedAction = {
      id: `staged-${Date.now()}`,
      detection_id: selectedDetection.id,
      action: selectedAction,
      status: policy.approval_required && isDestructive ? "awaiting_approval" : "queued",
      approval_required: policy.approval_required && isDestructive,
      requested_by: me?.account?.email ?? "operator",
      created_at: new Date().toISOString(),
      note: simulation ? "Simulation verified prior to action" : "Direct dispatch",
    };

    setStagedActions((current) => [optimistic, ...current]);
    setDetections((current) =>
      current.map((d) => (d.id === selectedDetection.id ? { ...d, status: "staged" } : d)),
    );

    try {
      if (selectedAction === "investigate") {
        await apiPost(`/easm/exposures/${selectedDetection.id}/investigate`, {});
      } else if (selectedAction === "remediate") {
        await apiPost(`/easm/exposures/${selectedDetection.id}/remediate`, {});
      } else if (selectedAction !== "mark_reviewed") {
        throw new Error("Unsupported EASM action selected.");
      }
      setStagedActions((current) =>
        current.map((s) => (s.id === optimistic.id ? { ...s, status: "approved" } : s)),
      );
      setSuccess(`Action '${selectedAction.replaceAll("_", " ")}' applied to ${selectedDetection.endpoint_name}.`);
      void loadExposures(true);
    } catch (err) {
      setStagedActions((current) =>
        current.map((s) => (s.id === optimistic.id ? { ...s, status: "failed" } : s)),
      );
      setError(err instanceof Error ? err.message : "Failed to dispatch EASM action.");
    } finally {
      setIsWorking(false);
      setConfirmRequest(null);
    }
  };

  const handleActionChange = (action: string) => {
    setSelectedAction(action);
    setSimulation(null);
  };

  if (isLoading) {
    const loadingState = (
      <div style={{ padding: "40px", width: "100%" }}>
        <LoadingState message="Discovering external assets and probing for exposures..." />
      </div>
    );
    return embedded ? loadingState : <ConsolePage>{loadingState}</ConsolePage>;
  }

  const content = (
    <>
      <ModuleHeader
        title="External Attack Surface (EASM)"
        eyebrow="Asset Discovery Module"
        icon={Globe2}
        status={policy.status}
        policyVersion={policy.policy_version}
        policyLastSynced={policy.last_updated}
        policyMode="Continuous Discovery"
        onRefresh={handleSyncPolicy}
        isRefreshing={isSyncing}
        quickActions={[
          {
            label: "Add Monitored Asset",
            icon: Plus,
            onClick: () => {
              setSuccess("Seed domain/IP addition modal triggered. (Placeholder)");
            },
            variant: "primary",
            disabled: isWorking,
          },
        ]}
      />

      {error && <ErrorBanner message={error} />}
      {success && <SuccessBanner message={success} />}

      <MetricGrid
        ariaLabel="EASM Summary Statistics"
        items={[
          { label: "Tracked Domains & IPs", value: "142 Assets", icon: <Globe2 size={20} />, color: "var(--accent)" },
          { label: "Active Exposures", value: `${detections.filter((d) => d.status === "new").length} Pending`, icon: <ScanEye size={20} />, color: "var(--warning)" },
          { label: "Perimeter Risk Score", value: "78 / 100", icon: <AlertTriangle size={20} />, color: "var(--warning)" },
        ]}
      />

      <section className="panelWorkspace" aria-label="EASM Core Console">
        <DetectionTable
          detections={detections}
          selectedId={selectedId}
          onSelect={(d) => {
            setSelectedId(d.id);
            handleActionChange(d.recommended_action);
          }}
          isLoading={isLoading}
          panelTitle="Attack Surface Exposures"
          panelSubtitle="Discovered external assets and open vulnerabilities"
        />

        <DetailPanel detection={selectedDetection} />

        <ActionStagingPanel
          detection={selectedDetection}
          selectedAction={selectedAction}
          simulation={simulation}
          stagedActions={stagedActions}
          isWorking={isWorking}
          onActionChange={handleActionChange}
          onSimulate={simulateAction}
          onStage={() => stageAction()}
          availableActions={EASM_ACTIONS}
        />
      </section>

      <section
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))",
          gap: "16px",
          marginTop: "24px",
        }}
      >
        <article className="panel">
          <div className="panelHeader" style={{ borderBottom: "1px solid var(--line)", paddingBottom: "10px", marginBottom: "12px" }}>
            <h2 style={{ fontSize: "14px", margin: 0 }}>Seed Assets</h2>
            <span style={{ fontSize: "11px", color: "var(--muted)" }}>Root domains and IP blocks driving discovery</span>
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: "8px", fontSize: "12px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", background: "rgba(11, 107, 87, 0.01)", padding: "8px", borderRadius: "6px", border: "1px solid var(--line)" }}>
              <code>aetherix.com</code>
              <span style={{ color: "var(--muted)" }}>Primary Domain</span>
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", background: "rgba(11, 107, 87, 0.01)", padding: "8px", borderRadius: "6px", border: "1px solid var(--line)" }}>
              <code>198.51.100.0/24</code>
              <span style={{ color: "var(--muted)" }}>Corporate Subnet</span>
            </div>
          </div>
        </article>

        <article className="panel">
          <div className="panelHeader" style={{ borderBottom: "1px solid var(--line)", paddingBottom: "10px", marginBottom: "12px" }}>
            <h2 style={{ fontSize: "14px", margin: 0 }}>EASM Engine Config</h2>
            <span style={{ fontSize: "11px", color: "var(--muted)" }}>Active discovery modules</span>
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
            {Object.entries(policy.controls).map(([key, enabled]) => (
              <label key={key} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", cursor: "pointer", fontSize: "12px" }}>
                <span>{key.replaceAll("_", " ").toUpperCase()}</span>
                <input type="checkbox" checked={enabled} readOnly style={{ accentColor: "var(--accent)", cursor: "not-allowed" }} />
              </label>
            ))}
          </div>
        </article>
      </section>

      {confirmRequest && (
        <div
          style={{
            position: "fixed",
            inset: 0,
            background: "rgba(19, 32, 27, 0.6)",
            backdropFilter: "blur(2px)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 1000,
          }}
          role="presentation"
        >
          <section
            className="accountModal"
            role="dialog"
            aria-modal="true"
            aria-label="Confirm Impact-heavy Action"
            style={{
              background: "#fffef9",
              padding: "24px",
              borderRadius: "12px",
              border: "1px solid var(--line)",
              maxWidth: "460px",
              width: "100%",
              boxShadow: "0 10px 25px -5px rgba(0, 0, 0, 0.1), 0 8px 10px -6px rgba(0, 0, 0, 0.1)",
            }}
          >
            <h3 style={{ margin: "0 0 10px 0", fontSize: "18px", color: "var(--warning)" }}>Confirm External Action</h3>
            <p style={{ margin: "0 0 20px 0", fontSize: "13px", color: "var(--muted)", lineHeight: 1.5 }}>
              You are staging an action (<strong>{confirmRequest.action.replaceAll("_", " ")}</strong>) targeting a discovered asset (<strong>{confirmRequest.detection.endpoint_name}</strong>). This will push critical remediation tickets to infrastructure teams or attempt automated blocking if integrated. Proceed?
            </p>
            <div style={{ display: "flex", justifyContent: "flex-end", gap: "12px" }}>
              <button
                type="button"
                className="btnSecondary"
                onClick={() => setConfirmRequest(null)}
                style={{ cursor: "pointer" }}
              >
                Cancel
              </button>
              <button
                type="button"
                className="btnPrimary"
                onClick={() => stageAction(true)}
                style={{ cursor: "pointer" }}
              >
                Confirm & Dispatch
              </button>
            </div>
          </section>
        </div>
      )}
    </>
  );

  return embedded ? content : <ConsolePage>{content}</ConsolePage>;
}
