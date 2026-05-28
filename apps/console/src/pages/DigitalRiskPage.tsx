import React, { useState, useEffect, useMemo, useCallback } from "react";
import { ShieldCheck, Plus, AlertTriangle, Search, Eye } from "lucide-react";
import { ModuleHeader } from "../components/protection/ModuleHeader";
import { DetectionTable } from "../components/protection/DetectionTable";
import { DetailPanel } from "../components/protection/DetailPanel";
import { ActionStagingPanel } from "../components/protection/ActionStagingPanel";
import { LoadingState } from "../components/protection/EmptyState";
import { Detection, StagedAction, SimulationPreview, EffectivePolicy, DetectionStatus } from "../components/protection/types";
import { ConsolePage, ErrorBanner, MetricGrid, SuccessBanner } from "../components";
import { apiGet, apiPost, type DRPFinding, type MeResponse, type RiskBand } from "../api";

const DRP_SEVERITY_TO_BAND: Record<string, RiskBand> = {
  low: "low",
  medium: "medium",
  high: "high",
  critical: "critical",
};

const DRP_STATUS_TO_DETECTION: Record<string, DetectionStatus> = {
  new: "new",
  reviewing: "investigating",
  validated: "investigating",
  confirmed: "investigating",
  false_positive: "resolved",
};

function findingToDetection(finding: DRPFinding): Detection {
  const destructive = finding.severity === "high" || finding.severity === "critical";
  const recommended =
    finding.status === "false_positive"
      ? "mark_reviewed"
      : destructive
        ? "request_takedown"
        : "validate";
  return {
    id: finding.id,
    customer_id: finding.customer_id,
    endpoint_id: finding.asset_id,
    endpoint_name: finding.asset_display_name,
    title: finding.title,
    source: `DRP · ${finding.source}`,
    description: finding.summary,
    risk_score: finding.risk_score,
    risk_band: DRP_SEVERITY_TO_BAND[finding.severity] ?? "medium",
    confidence: finding.confidence_score,
    recommended_action: recommended,
    status: DRP_STATUS_TO_DETECTION[finding.status] ?? "new",
    created_at: finding.created_at,
    context: {
      user: finding.finding_type,
      command_line:
        finding.evidence_links?.[0] ||
        finding.screenshot_url ||
        finding.asset_display_name,
      mitre_techniques: [],
    },
  };
}

export function DigitalRiskPage({ me }: { me?: MeResponse }) {
  const [isLoading, setIsLoading] = useState(true);
  const [isSyncing, setIsSyncing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const [policy, setPolicy] = useState<EffectivePolicy>({
    policy_version: "v3.4.1",
    last_updated: new Date(Date.now() - 3600000).toISOString(),
    status: "protected",
    approval_required: true,
    controls: {
      "dark_web_monitoring": true,
      "brand_impersonation_alerts": true,
      "typosquat_detection": true,
      "executive_exposure_tracking": true,
    },
  });

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

  const loadFindings = useCallback(
    async (silent = false) => {
      if (!silent) setIsLoading(true);
      try {
        const rows = await apiGet<DRPFinding[]>(`/drp/findings${scopedQuery}`);
        const detections = rows.map(findingToDetection);
        setDetections(detections);
        if (detections.length > 0) {
          setSelectedId((current) => current ?? detections[0].id);
          setSelectedAction((current) => current || detections[0].recommended_action);
        } else {
          setSelectedId(null);
        }
        setError(null);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load DRP findings.");
      } finally {
        if (!silent) setIsLoading(false);
      }
    },
    [scopedQuery],
  );

  useEffect(() => {
    void loadFindings();
  }, [loadFindings]);

  const selectedDetection = detections.find((d) => d.id === selectedId) || null;

  const handleSyncPolicy = async () => {
    setIsSyncing(true);
    setError(null);
    try {
      await loadFindings(true);
      setPolicy((prev) => ({
        ...prev,
        last_updated: new Date().toISOString(),
      }));
      setSuccess("Digital risk feeds synchronized.");
    } catch {
      setError("Failed to fetch fresh DRP assets.");
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
      const destructive = selectedAction === "request_takedown";
      const simulated: SimulationPreview = {
        id: `sim-run-${Date.now()}`,
        detection_id: selectedDetection.id,
        action: selectedAction,
        destructive,
        approval_required: policy.approval_required || destructive,
        affected_systems: 0,
        estimated_impact: [
          `Action: ${selectedAction.replaceAll("_", " ")} will be applied to ${selectedDetection.endpoint_name}.`,
          destructive
            ? "Dispatches a takedown request to the hosting provider/registrar."
            : "Marks the finding as validated and records analyst sign-off.",
        ],
        evidence_controls: ["nist-csf-2.0:ID.RM", "iso27001-2022:A.5.14"],
        created_at: new Date().toISOString(),
      };
      setSimulation(simulated);
      setSuccess("Takedown simulation preview generated.");
    } catch {
      setError("Simulation trigger failed.");
    } finally {
      setIsWorking(false);
    }
  };

  const stageAction = async (confirmed = false) => {
    if (!selectedDetection) return;

    const isDestructive = selectedAction === "request_takedown";
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
      if (selectedAction === "request_takedown") {
        await apiPost(`/drp/findings/${selectedDetection.id}/takedown`, {});
      } else {
        await apiPost(`/drp/findings/${selectedDetection.id}/validate`, {});
      }
      setStagedActions((current) =>
        current.map((s) => (s.id === optimistic.id ? { ...s, status: "approved" } : s)),
      );
      setSuccess(`Action '${selectedAction.replaceAll("_", " ")}' applied to ${selectedDetection.endpoint_name}.`);
      void loadFindings(true);
    } catch (err) {
      setStagedActions((current) =>
        current.map((s) => (s.id === optimistic.id ? { ...s, status: "failed" } : s)),
      );
      setError(err instanceof Error ? err.message : "Failed to dispatch DRP action.");
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
    return (
      <div style={{ padding: "40px", width: "100%" }}>
        <LoadingState message="Retrieving digital risk intelligence from global feeds..." />
      </div>
    );
  }

  return (
    <ConsolePage>
      <ModuleHeader
        title="Digital Risk Protection (DRP)"
        eyebrow="External Risk Module"
        icon={Eye}
        status={policy.status}
        policyVersion={policy.policy_version}
        policyLastSynced={policy.last_updated}
        policyMode="Active Monitoring"
        onRefresh={handleSyncPolicy}
        isRefreshing={isSyncing}
        quickActions={[
          {
            label: "Add Monitored Asset",
            icon: Plus,
            onClick: () => {
              setSuccess("Asset intake wizard initialized. (Placeholder)");
            },
            variant: "primary",
            disabled: isWorking,
          },
        ]}
      />

      {error && <ErrorBanner message={error} />}
      {success && <SuccessBanner message={success} />}

      <MetricGrid
        ariaLabel="Digital Risk Summary Statistics"
        items={[
          { label: "Monitored Brands", value: "8 Active", icon: <ShieldCheck size={20} />, color: "var(--accent)" },
          { label: "Active Findings", value: `${detections.filter((d) => d.status === "new").length} Pending`, icon: <Search size={20} />, color: "var(--warning)" },
          { label: "External Risk Score", value: "85 / 100", icon: <AlertTriangle size={20} />, color: "var(--warning)" },
        ]}
      />

      <section className="panelWorkspace" aria-label="Digital Risk Console">
        <DetectionTable
          detections={detections}
          selectedId={selectedId}
          onSelect={(d) => {
            setSelectedId(d.id);
            handleActionChange(d.recommended_action);
          }}
          isLoading={isLoading}
          panelTitle="Digital Risk Exposures"
          panelSubtitle="Brand, data leak, and threat intelligence alerts"
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
          availableActions={[
            { value: "request_takedown", label: "Request Takedown via Provider", destructive: true },
            { value: "mark_reviewed", label: "Mark as Reviewed / Safe", destructive: false },
            { value: "dismiss_alert", label: "Dismiss warning manually", destructive: false },
          ]}
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
            <h2 style={{ fontSize: "14px", margin: 0 }}>Monitored Executives</h2>
            <span style={{ fontSize: "11px", color: "var(--muted)" }}>Profiles tracked across social media</span>
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: "8px", fontSize: "12px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", background: "rgba(11, 107, 87, 0.01)", padding: "8px", borderRadius: "6px", border: "1px solid var(--line)" }}>
              <code>Jane Doe (CEO)</code>
              <span style={{ color: "var(--muted)" }}>LinkedIn, X, GitHub</span>
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", background: "rgba(11, 107, 87, 0.01)", padding: "8px", borderRadius: "6px", border: "1px solid var(--line)" }}>
              <code>John Smith (CISO)</code>
              <span style={{ color: "var(--muted)" }}>LinkedIn, GitHub, HackerNews</span>
            </div>
          </div>
        </article>

        <article className="panel">
          <div className="panelHeader" style={{ borderBottom: "1px solid var(--line)", paddingBottom: "10px", marginBottom: "12px" }}>
            <h2 style={{ fontSize: "14px", margin: 0 }}>DRP Engine Toggles</h2>
            <span style={{ fontSize: "11px", color: "var(--muted)" }}>Effective Digital Risk parameters</span>
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
              You are staging an action (<strong>{confirmRequest.action.replaceAll("_", " ")}</strong>) targeting an external entity (<strong>{confirmRequest.detection.endpoint_name}</strong>). This will submit automated legal takedown notices to third-party providers. Proceed with caution.
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
    </ConsolePage>
  );
}
