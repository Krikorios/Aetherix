import React, { useState, useEffect, useMemo, useCallback } from "react";
import { ShieldCheck, RefreshCw, AlertTriangle, Clock, Globe } from "lucide-react";
import { ModuleHeader } from "../components/protection/ModuleHeader";
import { DetectionTable } from "../components/protection/DetectionTable";
import { DetailPanel } from "../components/protection/DetailPanel";
import { ActionStagingPanel } from "../components/protection/ActionStagingPanel";
import { LoadingState } from "../components/protection/EmptyState";
import { Detection, StagedAction, SimulationPreview, EffectivePolicy, DetectionStatus } from "../components/protection/types";
import { ConsolePage, ErrorBanner, MetricGrid, SuccessBanner } from "../components";

import {
  apiGet,
  apiPost,
  apiPatch,
  type MeResponse,
  type EffectivePolicyResponse,
  type SecurityAlert,
  type RiskBand,
} from "../api";

const WEB_KEYWORDS = ["web", "browser", "extension", "genai", "ai", "phish", "url", "upload", "paste"];

const SEVERITY_BAND: Record<string, RiskBand> = {
  low: "low",
  medium: "medium",
  high: "high",
  critical: "critical",
};

function isWebRelevant(alert: SecurityAlert): boolean {
  const haystack = [
    alert.category,
    alert.payload?.source,
    alert.payload?.detector,
    alert.payload?.module,
    alert.payload?.url,
    alert.payload?.destination,
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
  return WEB_KEYWORDS.some((kw) => haystack.includes(kw));
}

function alertToDetection(alert: SecurityAlert): Detection {
  const payload = (alert.payload || {}) as Record<string, any>;
  const url = payload.url || payload.destination || payload.host || payload.domain || "";
  const score =
    alert.severity === "critical" ? 96 :
    alert.severity === "high" ? 88 :
    alert.severity === "medium" ? 68 : 42;
  const recommended =
    (alert.recommended_action || "").toLowerCase().replace(/\s+/g, "_") ||
    (alert.severity === "high" || alert.severity === "critical"
      ? "isolate_endpoint_browser"
      : "block_paste_action");
  const detStatus: DetectionStatus =
    alert.status === "resolved" || alert.status === "closed"
      ? "resolved"
      : alert.status === "acknowledged"
        ? "investigating"
        : "new";

  return {
    id: alert.id,
    customer_id: alert.customer_id,
    endpoint_id: alert.agent_id,
    endpoint_name: payload.endpoint_name || payload.hostname || alert.agent_id || "Unknown endpoint",
    title: payload.title || alert.category || "Web protection event",
    source: payload.source || "Web Protection Engine",
    description: alert.ai_summary || payload.description || "Web protection telemetry event recorded by the Aetherix agent.",
    risk_score: score,
    risk_band: SEVERITY_BAND[alert.severity] ?? "medium",
    confidence: Math.max(0, Math.min(100, alert.confidence ?? 90)),
    recommended_action: recommended,
    status: detStatus,
    created_at: alert.created_at,
    context: {
      user: payload.user || payload.username || "endpoint-user",
      command_line: url || payload.command_line || payload.process || "n/a",
      mitre_techniques: [],
    },
  };
}

export function WebProtectionPage({ me }: { me?: MeResponse }) {
  const [isLoading, setIsLoading] = useState(true);
  const [isSyncing, setIsSyncing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const [policy, setPolicy] = useState<EffectivePolicy>({
    policy_version: "v1.01.0",
    last_updated: new Date(Date.now() - 3600000).toISOString(),
    status: "protected",
    approval_required: false,
    controls: {
      "genai_guardrails": true,
      "sensitive_paste_upload_review": true,
      "url_reputation_anti_phishing": true,
      "browser_extension_enforcement": true,
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

  const loadData = useCallback(
    async (silent = false) => {
      if (!silent) setIsLoading(true);
      try {
        const policyRequest = apiGet<EffectivePolicyResponse>(`/policies/effective${scopedQuery}`).catch(() => null);
        const alertsRequest: Promise<SecurityAlert[]> = customerId
          ? apiGet<SecurityAlert[]>(`/customers/${customerId}/security-alerts`).catch(() => [])
          : Promise.resolve([]);

        const [effectivePolicy, alerts] = await Promise.all([policyRequest, alertsRequest]);

        if (effectivePolicy) {
          const modules = effectivePolicy.resolved_policy.modules ?? {};
          const genai = modules.web_protection?.genai_guardrails !== false;
          const paste = modules.web_protection?.sensitive_paste_review !== false;
          const reputation = modules.web_protection?.url_reputation !== false;
          const extEnforce = modules.web_protection?.extension_enforcement !== false;
          const version =
            effectivePolicy.assignments_applied[0]?.policy_version_id ??
            effectivePolicy.policy_ids_applied[0] ??
            "No active assignment";
          const disabled = !genai && !paste && !reputation && !extEnforce;
          setPolicy({
            policy_version: version,
            last_updated: new Date().toISOString(),
            status: disabled ? "disabled" : genai && reputation ? "protected" : "review_needed",
            approval_required: false,
            controls: {
              genai_guardrails: genai,
              sensitive_paste_upload_review: paste,
              url_reputation_anti_phishing: reputation,
              browser_extension_enforcement: extEnforce,
            },
          });
        }

        const webDetections = alerts.filter(isWebRelevant).map(alertToDetection);
        setDetections(webDetections);
        if (webDetections.length > 0) {
          setSelectedId((current) => current ?? webDetections[0].id);
          setSelectedAction((current) => current || webDetections[0].recommended_action);
        } else {
          setSelectedId(null);
        }
        setError(null);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load web protection telemetry.");
      } finally {
        if (!silent) setIsLoading(false);
      }
    },
    [scopedQuery, customerId],
  );

  useEffect(() => {
    void loadData();
  }, [loadData]);

  const selectedDetection = detections.find((d) => d.id === selectedId) || null;

  const handleSyncPolicy = async () => {
    setIsSyncing(true);
    setError(null);
    try {
      await loadData(true);
      setSuccess("Web protection telemetry and policy refreshed.");
    } catch {
      setError("Failed to fetch fresh Web Protection policies.");
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
      const simulated = await apiPost<SimulationPreview>("/web-protection/simulate", {
        detection_id: selectedDetection.id,
        action: selectedAction,
      });
      setSimulation(simulated);
      setSuccess("Dry run web policy simulation succeeded.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Direct simulation trigger failed.");
    } finally {
      setIsWorking(false);
    }
  };

  const stageAction = async (confirmed = false) => {
    if (!selectedDetection) return;

    const isDestructive =
      selectedAction === "isolate_endpoint_browser" || selectedAction === "force_extension_reload";
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
      if (selectedAction === "dismiss_alert") {
        await apiPatch(`/alerts/${selectedDetection.id}/acknowledge`);
      } else {
        await apiPost<any>("/web-protection/action", {
          detection_id: selectedDetection.id,
          action: selectedAction,
        });
      }
      setStagedActions((current) =>
        current.map((s) => (s.id === optimistic.id ? { ...s, status: "approved" } : s)),
      );
      setSuccess(`Response decision recorded for agent ${selectedDetection.endpoint_name}.`);
      void loadData(true);
    } catch (err) {
      setStagedActions((current) =>
        current.map((s) => (s.id === optimistic.id ? { ...s, status: "failed" } : s)),
      );
      setError(err instanceof Error ? err.message : "Failed to dispatch web protection action.");
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
        <LoadingState message="Retrieving web protection telemetry from agent registries..." />
      </div>
    );
  }

  return (
    <ConsolePage>
      
      <ModuleHeader
        title="Web Protection & GenAI Guardrails"
        eyebrow="Endpoint Protection Module"
        icon={Globe}
        status={policy.status}
        policyVersion={policy.policy_version}
        policyLastSynced={policy.last_updated}
        policyMode={policy.controls["genai_guardrails"] ? "GenAI Guardrails Active" : "Standard"}
        onRefresh={handleSyncPolicy}
        isRefreshing={isSyncing}
        quickActions={[
          {
            label: "Update Reputation Lists",
            icon: RefreshCw,
            onClick: () => {
              setSuccess("Initiated reputation lists sync across scoped agents.");
            },
            variant: "secondary",
            disabled: isWorking,
          },
        ]}
      />

      {error && <ErrorBanner message={error} />}
      {success && <SuccessBanner message={success} />}

      <MetricGrid
        ariaLabel="Web Compliance Summary Statistics"
        items={[
          { label: "Module Mode", value: "GenAI Guardrails Active", icon: <ShieldCheck size={20} />, color: "var(--accent)" },
          { label: "Active Incidents", value: `${detections.filter((d) => d.status === "new").length} Issues Pending`, icon: <AlertTriangle size={20} />, color: "var(--warning)" },
          { label: "Extension Health", value: "98% Connected", icon: <Globe size={20} />, color: "var(--muted)" },
        ]}
      />

      <section className="panelWorkspace" aria-label="Web Protection Core Console">
        <DetectionTable
          detections={detections}
          selectedId={selectedId}
          onSelect={(d) => {
            setSelectedId(d.id);
            handleActionChange(d.recommended_action);
          }}
          isLoading={isLoading}
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
            { value: "block_paste_action", label: "Block Paste/Upload to Destination", destructive: false },
            { value: "isolate_endpoint_browser", label: "Isolate Endpoint Web Access", destructive: true },
            { value: "force_extension_reload", label: "Force Extension Re-installation", destructive: true },
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
            <h2 style={{ fontSize: "14px", margin: 0 }}>Approved GenAI Destinations</h2>
            <span style={{ fontSize: "11px", color: "var(--muted)" }}>Monitored but allowed destinations</span>
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: "8px", fontSize: "12px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", background: "rgba(11, 107, 87, 0.01)", padding: "8px", borderRadius: "6px", border: "1px solid var(--line)" }}>
              <code>copilot.microsoft.com</code>
              <span style={{ color: "var(--muted)" }}>Corporate Subscribed Copilot</span>
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", background: "rgba(11, 107, 87, 0.01)", padding: "8px", borderRadius: "6px", border: "1px solid var(--line)" }}>
              <code>chatgpt.com (enterprise)</code>
              <span style={{ color: "var(--muted)" }}>Enterprise Tenant Workspace</span>
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", background: "rgba(11, 107, 87, 0.01)", padding: "8px", borderRadius: "6px", border: "1px solid var(--line)" }}>
              <code>claude.ai</code>
              <span style={{ color: "var(--muted)" }}>Anthropic Team Plan</span>
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", background: "rgba(11, 107, 87, 0.01)", padding: "8px", borderRadius: "6px", border: "1px solid var(--line)" }}>
              <code>gemini.google.com</code>
              <span style={{ color: "var(--muted)" }}>Google Workspace Edition</span>
            </div>
          </div>
        </article>

        <article className="panel">
          <div className="panelHeader" style={{ borderBottom: "1px solid var(--line)", paddingBottom: "10px", marginBottom: "12px" }}>
            <h2 style={{ fontSize: "14px", margin: 0 }}>Web Policy Engine Map</h2>
            <span style={{ fontSize: "11px", color: "var(--muted)" }}>Effective Web Protection parameters</span>
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
            <h3 style={{ margin: "0 0 10px 0", fontSize: "18px", color: "var(--warning)" }}>Confirm Destruction Level response</h3>
            <p style={{ margin: "0 0 20px 0", fontSize: "13px", color: "var(--muted)", lineHeight: 1.5 }}>
              You are staging an action (<strong>{confirmRequest.action.replaceAll("_", " ")}</strong>) with high-density system modification impact metrics on endpoint <strong>{confirmRequest.detection.endpoint_name}</strong>. This can disrupt web connectivity or browser functioning.
            </p>
            <div style={{ display: "flex", justifyContent: "flex-end", gap: "12px" }}>
              <button
                type="button"
                className="btnSecondary"
                onClick={() => setConfirmRequest(null)}
                style={{ cursor: "pointer" }}
              >
                Abrupt Cancel
              </button>
              <button
                type="button"
                className="btnPrimary"
                onClick={() => stageAction(true)}
                style={{ cursor: "pointer" }}
              >
                Confirm & Dispatch Stage
              </button>
            </div>
          </section>
        </div>
      )}
    </ConsolePage>
  );
}
