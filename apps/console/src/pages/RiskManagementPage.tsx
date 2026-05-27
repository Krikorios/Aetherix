import React, { useState, useEffect } from "react";
import {
  AlertTriangle,
  CheckCircle,
  Package,
  ShieldAlert,
  TrendingUp,
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

export interface PatchItem {
  id: string;
  customer_id?: string | null;
  hostname: string;
  os: string;
  cve_id: string | null;
  kb_id: string | null;
  title: string;
  description: string;
  severity: "low" | "medium" | "high" | "critical";
  status: "missing" | "pending" | "applied" | "failed" | "excluded";
  category: "os" | "application" | "driver" | "security";
  vendor: string;
  release_date: string;
  installed_at?: string | null;
  tags: string[];
  cvss_score?: number | null;
}

export function RiskManagementPage({ me }: { me: MeResponse }) {
  const [isLoading, setIsLoading] = useState(true);
  const [isSyncing, setIsSyncing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const [policy, setPolicy] = useState<EffectivePolicy>({
    policy_version: "v2.10.4",
    last_updated: new Date(Date.now() - 3600000).toISOString(),
    status: "review_needed",
    approval_required: true,
    controls: {
      patch_scan: true,
      auto_patch_critical: false,
      patch_rollback: true,
    },
  });

  const [patches, setPatches] = useState<PatchItem[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [selectedAction, setSelectedAction] = useState<string>("schedule_patch");
  const [simulation, setSimulation] = useState<SimulationPreview | null>(null);
  const [stagedActions, setStagedActions] = useState<StagedAction[]>([]);
  const [isWorking, setIsWorking] = useState(false);

  const detections: Detection[] = patches.map((p) => ({
    id: p.id,
    customer_id: p.customer_id,
    endpoint_id: p.hostname,
    endpoint_name: p.hostname,
    title: p.title,
    source: `Patch Inventory · ${p.vendor}`,
    description: p.description,
    risk_score:
      p.severity === "critical" ? 95 : p.severity === "high" ? 78 : p.severity === "medium" ? 50 : 20,
    risk_band: p.severity,
    confidence: p.status === "missing" ? 100 : p.status === "failed" ? 90 : 70,
    recommended_action:
      p.status === "failed" ? "retry_patch_install" : p.status === "missing" ? "schedule_patch" : "no_action",
    status:
      p.status === "applied" ? "resolved" : p.status === "failed" ? "staged" : p.status === "pending" ? "investigating" : "new",
    created_at: p.release_date,
    context: {
      user: `patchmgr@${p.hostname}`,
      command_line: `vendor:${p.vendor} ${p.cve_id ?? p.kb_id ?? ""}`,
      mitre_techniques: p.cve_id
        ? [{ id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" }]
        : [],
    },
  }));

  const selectedDetection = detections.find((d) => d.id === selectedId) ?? null;
  const selectedPatch = patches.find((p) => p.id === selectedId) ?? null;

  useEffect(() => {
    async function load() {
      try {
        const customerId = me.scope.customer_ids[0];
        const url = customerId ? `/risk/patches?customer_id=${customerId}` : `/risk/patches`;
        const data = await apiGet<PatchItem[]>(url);
        setPatches(data);
        if (data.length > 0) {
          setSelectedId(data[0].id);
          setSelectedAction(data[0].status === "failed" ? "retry_patch_install" : "schedule_patch");
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load patch risk data.");
      } finally {
        setIsLoading(false);
      }
    }
    void load();
  }, [me]);

  const handleSyncPolicy = async () => {
    setIsSyncing(true);
    try {
      const customerId = me.scope.customer_ids[0];
      await apiGet(customerId ? `/risk/patches?customer_id=${customerId}` : "/risk/patches");
      setPolicy((prev) => ({ ...prev, last_updated: new Date().toISOString() }));
      setSuccess("Patch management policies synced.");
    } catch {
      setError("Sync failed.");
    } finally {
      setIsSyncing(false);
    }
  };

  const handleSimulate = async () => {
    if (!selectedPatch) return;
    setIsWorking(true);
    try {
      const sim = await apiPost<SimulationPreview>(`/risk/patches/${selectedPatch.id}/simulate`, { action: selectedAction });
      setSimulation(sim);
      setSuccess("Patch simulation complete — review impact before staging.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Patch simulation failed.");
    } finally {
      setIsWorking(false);
    }
  };

  const handleStage = async () => {
    if (!selectedPatch) return;
    setIsWorking(true);
    const optimistic: StagedAction = {
      id: `staged-patch-${Date.now()}`,
      detection_id: selectedPatch.id,
      action: selectedAction,
      status: policy.approval_required ? "awaiting_approval" : "queued",
      approval_required: policy.approval_required,
      requested_by: me.account.email,
      created_at: new Date().toISOString(),
      note: `Patch deployment staged for ${selectedPatch.hostname}`,
    };
    setStagedActions((prev) => [optimistic, ...prev]);
    try {
      await apiPost(`/risk/patches/${selectedPatch.id}/deploy`, { action: selectedAction });
      setPatches((prev) =>
        prev.map((p) => (p.id === selectedPatch.id ? { ...p, status: "pending" } : p)),
      );
      setSuccess(`Patch deployment staged: ${selectedPatch.title}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to stage patch deployment.");
    } finally {
      setIsWorking(false);
    }
  };

  const missing = patches.filter((p) => p.status === "missing").length;
  const criticalMissing = patches.filter((p) => p.status === "missing" && p.severity === "critical").length;
  const failed = patches.filter((p) => p.status === "failed").length;
  const applied = patches.filter((p) => p.status === "applied").length;

  if (isLoading) {
    return (
      <div style={{ padding: "40px", width: "100%" }}>
        <LoadingState message="Scanning patch inventory…" />
      </div>
    );
  }

  return (
    <ConsolePage>
      <ModuleHeader
        title="Risk Management"
        eyebrow="Asset Hardening"
        icon={AlertTriangle}
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
        ariaLabel="Patch Metrics"
        items={[
          { label: "Missing Patches", value: missing, icon: <ShieldAlert size={18} />, color: "var(--danger)" },
          { label: "Critical Missing", value: criticalMissing, icon: <TrendingUp size={18} />, color: "var(--danger)" },
          { label: "Install Failed", value: failed, icon: <AlertTriangle size={18} />, color: "var(--warning)" },
          { label: "Applied (30d)", value: applied, icon: <CheckCircle size={18} />, color: "var(--success)" },
          { label: "Total Tracked", value: patches.length, icon: <Package size={18} />, color: "var(--accent)" },
        ]}
      />

      {patches.length === 0 ? (
        <EmptyState
          icon={Package}
          title="No patch risk items"
          message="Endpoint heartbeat signals with pending updates will appear here once enrolled agents report them."
        />
      ) : (
      <section className="panelWorkspace" aria-label="Patch Management Board">
        <DetectionTable
          detections={detections}
          selectedId={selectedId}
          onSelect={(d) => {
            setSelectedId(d.id);
            const p = patches.find((x) => x.id === d.id);
            setSelectedAction(p?.status === "failed" ? "retry_patch_install" : "schedule_patch");
            setSimulation(null);
          }}
          isLoading={isLoading}
        />

        <DetailPanel
          detection={selectedDetection}
          customContextRenderer={(d) => {
            const p = patches.find((x) => x.id === d.id);
            if (!p) return null;
            return (
              <div className="detailStack">
                <div>
                  <h4 className="sectionKicker" style={{ margin: "0 0 8px 0" }}>
                    Patch Details
                  </h4>
                  <div className="kvStack">
                    {[
                      { label: "Vendor", value: p.vendor },
                      { label: "Category", value: p.category },
                      ...(p.cve_id ? [{ label: "CVE", value: p.cve_id }] : []),
                      ...(p.kb_id ? [{ label: "KB Article", value: p.kb_id }] : []),
                      ...(p.cvss_score != null ? [{ label: "CVSS Score", value: String(p.cvss_score) }] : []),
                      { label: "Release Date", value: new Date(p.release_date).toLocaleDateString() },
                      { label: "Status", value: p.status },
                      ...(p.installed_at ? [{ label: "Installed", value: new Date(p.installed_at).toLocaleDateString() }] : []),
                    ].map(({ label, value }) => (
                      <div key={label} className="kvRow">
                        <span>{label}</span>
                        <strong>{value}</strong>
                      </div>
                    ))}
                  </div>
                </div>
                {p.tags.length > 0 && (
                  <div>
                    <h4 className="sectionKicker" style={{ margin: "0 0 8px 0" }}>
                      Tags
                    </h4>
                    <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
                      {p.tags.map((tag) => (
                        <span
                          key={tag}
                          style={{
                            background: "rgba(180, 80, 24, 0.08)",
                            color: "var(--warning)",
                            border: "1px solid rgba(180, 80, 24, 0.2)",
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
            { value: "schedule_patch", label: "Schedule Patch Installation", destructive: false },
            { value: "retry_patch_install", label: "Retry Failed Installation", destructive: false },
            { value: "exclude_patch", label: "Exclude from Policy", destructive: false },
            { value: "rollback_patch", label: "Rollback Installed Patch", destructive: true },
          ]}
        />
      </section>
      )}
    </ConsolePage>
  );
}
