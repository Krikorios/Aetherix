import React, { useState, useEffect } from "react";
import {
  Archive,
  AlertTriangle,
  CheckCircle,
  FileText,
  Mail,
  Terminal,
  ShieldCheck,
} from "lucide-react";
import { ModuleHeader } from "../components/protection/ModuleHeader";
import { DetectionTable } from "../components/protection/DetectionTable";
import { DetailPanel } from "../components/protection/DetailPanel";
import { ActionStagingPanel } from "../components/protection/ActionStagingPanel";
import { EmptyState, LoadingState } from "../components/protection/EmptyState";
import { CorrelationBanner } from "../components/protection/CorrelationBanner";
import {
  Detection,
  StagedAction,
  SimulationPreview,
  EffectivePolicy,
  ActionStatus,
} from "../components/protection/types";
import { ConsolePage, ErrorBanner, MetricGrid, SuccessBanner } from "../components";
import { apiGet, apiPost, type MeResponse, type CorrelationResponse } from "../api";

export interface QuarantineInventoryItem {
  quarantine_id: string;
  original_path: string;
  file_hash: string;
  quarantined_at: string;
  severity_hint: "low" | "medium" | "high" | "critical";
  reason: string;
}

export interface QuarantineInventoryResponse {
  endpoint_id: string;
  customer_id: string | null;
  items: QuarantineInventoryItem[];
  source_action_id: string | null;
  refreshed_at: string | null;
}

export interface ModuleActionResult {
  id: string;
  target_id: string;
  action: string;
  status: "queued" | "awaiting_approval" | "completed" | "failed" | "denied";
  approval_required: boolean;
  payload: Record<string, any> | null;
  evidence_controls: string[];
  created_at: string;
  result: Record<string, any> | null;
  processed_at: string | null;
  requested_by: string | null;
  approved_by: string | null;
  approved_at: string | null;
}

export type QuarantineItemKind = "file" | "email" | "process" | "network_connection";

export interface QuarantineItem {
  id: string;
  customer_id?: string | null;
  hostname: string;
  kind: QuarantineItemKind;
  name: string;
  path?: string | null;
  hash?: string | null;
  quarantine_reason: string;
  severity: "low" | "medium" | "high" | "critical";
  status: "quarantined" | "restore_requested" | "restored" | "deleted";
  quarantined_at: string;
  quarantined_by: string;
  detection_id?: string | null;
}


const KIND_LABEL: Record<QuarantineItemKind, string> = {
  file: "File",
  email: "Email",
  process: "Process",
  network_connection: "Network Connection",
};

export function QuarantinePage({ me }: { me: MeResponse }) {
  const [isLoading, setIsLoading] = useState(true);
  const [isSyncing, setIsSyncing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const [policy, setPolicy] = useState<EffectivePolicy>({
    policy_version: "v2.10.4",
    last_updated: new Date(Date.now() - 3600000).toISOString(),
    status: "protected",
    approval_required: true,
    controls: {
      quarantine_auto: true,
      quarantine_restore_approval: true,
      quarantine_audit_trail: true,
    },
  });

  const [activeTab, setActiveTab] = useState<"board" | "inbox">("board");
  const [inventory, setInventory] = useState<QuarantineInventoryItem[]>([]);
  const [inventoryRefreshedAt, setInventoryRefreshedAt] = useState<string | null>(null);
  const [inventoryLoading, setInventoryLoading] = useState<boolean>(false);
  const [pendingRestores, setPendingRestores] = useState<any[]>([]);

  const [items, setItems] = useState<QuarantineItem[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [selectedAction, setSelectedAction] = useState<string>("confirm_quarantine");
  const [simulation, setSimulation] = useState<SimulationPreview | null>(null);
  const [stagedActions, setStagedActions] = useState<StagedAction[]>([]);
  const [isWorking, setIsWorking] = useState(false);

  // Cross-module correlation data for the selected item's linked security alert
  const [correlationData, setCorrelationData] = useState<CorrelationResponse | null>(null);
  const [correlationLoading, setCorrelationLoading] = useState(false);

  const detections: Detection[] = items.map((item) => ({
    id: item.id,
    customer_id: item.customer_id,
    endpoint_id: item.hostname,
    endpoint_name: item.hostname,
    title: item.name,
    source: `Quarantine: ${KIND_LABEL[item.kind]}`,
    description: item.quarantine_reason,
    risk_score:
      item.severity === "critical" ? 95 : item.severity === "high" ? 75 : item.severity === "medium" ? 45 : 20,
    risk_band: item.severity,
    confidence: 90,
    recommended_action:
      item.status === "restore_requested" ? "approve_restore" : item.status === "quarantined" ? "confirm_quarantine" : "no_action",
    status:
      item.status === "restored" || item.status === "deleted" ? "resolved" : item.status === "restore_requested" ? "staged" : "investigating",
    created_at: item.quarantined_at,
    context: {
      user: item.quarantined_by,
      command_line: [item.path, item.hash].filter(Boolean).join(" · ") || item.name,
      mitre_techniques: item.kind === "file" ? [{ id: "T1204.002", name: "Malicious File", tactic: "Execution" }] : [],
    },
  }));

  const selectedDetection = detections.find((d) => d.id === selectedId) ?? null;
  const selectedItem = items.find((i) => i.id === selectedId) ?? null;

  // 1. Fetch alerts list
  useEffect(() => {
    async function load() {
      try {
        const customerId = me.scope.customer_ids[0];
        const url = customerId ? `/quarantine?customer_id=${customerId}` : `/quarantine`;
        const data = await apiGet<QuarantineItem[]>(url);
        setItems(data);
        if (data.length > 0) {
          setSelectedId(data[0].id);
          setSelectedAction(data[0].status === "restore_requested" ? "release_from_quarantine" : "confirm_quarantine");
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load quarantine store.");
      } finally {
        setIsLoading(false);
      }
    }
    void load();
  }, [me]);

  // 2. Fetch global pending restores
  useEffect(() => {
    async function fetchPending() {
      try {
        const customerId = me.scope.customer_ids[0];
        const url = customerId ? `/quarantine-restores/pending?customer_id=${customerId}` : `/quarantine-restores/pending`;
        const data = await apiGet<any[]>(url);
        setPendingRestores(data);
      } catch (err) {
        console.error("Failed to load pending restores:", err);
      }
    }
    void fetchPending();
    const interval = setInterval(fetchPending, 15_000);
    return () => clearInterval(interval);
  }, [me]);

  // 3. Fetch EDR inventory & response actions on selection
  useEffect(() => {
    if (!selectedItem) {
      setInventory([]);
      setInventoryRefreshedAt(null);
      setCorrelationData(null);
      return;
    }

    const _item = selectedItem;

    async function loadEndpointData() {
      setInventoryLoading(true);
      try {
        const endpointId = _item.hostname;

        // Fetch remote inventory
        const invData = await apiGet<QuarantineInventoryResponse>(`/endpoints/${endpointId}/quarantine-inventory`);
        setInventory(invData.items || []);
        setInventoryRefreshedAt(invData.refreshed_at);

        // Fetch EDR response actions
        const actionsData = await apiGet<ModuleActionResult[]>(`/endpoints/${endpointId}/response-actions`);
        
        const mappedActions = actionsData.map(act => {
          let mappedStatus: ActionStatus = "queued";
          if (act.status === "completed") {
            mappedStatus = "executed";
          } else if (act.status === "failed") {
            mappedStatus = "failed";
          } else if (act.status === "awaiting_approval") {
            mappedStatus = "awaiting_approval";
          } else if (act.status === "queued") {
            mappedStatus = "queued";
          } else if (act.status === "denied") {
            mappedStatus = "denied";
          }
          return {
            id: act.id,
            detection_id: _item.id,
            action: act.action,
            status: mappedStatus,
            approval_required: act.approval_required,
            requested_by: act.requested_by || "system",
            created_at: act.created_at,
            note: act.status === "denied"
              ? `Denied by operator. Reason: ${act.payload?.denial_reason || "None"}`
              : act.result
                ? `Restored successfully. Controls: ${act.evidence_controls.join(", ")}`
                : `Staged action: ${act.action}`,
          };
        });

        setStagedActions(mappedActions);
      } catch (err) {
        console.error("Failed to load real endpoint data:", err);
      } finally {
        setInventoryLoading(false);
      }
    }
    void loadEndpointData();

    // Fetch correlation data if this quarantine item is linked to a security alert
    if (selectedItem.detection_id) {
      setCorrelationLoading(true);
      apiGet<CorrelationResponse>(`/security-alerts/${selectedItem.detection_id}/correlations`)
        .then(setCorrelationData)
        .catch(() => setCorrelationData(null))
        .finally(() => setCorrelationLoading(false));
    } else {
      setCorrelationData(null);
    }
  }, [selectedId, selectedItem]);

  const handleSyncPolicy = async () => {
    setIsSyncing(true);
    try {
      const customerId = me.scope.customer_ids[0];
      await apiGet(customerId ? `/quarantine?customer_id=${customerId}` : "/quarantine");
      setPolicy((prev) => ({ ...prev, last_updated: new Date().toISOString() }));
      setSuccess("Quarantine policies synced.");
    } catch {
      setError("Sync failed.");
    } finally {
      setIsSyncing(false);
    }
  };

  const handleSimulate = async () => {
    if (!selectedItem) return;
    setIsWorking(true);
    try {
      const sim = await apiPost<SimulationPreview>(`/quarantine/${selectedItem.id}/simulate`, { action: selectedAction });
      setSimulation(sim);
      setSuccess("Simulation complete.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Quarantine simulation failed.");
    } finally {
      setIsWorking(false);
    }
  };

  const handleStage = async () => {
    if (!selectedItem) return;
    setIsWorking(true);

    const isRestoreOrRelease = selectedAction === "request_restore" || selectedAction === "release_from_quarantine";
    let approvalRequired = false;

    if (isRestoreOrRelease) {
      const isHighOrCritical = selectedItem.severity === "high" || selectedItem.severity === "critical";
      approvalRequired = isHighOrCritical ? true : !!policy.controls?.quarantine_restore_approval;
    } else {
      approvalRequired = policy.approval_required;
    }

    try {
      if (isRestoreOrRelease) {
        // Dispatch real quarantine-restore action
        const result = await apiPost<ModuleActionResult>(`/endpoints/${selectedItem.hostname}/quarantine-restore`, {
          quarantine_id: selectedItem.hash || selectedItem.id,
          target_path: selectedItem.path || null,
          severity_hint: selectedItem.severity,
          reason: `Restore requested via console Quarantine page.`,
        });

        let mappedStatus: ActionStatus = "queued";
        if (result.status === "completed") {
          mappedStatus = "executed";
        } else if (result.status === "failed") {
          mappedStatus = "failed";
        } else if (result.status === "awaiting_approval") {
          mappedStatus = "awaiting_approval";
        } else if (result.status === "queued") {
          mappedStatus = "queued";
        } else if (result.status === "denied") {
          mappedStatus = "denied";
        }

        const optimistic: StagedAction = {
          id: result.id,
          detection_id: selectedItem.id,
          action: result.action,
          status: mappedStatus,
          approval_required: result.approval_required,
          requested_by: me.account.email,
          created_at: result.created_at,
          note: `Staged: ${result.action} (${result.status})`,
        };
        setStagedActions((prev) => [optimistic, ...prev]);

        // Refresh global pending restores
        const pendingData = await apiGet<any[]>(`/quarantine-restores/pending`);
        setPendingRestores(pendingData);

      } else if (selectedAction === "confirm_quarantine") {
        // Dispatch real quarantine-list scan action
        const result = await apiPost<ModuleActionResult>(`/endpoints/${selectedItem.hostname}/quarantine-list`, {
          reason: `Sync requested from console.`,
        });

        const optimistic: StagedAction = {
          id: result.id,
          detection_id: selectedItem.id,
          action: result.action,
          status: "queued",
          approval_required: false,
          requested_by: me.account.email,
          created_at: result.created_at,
          note: `Quarantine scan scheduled on agent.`,
        };
        setStagedActions((prev) => [optimistic, ...prev]);
      } else {
        // Old simulated action stage
        await apiPost(`/quarantine/${selectedItem.id}/action`, { action: selectedAction });
      }

      const nextStatus: QuarantineItem["status"] =
        selectedAction === "release_from_quarantine"
          ? "restored"
          : selectedAction === "request_restore"
          ? "restore_requested"
          : selectedAction === "delete_permanently"
          ? "deleted"
          : "quarantined";
      setItems((prev) => prev.map((i) => (i.id === selectedItem.id ? { ...i, status: nextStatus } : i)));
      
      const statusMsg = approvalRequired ? "Awaiting Operator Approval (Dual-Operator/Policy Gated)" : "Queued for immediate execution";
      setSuccess(`Action staged: ${selectedAction} on ${selectedItem.name}. Status: ${statusMsg}.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to stage quarantine action.");
    } finally {
      setIsWorking(false);
    }
  };

  const quarantined = items.filter((i) => i.status === "quarantined").length;
  const restoreRequested = items.filter((i) => i.status === "restore_requested").length;
  const resolved = items.filter((i) => i.status === "restored" || i.status === "deleted").length;

  if (isLoading) {
    return (
      <div style={{ padding: "40px", width: "100%" }}>
        <LoadingState message="Loading quarantine store…" />
      </div>
    );
  }

  return (
    <ConsolePage>
      <ModuleHeader
        title="Quarantine"
        eyebrow="Containment"
        icon={Archive}
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
        ariaLabel="Quarantine Metrics"
        items={[
          { label: "Quarantined", value: quarantined, icon: <Archive size={18} />, color: "var(--danger)" },
          { label: "Restore Requested", value: restoreRequested, icon: <AlertTriangle size={18} />, color: "var(--warning)" },
          { label: "Resolved", value: resolved, icon: <CheckCircle size={18} />, color: "var(--success)" },
          { label: "Files", value: items.filter((i) => i.kind === "file").length, icon: <FileText size={18} />, color: "var(--muted)" },
          { label: "Emails", value: items.filter((i) => i.kind === "email").length, icon: <Mail size={18} />, color: "var(--muted)" },
        ]}
      />

      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: "8px",
          fontSize: "12.5px",
          padding: "12px 16px",
          background: "rgba(11, 107, 87, 0.04)",
          border: "1px solid var(--line)",
          borderRadius: "10px",
          marginTop: "16px",
          marginBottom: "16px",
          color: "var(--ink)",
        }}
      >
        <span style={{ fontWeight: 700, color: "var(--accent)" }}>🛡️ Active Approval Model:</span>
        <span className="muted">
          Dual-operator required by default for <strong>High / Critical</strong> threats. Policy-configurable for <strong>Medium / Low</strong> severity threats (currently: <strong>{policy.controls.quarantine_restore_approval ? "Approval Required" : "Auto-Restore Gated"}</strong>).
        </span>
      </div>

      <div style={{ display: "flex", gap: "12px", borderBottom: "1px solid var(--line)", marginBottom: "16px", paddingBottom: "2px" }}>
        <button
          type="button"
          onClick={() => setActiveTab("board")}
          style={{
            padding: "8px 16px",
            background: "none",
            border: "none",
            borderBottom: activeTab === "board" ? "2px solid var(--accent)" : "none",
            fontWeight: activeTab === "board" ? 700 : 500,
            color: activeTab === "board" ? "var(--ink)" : "var(--muted)",
            cursor: "pointer",
            fontSize: "13.5px",
          }}
        >
          Quarantine Board ({items.length})
        </button>
        <button
          type="button"
          onClick={() => setActiveTab("inbox")}
          style={{
            padding: "8px 16px",
            background: "none",
            border: "none",
            borderBottom: activeTab === "inbox" ? "2px solid var(--accent)" : "none",
            fontWeight: activeTab === "inbox" ? 700 : 500,
            color: activeTab === "inbox" ? "var(--ink)" : "var(--muted)",
            cursor: "pointer",
            fontSize: "13.5px",
          }}
        >
          Approvals Inbox ({pendingRestores.length})
        </button>
      </div>

      {activeTab === "inbox" ? (
        <div className="panelWorkspace" style={{ flexDirection: "column", gap: "16px" }}>
          <article className="panel" style={{ width: "100%" }}>
            <div className="panelHeader" style={{ borderBottom: "1px solid var(--line)", paddingBottom: "12px", marginBottom: "16px" }}>
              <h2 style={{ fontSize: "16px", margin: 0 }}>Global Quarantine Restore Approvals Inbox</h2>
              <span style={{ fontSize: "12px", color: "var(--muted)" }}>Review EDR staging actions awaiting dual-operator auth or policy verification</span>
            </div>
            
            {pendingRestores.length === 0 ? (
              <div style={{ padding: "40px", textAlign: "center", color: "var(--muted)", fontSize: "13px" }}>
                All caught up! There are no pending quarantine restore requests currently awaiting approval.
              </div>
            ) : (
              <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
                {pendingRestores.map((p) => {
                  const action = p.action;
                  const isSelfRequest = action.requested_by === me.account.email || action.requested_by === me.account.id;
                  return (
                    <div
                      key={action.id}
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center",
                        padding: "16px",
                        background: "rgba(251, 252, 247, 0.95)",
                        border: "1px solid var(--line)",
                        borderRadius: "8px",
                        gap: "20px",
                        flexWrap: "wrap",
                      }}
                    >
                      <div style={{ flex: 1, minWidth: "250px" }}>
                        <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "4px" }}>
                          <strong style={{ fontSize: "14px" }}>{p.hostname || p.endpoint_id}</strong>
                          <span style={{ fontSize: "10px", background: "rgba(180, 80, 24, 0.07)", color: "var(--warning)", border: "1px solid rgba(180, 80, 24, 0.2)", padding: "1px 6px", borderRadius: "4px", fontWeight: 600 }}>
                            {action.payload?.severity_hint?.toUpperCase() || "MEDIUM"}
                          </span>
                        </div>
                        <div style={{ fontSize: "12.5px", color: "var(--ink)", marginBottom: "4px" }}>
                          Restore File: <code>{action.payload?.file_path || action.payload?.target_path || action.payload?.quarantine_id}</code>
                        </div>
                        <div style={{ fontSize: "11px", color: "var(--muted)" }}>
                          Staged by <strong>{action.requested_by}</strong> on {new Date(action.created_at).toLocaleString()}
                          {action.payload?.reason && ` · Reason: "${action.payload.reason}"`}
                        </div>
                      </div>
                      
                      <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                        {isSelfRequest && (
                          <span style={{ fontSize: "11px", color: "var(--warning)", fontStyle: "italic", marginRight: "8px" }}>
                            (Requires distinct account to approve)
                          </span>
                        )}
                        <button
                          type="button"
                          className="btnSecondary"
                          onClick={async () => {
                            const reason = prompt("Enter denial explanation:");
                            if (reason === null) return;
                            setIsWorking(true);
                            try {
                              await apiPost(`/endpoints/${p.endpoint_id}/quarantine-restore/${action.id}/deny`, { reason });
                              setSuccess(`Restore request denied.`);
                              const updatedData = await apiGet<any[]>(`/quarantine-restores/pending`);
                              setPendingRestores(updatedData);
                            } catch (err) {
                              setError(err instanceof Error ? err.message : "Denial failed");
                            } finally {
                              setIsWorking(false);
                            }
                          }}
                          disabled={isWorking}
                          style={{ padding: "6px 12px", fontSize: "12px", height: "auto", cursor: "pointer" }}
                        >
                          Deny
                        </button>
                        <button
                          type="button"
                          className="btnPrimary"
                          onClick={async () => {
                            setIsWorking(true);
                            try {
                              await apiPost(`/endpoints/${p.endpoint_id}/quarantine-restore/${action.id}/approve`, {});
                              setSuccess(`Restore request successfully approved and queued for dispatch.`);
                              const updatedData = await apiGet<any[]>(`/quarantine-restores/pending`);
                              setPendingRestores(updatedData);
                            } catch (err) {
                              setError(err instanceof Error ? err.message : "Approval failed");
                            } finally {
                              setIsWorking(false);
                            }
                          }}
                          disabled={isWorking}
                          style={{ padding: "6px 12px", fontSize: "12px", height: "auto", cursor: "pointer" }}
                        >
                          Approve
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </article>
        </div>
      ) : items.length === 0 ? (
        <EmptyState
          icon={Archive}
          title="Quarantine store is empty"
          message="No files, emails, processes, or connections are currently isolated. New containment events from agents and DLP will appear here."
        />
      ) : (
      <section className="panelWorkspace" aria-label="Quarantine Board">
        <DetectionTable
          detections={detections}
          selectedId={selectedId}
          onSelect={(d) => {
            setSelectedId(d.id);
            const item = items.find((i) => i.id === d.id);
            setSelectedAction(item?.status === "restore_requested" ? "release_from_quarantine" : "confirm_quarantine");
            setSimulation(null);
          }}
          isLoading={isLoading}
        />

        <DetailPanel
          detection={selectedDetection}
          customContextRenderer={(d) => {
            const item = items.find((i) => i.id === d.id);
            if (!item) return null;
            return (
              <div className="detailStack">
                {/* Correlation uplift banner when item is linked to a security alert */}
                {(correlationData || correlationLoading) && (
                  <CorrelationBanner data={correlationData} isLoading={correlationLoading} />
                )}

                <div>
                  <h4 className="sectionKicker" style={{ margin: "0 0 8px 0" }}>
                    Quarantine Details
                  </h4>
                  <div className="kvStack">
                    {[
                      { label: "Type", value: KIND_LABEL[item.kind] },
                      { label: "Status", value: item.status.replace("_", " ") },
                      { label: "Quarantined By", value: item.quarantined_by },
                      { label: "Quarantined At", value: new Date(item.quarantined_at).toLocaleString() },
                      { label: "Detection Source", value: KIND_LABEL[item.kind] },
                      ...(item.detection_id ? [{ label: "Linked Alert", value: item.detection_id }] : []),
                      ...(item.path ? [{ label: "Original Path", value: item.path }] : []),
                      ...(item.hash ? [{ label: "File Hash (sha256)", value: item.hash }] : []),
                    ].map(({ label, value }) => (
                      <div key={label} className="kvRow">
                        <span>{label}</span>
                        <strong>{value}</strong>
                      </div>
                    ))}
                  </div>
                </div>

                <div style={{ marginTop: "20px", borderTop: "1px solid var(--line)", paddingTop: "16px" }}>
                  <h4 className="sectionKicker" style={{ margin: "0 0 10px 0" }}>
                    🛡️ Live Endpoint Quarantine Snapshot
                  </h4>
                  {inventoryLoading ? (
                    <span className="muted" style={{ fontSize: "12px" }}>Scanning host inventory...</span>
                  ) : inventory.length === 0 ? (
                    <span className="muted" style={{ fontSize: "12px" }}>
                      No active files in remote inventory. Click "Confirm Quarantine" to trigger a refresh.
                      {inventoryRefreshedAt && ` (Last sync: ${new Date(inventoryRefreshedAt).toLocaleTimeString()})`}
                    </span>
                  ) : (
                    <div style={{ display: "flex", flexDirection: "column", gap: "8px", maxHeight: "250px", overflowY: "auto" }}>
                      {inventory.map((inv, idx) => (
                        <div
                          key={idx}
                          style={{
                            padding: "8px 10px",
                            background: "rgba(11, 107, 87, 0.02)",
                            border: "1px solid var(--line)",
                            borderRadius: "6px",
                            fontSize: "11px",
                          }}
                        >
                          <div style={{ fontWeight: 600, color: "var(--ink)", wordBreak: "break-all" }}>
                            {inv.original_path || inv.quarantine_id}
                          </div>
                          <div style={{ display: "flex", justifyContent: "space-between", color: "var(--muted)", marginTop: "4px" }}>
                            <span>SHA-256: <code>{inv.file_hash?.slice(0, 12)}...</code></span>
                            <span style={{ fontWeight: 600, color: "var(--accent)" }}>{inv.severity_hint || "medium"}</span>
                          </div>
                        </div>
                      ))}
                      {inventoryRefreshedAt && (
                        <span className="muted" style={{ fontSize: "10px", marginTop: "4px", display: "block" }}>
                          Last sync: {new Date(inventoryRefreshedAt).toLocaleString()}
                        </span>
                      )}
                    </div>
                  )}
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
            { value: "confirm_quarantine", label: "Confirm Quarantine", destructive: false },
            { value: "request_restore", label: "Request Restore", destructive: false },
            { value: "release_from_quarantine", label: "Release from Quarantine", destructive: true },
            { value: "delete_permanently", label: "Delete Permanently", destructive: true },
          ]}
        />
      </section>
      )}
    </ConsolePage>
  );
}
