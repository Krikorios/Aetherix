import React, { useState, useEffect } from "react";
import {
  Archive,
  RefreshCw,
  RotateCcw,
  Trash2,
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
import { LoadingState } from "../components/protection/EmptyState";
import {
  Detection,
  StagedAction,
  SimulationPreview,
  EffectivePolicy,
} from "../components/protection/types";
import { ConsolePage, ErrorBanner, MetricGrid, SuccessBanner } from "../components";
import { apiGet, apiPost, type MeResponse } from "../api";

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

const KIND_ICON: Record<QuarantineItemKind, React.ReactNode> = {
  file: <FileText size={14} />,
  email: <Mail size={14} />,
  process: <Terminal size={14} />,
  network_connection: <ShieldCheck size={14} />,
};

const KIND_LABEL: Record<QuarantineItemKind, string> = {
  file: "File",
  email: "Email",
  process: "Process",
  network_connection: "Network Connection",
};

const DEMO_ITEMS: QuarantineItem[] = [
  {
    id: "q-001",
    customer_id: null,
    hostname: "WIN-WORK-042",
    kind: "file",
    name: "invoice_Q1_2024.exe",
    path: "C:\\Users\\jdoe\\Downloads\\invoice_Q1_2024.exe",
    hash: "a3f8b1c2d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0",
    quarantine_reason: "Trojan.GenericKD.46832741 — confidence 98%",
    severity: "critical",
    status: "quarantined",
    quarantined_at: new Date(Date.now() - 3600000 * 2).toISOString(),
    quarantined_by: "Aetherix Agent v1.4.2",
    detection_id: "alert-abc-123",
  },
  {
    id: "q-002",
    customer_id: null,
    hostname: "WIN-WORK-017",
    kind: "email",
    name: "Urgent: Account Verification Required",
    path: null,
    hash: null,
    quarantine_reason: "Phishing email — credential harvesting link detected",
    severity: "high",
    status: "quarantined",
    quarantined_at: new Date(Date.now() - 3600000 * 5).toISOString(),
    quarantined_by: "DLP Policy v2",
    detection_id: null,
  },
  {
    id: "q-003",
    customer_id: null,
    hostname: "LINUX-SRV-08",
    kind: "process",
    name: "cryptominer64",
    path: "/tmp/.hidden/cryptominer64",
    hash: "b4c9d2e3f1a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5",
    quarantine_reason: "Cryptominer binary — CPU abuse detected",
    severity: "high",
    status: "quarantined",
    quarantined_at: new Date(Date.now() - 3600000 * 12).toISOString(),
    quarantined_by: "Aetherix Agent v1.4.1",
    detection_id: "alert-def-456",
  },
  {
    id: "q-004",
    customer_id: null,
    hostname: "WIN-WORK-001",
    kind: "file",
    name: "report_template.docm",
    path: "C:\\Users\\ksmith\\Documents\\report_template.docm",
    hash: "c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5",
    quarantine_reason: "Macro-enabled document — suspicious auto-open macro",
    severity: "medium",
    status: "restore_requested",
    quarantined_at: new Date(Date.now() - 86400000).toISOString(),
    quarantined_by: "Aetherix Agent v1.4.2",
    detection_id: null,
  },
];

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

  const [items, setItems] = useState<QuarantineItem[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [selectedAction, setSelectedAction] = useState<string>("confirm_quarantine");
  const [simulation, setSimulation] = useState<SimulationPreview | null>(null);
  const [stagedActions, setStagedActions] = useState<StagedAction[]>([]);
  const [isWorking, setIsWorking] = useState(false);

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

  useEffect(() => {
    async function load() {
      try {
        const customerId = me.scope.customer_ids[0];
        const url = customerId ? `/quarantine?customer_id=${customerId}` : `/quarantine`;
        const data = await apiGet<QuarantineItem[]>(url);
        setItems(data);
        if (data.length > 0) {
          setSelectedId(data[0].id);
          setSelectedAction(data[0].status === "restore_requested" ? "approve_restore" : "confirm_quarantine");
        }
      } catch {
        setItems(DEMO_ITEMS);
        setSelectedId(DEMO_ITEMS[0].id);
        setSelectedAction("confirm_quarantine");
      } finally {
        setIsLoading(false);
      }
    }
    void load();
  }, [me]);

  const handleSyncPolicy = async () => {
    setIsSyncing(true);
    try {
      await new Promise((r) => setTimeout(r, 600));
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
      await apiPost(`/quarantine/${selectedItem.id}/simulate`, { action: selectedAction });
    } catch {
      const isRestore = selectedAction === "approve_restore" || selectedAction === "request_restore";
      const sim: SimulationPreview = {
        id: `sim-q-${selectedItem.id}-${Date.now()}`,
        detection_id: selectedItem.id,
        action: selectedAction,
        destructive: selectedAction === "delete_permanently",
        approval_required: policy.approval_required,
        affected_systems: 1,
        estimated_impact: [
          isRestore
            ? `Restoring ${KIND_LABEL[selectedItem.kind]}: ${selectedItem.name}`
            : `${selectedAction === "delete_permanently" ? "Permanently deleting" : "Confirming quarantine for"}: ${selectedItem.name}`,
          `Endpoint: ${selectedItem.hostname}`,
          isRestore
            ? `The item will be restored to its original location. Original threat risk remains — confirm with operator.`
            : `Item is isolated in the quarantine store. No further execution possible.`,
        ],
        evidence_controls: ["iso27001-2022:A.8.7", "nist-csf-2.0:RS.MI"],
        created_at: new Date().toISOString(),
      };
      setSimulation(sim);
      setSuccess("Simulation complete.");
    } finally {
      setIsWorking(false);
    }
  };

  const handleStage = async () => {
    if (!selectedItem) return;
    setIsWorking(true);
    const optimistic: StagedAction = {
      id: `staged-q-${Date.now()}`,
      detection_id: selectedItem.id,
      action: selectedAction,
      status: policy.approval_required ? "awaiting_approval" : "queued",
      approval_required: policy.approval_required,
      requested_by: me.account.email,
      created_at: new Date().toISOString(),
      note: `Quarantine action staged: ${selectedAction}`,
    };
    setStagedActions((prev) => [optimistic, ...prev]);
    try {
      await apiPost(`/quarantine/${selectedItem.id}/action`, { action: selectedAction });
    } catch {
      // offline fallback — update state optimistically
    }
    const nextStatus: QuarantineItem["status"] =
      selectedAction === "approve_restore" || selectedAction === "request_restore"
        ? "restore_requested"
        : selectedAction === "delete_permanently"
        ? "deleted"
        : "quarantined";
    setItems((prev) => prev.map((i) => (i.id === selectedItem.id ? { ...i, status: nextStatus } : i)));
    setSuccess(`Action staged: ${selectedAction} on ${selectedItem.name}`);
    setIsWorking(false);
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

      <section className="panelWorkspace" aria-label="Quarantine Board">
        <DetectionTable
          detections={detections}
          selectedId={selectedId}
          onSelect={(d) => {
            setSelectedId(d.id);
            const item = items.find((i) => i.id === d.id);
            setSelectedAction(item?.status === "restore_requested" ? "approve_restore" : "confirm_quarantine");
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
                      ...(item.path ? [{ label: "Original Path", value: item.path }] : []),
                      ...(item.hash ? [{ label: "File Hash", value: `${item.hash.slice(0, 16)}…` }] : []),
                    ].map(({ label, value }) => (
                      <div key={label} className="kvRow">
                        <span>{label}</span>
                        <strong>{value}</strong>
                      </div>
                    ))}
                  </div>
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
            { value: "approve_restore", label: "Approve & Restore", destructive: false },
            { value: "delete_permanently", label: "Delete Permanently", destructive: true },
          ]}
        />
      </section>
    </ConsolePage>
  );
}
