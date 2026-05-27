import React, { useState, useEffect } from "react";
import {
  Usb,
  CheckCircle,
  AlertTriangle,
  Printer,
  Bluetooth,
  HardDrive,
  LockKeyhole,
  ShieldCheck,
  Clipboard,
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
import { apiGet, apiPost, type MeResponse, type EffectivePolicyResponse } from "../api";

export type DeviceType = "usb_storage" | "usb_other" | "printer" | "bluetooth" | "optical" | "thunderbolt" | "clipboard";

export interface DeviceEvent {
  id: string;
  customer_id?: string | null;
  hostname: string;
  user: string;
  device_type: DeviceType;
  device_name: string;
  vendor_id: string;
  product_id: string;
  serial?: string | null;
  action: "connected" | "blocked" | "allowed_once" | "read_attempted" | "write_attempted" | "paste_attempted" | "print_job";
  severity: "low" | "medium" | "high" | "critical";
  status: "blocked" | "pending_approval" | "allowed" | "review";
  timestamp: string;
  bytes_written?: number | null;
  destination?: string | null;
  policy_rule?: string | null;
  approval_required: boolean;
}


const DEVICE_LABEL: Record<DeviceType, string> = {
  usb_storage: "USB Storage",
  usb_other: "USB Device",
  printer: "Printer",
  bluetooth: "Bluetooth",
  optical: "Optical Drive",
  thunderbolt: "Thunderbolt",
  clipboard: "Clipboard",
};

export function DeviceControlPage({ me }: { me: MeResponse }) {
  const [isLoading, setIsLoading] = useState(true);
  const [isSyncing, setIsSyncing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const [policy, setPolicy] = useState<EffectivePolicy>(() => ({
    policy_version: "v2.10.4",
    last_updated: new Date(Date.now() - 3600000).toISOString(),
    status: "protected",
    approval_required: true,
    controls: {
      usb_storage_block: true,
      usb_approval_gate: true,
      bluetooth_monitor: true,
      audit_evidence: true,
    },
  }));

  const [deviceEvents, setDeviceEvents] = useState<DeviceEvent[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [selectedAction, setSelectedAction] = useState<string>("confirm_block");
  const [simulation, setSimulation] = useState<SimulationPreview | null>(null);
  const [stagedActions, setStagedActions] = useState<StagedAction[]>([]);
  const [isWorking, setIsWorking] = useState(false);

  const detections: Detection[] = deviceEvents.map((ev) => ({
    id: ev.id,
    customer_id: ev.customer_id,
    endpoint_id: ev.hostname,
    endpoint_name: `${ev.hostname} · ${ev.user.split("@")[0]}`,
    title: ev.device_name,
    source: `Device Control: ${DEVICE_LABEL[ev.device_type]}`,
    description: `${ev.action.replace("_", " ")} — ${ev.policy_rule ?? "no policy match"}`,
    risk_score:
      ev.severity === "critical" ? 95 : ev.severity === "high" ? 75 : ev.severity === "medium" ? 45 : 20,
    risk_band: ev.severity,
    confidence: ev.status === "blocked" ? 95 : 70,
    recommended_action:
      ev.status === "pending_approval"
        ? "approve_device"
        : ev.status === "review"
        ? "review_event"
        : ev.status === "blocked"
        ? "confirm_block"
        : "add_to_allowlist",
    status:
      ev.status === "blocked" ? "investigating"
        : ev.status === "pending_approval" || ev.status === "review" ? "staged"
        : "resolved",
    created_at: ev.timestamp,
    context: {
      user: ev.user,
      command_line: `vid:${ev.vendor_id} pid:${ev.product_id}${ev.serial ? ` sn:${ev.serial}` : ""}`,
      mitre_techniques:
        ev.action === "write_attempted" || ev.action === "paste_attempted"
          ? [{ id: "T1052.001", name: "Exfiltration over Physical/Logical Medium", tactic: "Exfiltration" }]
          : [],
    },
  }));

  const selectedDetection = detections.find((d) => d.id === selectedId) ?? null;
  const selectedEvent = deviceEvents.find((e) => e.id === selectedId) ?? null;

  useEffect(() => {
    async function load() {
      try {
        const customerId = me.scope.customer_ids[0];
        const url = customerId ? `/device-control/events?customer_id=${customerId}` : `/device-control/events`;
        const [data, effectivePolicy] = await Promise.all([
          apiGet<DeviceEvent[]>(url),
          apiGet<EffectivePolicyResponse>(customerId ? `/policies/effective?customer_id=${customerId}` : "/policies/effective").catch(() => null),
        ]);
        if (effectivePolicy) {
          const module = effectivePolicy.resolved_policy.modules.device_control ?? {};
          const enabled = module.enabled !== false;
          setPolicy({
            policy_version: effectivePolicy.assignments_applied[0]?.policy_version_id ?? effectivePolicy.policy_ids_applied[0] ?? "No active assignment",
            last_updated: new Date().toISOString(),
            status: enabled ? "protected" : "disabled",
            approval_required: true,
            controls: {
              usb_storage_block: enabled,
              usb_approval_gate: enabled,
              bluetooth_monitor: enabled,
              audit_evidence: true,
            },
          });
        }
        setDeviceEvents(data);
        if (data.length > 0) {
          setSelectedId(data[0].id);
          setSelectedAction(
            data[0].status === "pending_approval"
              ? "approve_device"
              : data[0].status === "review"
              ? "review_event"
              : "confirm_block",
          );
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load device control events.");
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
      await apiGet<EffectivePolicyResponse>(customerId ? `/policies/effective?customer_id=${customerId}` : "/policies/effective");
      setPolicy((prev) => ({ ...prev, last_updated: new Date().toISOString() }));
      setSuccess("Device control policies synced.");
    } catch {
      setError("Sync failed.");
    } finally {
      setIsSyncing(false);
    }
  };

  const handleSimulate = async () => {
    if (!selectedEvent) return;
    setIsWorking(true);
    try {
      const sim = await apiPost<SimulationPreview>(`/device-control/events/${selectedEvent.id}/simulate`, { action: selectedAction });
      setSimulation(sim);
      setSuccess("Simulation complete.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Device simulation failed.");
    } finally {
      setIsWorking(false);
    }
  };

  const handleStage = async () => {
    if (!selectedEvent) return;
    setIsWorking(true);
    const optimistic: StagedAction = {
      id: `staged-dev-${Date.now()}`,
      detection_id: selectedEvent.id,
      action: selectedAction,
      status: selectedEvent.approval_required ? "awaiting_approval" : "queued",
      approval_required: selectedEvent.approval_required,
      requested_by: me.account.email,
      created_at: new Date().toISOString(),
      note: `Device control: ${selectedAction} for ${selectedEvent.device_name}`,
    };
    setStagedActions((prev) => [optimistic, ...prev]);
    try {
      await apiPost(`/device-control/events/${selectedEvent.id}/action`, { action: selectedAction });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to stage device action.");
      setIsWorking(false);
      return;
    }
    const nextStatus: DeviceEvent["status"] =
      selectedAction === "add_to_allowlist" || selectedAction === "approve_device"
        ? "allowed"
        : selectedAction === "review_event"
        ? "review"
        : "blocked";
    setDeviceEvents((prev) =>
      prev.map((e) => (e.id === selectedEvent.id ? { ...e, status: nextStatus } : e)),
    );
    setSuccess(`Action staged: ${selectedAction} on ${selectedEvent.device_name}`);
    setIsWorking(false);
  };

  const blocked = deviceEvents.filter((e) => e.status === "blocked").length;
  const pendingApproval = deviceEvents.filter((e) => e.status === "pending_approval").length;
  const review = deviceEvents.filter((e) => e.status === "review").length;
  const allowed = deviceEvents.filter((e) => e.status === "allowed").length;
  const usbEvents = deviceEvents.filter((e) => e.device_type.startsWith("usb")).length;
  const clipboardEvents = deviceEvents.filter((e) => e.device_type === "clipboard").length;
  const printerEvents = deviceEvents.filter((e) => e.device_type === "printer").length;

  if (isLoading) {
    return (
      <div style={{ padding: "40px", width: "100%" }}>
        <LoadingState message="Loading device control events…" />
      </div>
    );
  }

  return (
    <ConsolePage>
      <ModuleHeader
        title="Device Control"
        eyebrow="Data Movement Controls"
        icon={Usb}
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
        ariaLabel="Device Control Metrics"
        items={[
          { label: "Blocked", value: blocked, icon: <LockKeyhole size={18} />, color: "var(--danger)" },
          { label: "Pending Approval", value: pendingApproval, icon: <AlertTriangle size={18} />, color: "var(--warning)" },
          { label: "Review Queue", value: review, icon: <AlertTriangle size={18} />, color: "var(--warning)" },
          { label: "Allowed", value: allowed, icon: <CheckCircle size={18} />, color: "var(--success)" },
          { label: "USB", value: usbEvents, icon: <Usb size={18} />, color: "var(--accent)" },
          { label: "Clipboard", value: clipboardEvents, icon: <Clipboard size={18} />, color: "var(--accent)" },
          { label: "Printer", value: printerEvents, icon: <Printer size={18} />, color: "var(--accent)" },
        ]}
      />

      {deviceEvents.length === 0 ? (
        <EmptyState
          icon={Usb}
          title="No device control events yet"
          message="USB, printer, Bluetooth, and clipboard activity from enrolled endpoints will appear here as policies engage."
        />
      ) : (
      <section className="panelWorkspace" aria-label="Device Control Board">
        <DetectionTable
          detections={detections}
          selectedId={selectedId}
          onSelect={(d) => {
            setSelectedId(d.id);
            const ev = deviceEvents.find((e) => e.id === d.id);
            setSelectedAction(
              ev?.status === "pending_approval"
                ? "approve_device"
                : ev?.status === "review"
                ? "review_event"
                : "confirm_block",
            );
            setSimulation(null);
          }}
          isLoading={isLoading}
        />

        <DetailPanel
          detection={selectedDetection}
          customContextRenderer={(d) => {
            const ev = deviceEvents.find((e) => e.id === d.id);
            if (!ev) return null;
            return (
              <div className="detailStack">
                <div>
                  <h4 className="sectionKicker" style={{ margin: "0 0 8px 0" }}>
                    Device Details
                  </h4>
                  <div className="kvStack">
                    {[
                      { label: "Device Type", value: DEVICE_LABEL[ev.device_type] },
                      { label: "Vendor ID", value: ev.vendor_id },
                      { label: "Product ID", value: ev.product_id },
                      ...(ev.serial ? [{ label: "Serial Number", value: ev.serial }] : []),
                      { label: "Action", value: ev.action.replace(/_/g, " ") },
                      { label: "Status", value: ev.status.replace(/_/g, " ") },
                      { label: "User", value: ev.user },
                      ...(ev.destination ? [{ label: "Destination", value: ev.destination }] : []),
                      ...(ev.policy_rule ? [{ label: "Policy Rule", value: ev.policy_rule }] : []),
                      ...(ev.bytes_written != null
                        ? [{ label: "Bytes Written", value: ev.bytes_written === 0 ? "Blocked (0)" : `${(ev.bytes_written / 1024 / 1024).toFixed(1)} MB` }]
                        : []),
                      { label: "Timestamp", value: new Date(ev.timestamp).toLocaleString() },
                    ].map(({ label, value }) => (
                      <div key={label} className="kvRow">
                        <span>{label}</span>
                        <strong>{value}</strong>
                      </div>
                    ))}
                  </div>
                </div>
                {ev.approval_required && (
                  <div
                    style={{
                      background: "rgba(180,80,24,0.06)",
                      border: "1px solid rgba(180,80,24,0.2)",
                      borderRadius: "6px",
                      padding: "10px 12px",
                      fontSize: "12px",
                      color: "var(--warning)",
                    }}
                  >
                    Approval required — this device type requires explicit authorization before access is granted.
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
            { value: "confirm_block", label: "Confirm Block", destructive: false },
            { value: "review_event", label: "Mark for Review", destructive: false },
            { value: "approve_device", label: "Approve One-Time Access", destructive: false },
            { value: "add_to_allowlist", label: "Add to Allowlist", destructive: false },
            { value: "block_device_class", label: "Block Entire Device Class", destructive: true },
          ]}
        />
      </section>
      )}
    </ConsolePage>
  );
}
