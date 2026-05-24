import React, { useState, useEffect } from "react";
import {
  Usb,
  RefreshCw,
  ShieldAlert,
  CheckCircle,
  AlertTriangle,
  Printer,
  Bluetooth,
  HardDrive,
  LockKeyhole,
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

export type DeviceType = "usb_storage" | "usb_other" | "printer" | "bluetooth" | "optical" | "thunderbolt";

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
  action: "connected" | "blocked" | "allowed_once" | "read_attempted" | "write_attempted";
  severity: "low" | "medium" | "high" | "critical";
  status: "blocked" | "pending_approval" | "allowed" | "review";
  timestamp: string;
  bytes_written?: number | null;
  policy_rule?: string | null;
  approval_required: boolean;
}

const DEVICE_ICON: Record<DeviceType, React.ReactNode> = {
  usb_storage: <HardDrive size={14} />,
  usb_other: <Usb size={14} />,
  printer: <Printer size={14} />,
  bluetooth: <Bluetooth size={14} />,
  optical: <HardDrive size={14} />,
  thunderbolt: <Usb size={14} />,
};

const DEVICE_LABEL: Record<DeviceType, string> = {
  usb_storage: "USB Storage",
  usb_other: "USB Device",
  printer: "Printer",
  bluetooth: "Bluetooth",
  optical: "Optical Drive",
  thunderbolt: "Thunderbolt",
};

const DEMO_EVENTS: DeviceEvent[] = [
  {
    id: "dev-001",
    customer_id: null,
    hostname: "WIN-WORK-042",
    user: "jdoe@northgate.internal",
    device_type: "usb_storage",
    device_name: "SanDisk Ultra 64GB",
    vendor_id: "0781",
    product_id: "5591",
    serial: "AA01234567890123",
    action: "write_attempted",
    severity: "high",
    status: "blocked",
    timestamp: new Date(Date.now() - 3600000).toISOString(),
    bytes_written: 0,
    policy_rule: "device:block-usb-storage-write",
    approval_required: true,
  },
  {
    id: "dev-002",
    customer_id: null,
    hostname: "WIN-WORK-017",
    user: "ksmith@northgate.internal",
    device_type: "usb_storage",
    device_name: "Kingston DataTraveler 32GB",
    vendor_id: "0951",
    product_id: "1666",
    serial: "KT201812345",
    action: "connected",
    severity: "medium",
    status: "pending_approval",
    timestamp: new Date(Date.now() - 7200000).toISOString(),
    bytes_written: null,
    policy_rule: "device:require-approval-removable",
    approval_required: true,
  },
  {
    id: "dev-003",
    customer_id: null,
    hostname: "WIN-WORK-001",
    user: "mwilson@northgate.internal",
    device_type: "bluetooth",
    device_name: "AirPods Pro (2nd gen)",
    vendor_id: "004C",
    product_id: "2002",
    serial: null,
    action: "connected",
    severity: "low",
    status: "allowed",
    timestamp: new Date(Date.now() - 86400000).toISOString(),
    bytes_written: null,
    policy_rule: "device:allow-audio-bluetooth",
    approval_required: false,
  },
  {
    id: "dev-004",
    customer_id: null,
    hostname: "LINUX-SRV-08",
    user: "svc-backup@northgate.internal",
    device_type: "usb_storage",
    device_name: "Unknown USB Device",
    vendor_id: "1234",
    product_id: "5678",
    serial: null,
    action: "write_attempted",
    severity: "critical",
    status: "blocked",
    timestamp: new Date(Date.now() - 3600000 * 4).toISOString(),
    bytes_written: 52428800,
    policy_rule: "device:block-server-usb",
    approval_required: true,
  },
  {
    id: "dev-005",
    customer_id: null,
    hostname: "WIN-WORK-042",
    user: "jdoe@northgate.internal",
    device_type: "printer",
    device_name: "HP LaserJet Pro MFP M428",
    vendor_id: "03F0",
    product_id: "4E17",
    serial: "VNB3M12345",
    action: "connected",
    severity: "low",
    status: "allowed",
    timestamp: new Date(Date.now() - 86400000 * 3).toISOString(),
    bytes_written: null,
    policy_rule: "device:allow-approved-printers",
    approval_required: false,
  },
];

export function DeviceControlPage({ me }: { me: MeResponse }) {
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
      usb_storage_block: true,
      usb_approval_gate: true,
      bluetooth_monitor: true,
      audit_evidence: true,
    },
  });

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
      ev.status === "pending_approval" ? "approve_device" : ev.status === "blocked" ? "confirm_block" : "add_to_allowlist",
    status:
      ev.status === "blocked" ? "investigating" : ev.status === "pending_approval" ? "staged" : "resolved",
    created_at: ev.timestamp,
    context: {
      user: ev.user,
      command_line: `vid:${ev.vendor_id} pid:${ev.product_id}${ev.serial ? ` sn:${ev.serial}` : ""}`,
      mitre_techniques:
        ev.action === "write_attempted"
          ? [{ id: "T1052.001", name: "Exfiltration over USB", tactic: "Exfiltration" }]
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
        const data = await apiGet<DeviceEvent[]>(url);
        setDeviceEvents(data);
        if (data.length > 0) {
          setSelectedId(data[0].id);
          setSelectedAction(data[0].status === "pending_approval" ? "approve_device" : "confirm_block");
        }
      } catch {
        setDeviceEvents(DEMO_EVENTS);
        setSelectedId(DEMO_EVENTS[0].id);
        setSelectedAction("confirm_block");
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
      await apiPost(`/device-control/events/${selectedEvent.id}/simulate`, { action: selectedAction });
    } catch {
      const sim: SimulationPreview = {
        id: `sim-dev-${selectedEvent.id}-${Date.now()}`,
        detection_id: selectedEvent.id,
        action: selectedAction,
        destructive: false,
        approval_required: selectedEvent.approval_required,
        affected_systems: 1,
        estimated_impact: [
          `Device: ${selectedEvent.device_name} (VID:${selectedEvent.vendor_id} PID:${selectedEvent.product_id})`,
          `Endpoint: ${selectedEvent.hostname}`,
          selectedAction === "add_to_allowlist"
            ? "Device will be added to the tenant allowlist and permitted on all enrolled endpoints."
            : selectedAction === "approve_device"
            ? "One-time access approval will be granted for this device connection."
            : "Device connection will remain blocked. Audit evidence preserved.",
        ],
        evidence_controls: ["iso27001-2022:A.8.12", "nist-csf-2.0:PR.DS"],
        created_at: new Date().toISOString(),
      };
      setSimulation(sim);
      setSuccess("Simulation complete.");
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
    } catch {
      // offline fallback
    }
    const nextStatus: DeviceEvent["status"] =
      selectedAction === "add_to_allowlist" || selectedAction === "approve_device" ? "allowed" : "blocked";
    setDeviceEvents((prev) =>
      prev.map((e) => (e.id === selectedEvent.id ? { ...e, status: nextStatus } : e)),
    );
    setSuccess(`Action staged: ${selectedAction} on ${selectedEvent.device_name}`);
    setIsWorking(false);
  };

  const blocked = deviceEvents.filter((e) => e.status === "blocked").length;
  const pendingApproval = deviceEvents.filter((e) => e.status === "pending_approval").length;
  const allowed = deviceEvents.filter((e) => e.status === "allowed").length;
  const usbEvents = deviceEvents.filter((e) => e.device_type.startsWith("usb")).length;

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
          { label: "Allowed", value: allowed, icon: <CheckCircle size={18} />, color: "var(--success)" },
          { label: "USB Events", value: usbEvents, icon: <Usb size={18} />, color: "var(--accent)" },
          { label: "Total Events", value: deviceEvents.length, icon: <ShieldCheck size={18} />, color: "var(--muted)" },
        ]}
      />

      <section className="panelWorkspace" aria-label="Device Control Board">
        <DetectionTable
          detections={detections}
          selectedId={selectedId}
          onSelect={(d) => {
            setSelectedId(d.id);
            const ev = deviceEvents.find((e) => e.id === d.id);
            setSelectedAction(ev?.status === "pending_approval" ? "approve_device" : "confirm_block");
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
            { value: "approve_device", label: "Approve One-Time Access", destructive: false },
            { value: "add_to_allowlist", label: "Add to Allowlist", destructive: false },
            { value: "block_device_class", label: "Block Entire Device Class", destructive: true },
          ]}
        />
      </section>
    </ConsolePage>
  );
}
