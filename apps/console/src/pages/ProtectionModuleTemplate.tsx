import React, { useState, useEffect } from "react";
import { ShieldCheck, RefreshCw, AlertTriangle, PlayCircle, Eye, Info, Clock, PlusCircle } from "lucide-react";
import { ModuleHeader } from "../components/protection/ModuleHeader";
import { DetectionTable } from "../components/protection/DetectionTable";
import { DetailPanel } from "../components/protection/DetailPanel";
import { ActionStagingPanel } from "../components/protection/ActionStagingPanel";
import { LoadingState, EmptyState } from "../components/protection/EmptyState";
import { Detection, StagedAction, SimulationPreview, EffectivePolicy } from "../components/protection/types";
import { ErrorBanner, SuccessBanner, PageHeader } from "../components";

/**
 * ProtectionModuleTemplate
 * 
 * A reusable page layout for security compliance modules within the Aetherix Console.
 * It demonstrates integration between:
 * 1. Policy Sync Status Header
 * 2. Risk telemetry / Alarm queues
 * 3. Side-by-side interactive detail analysis panels
 * 4. Staged containment actions with dry runs & confirmations
 */
export default function ProtectionModuleTemplate() {
  // 1. Core Component States
  const [isLoading, setIsLoading] = useState(true);
  const [isSyncing, setIsSyncing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  // 2. Integration / Domain States
  const [policy, setPolicy] = useState<EffectivePolicy>({
    policy_version: "v2.10.4",
    last_updated: new Date(Date.now() - 3600000).toISOString(), // 1hr ago
    status: "protected",
    approval_required: true,
    controls: {
      "block_unauthorized_removable_media": true,
      "audit_write_connections": true,
      "encryption_enforcement": true,
    },
  });

  const [detections, setDetections] = useState<Detection[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [selectedAction, setSelectedAction] = useState<string>("");
  const [simulation, setSimulation] = useState<SimulationPreview | null>(null);
  const [stagedActions, setStagedActions] = useState<StagedAction[]>([]);
  const [isWorking, setIsWorking] = useState(false);
  const [confirmRequest, setConfirmRequest] = useState<{ detection: Detection; action: string } | null>(null);

  // 3. Mock Data Loader (Replace with backend API integration pattern)
  useEffect(() => {
    const timer = setTimeout(() => {
      const mockDetections: Detection[] = [
        {
          id: "rule-media-01",
          endpoint_id: "agent-ny-01",
          endpoint_name: "NY-DESKTOP-882",
          title: "Unauthorized USB Storage Attachment Attempt",
          source: "Device Control",
          description: "A block-tier USB mass storage device was mounted by user 'j.smith'. The system interdicted write access.",
          risk_score: 82,
          risk_band: "high",
          confidence: 94,
          recommended_action: "quarantine_drive",
          status: "new",
          created_at: new Date(Date.now() - 60000).toISOString(),
          context: {
            user: "j.smith",
            command_line: "cmd.exe /c cp -r C:\\Sensitive-Customer-Data F:\\",
            file_hashes: [
              { algorithm: "sha256", value: "f295bc10aef92cd611985bd3a2e99f018e69ac3a4911dcaeef234f9a39a2be91", reputation: "suspicious" }
            ],
            mitre_techniques: [
              { id: "T1052", name: "Exfiltration Over Physical Medium", tactic: "Exfiltration" }
            ],
          },
        },
        {
          id: "rule-encryption-02",
          endpoint_id: "agent-ldn-04",
          endpoint_name: "LDN-LAPTOP-510",
          title: "BitLocker Encryption Unenforced on Primary Disk",
          source: "Security Compliance Rules",
          description: "Full disk encryption has been suspended or turned off by local administrative override.",
          risk_score: 64,
          risk_band: "medium",
          confidence: 100,
          recommended_action: "re_enable_encryption",
          status: "new",
          created_at: new Date(Date.now() - 180000).toISOString(),
          context: {
            user: "admin.local",
            command_line: "manage-bde.exe -off C:",
            mitre_techniques: [
              { id: "T1562", name: "Impair Defenses", tactic: "Defense Evasion" }
            ]
          }
        }
      ];

      setDetections(mockDetections);
      if (mockDetections.length > 0) {
        setSelectedId(mockDetections[0].id);
        setSelectedAction(mockDetections[0].recommended_action);
      }
      setIsLoading(false);
    }, 1000);

    return () => clearTimeout(timer);
  }, []);

  // 4. Shared Actions / Event Handlers
  const selectedDetection = detections.find((d) => d.id === selectedId) || null;

  const handleSyncPolicy = async () => {
    setIsSyncing(true);
    setError(null);
    try {
      // Simulate API Policy fetch
      await new Promise((resolve) => setTimeout(resolve, 800));
      setPolicy((prev) => ({
        ...prev,
        last_updated: new Date().toISOString(),
      }));
      setSuccess("Effective active compliance policies updated from Policy Engine v2 successfully.");
    } catch (e) {
      setError("Failed to fetch fresh compliance schemas from endpoint. Check server peer logs.");
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
      // Mimics backend simulate endpoint POST /module/simulate
      await new Promise((resolve) => setTimeout(resolve, 600));
      const simulated: SimulationPreview = {
        id: `sim-run-${Date.now()}`,
        detection_id: selectedDetection.id,
        action: selectedAction,
        destructive: selectedAction === "quarantine_drive" || selectedAction === "disable_host_nic",
        approval_required: policy.approval_required || selectedAction === "isolate_endpoint",
        affected_systems: 1,
        estimated_impact: [
          `Action: ${selectedAction.replaceAll("_", " ")} would target device F: on target endpoint ${selectedDetection.endpoint_name}.`,
          "Host background monitoring tasks would log cryptographic handshake verification identifiers.",
          "Target will undergo local storage interdiction verification checks."
        ],
        evidence_controls: ["nist-csf-2.0:PR.DS", "iso27001-2022:A.8.20"],
        created_at: new Date().toISOString(),
      };
      setSimulation(simulated);
      setSuccess("Dry run policy simulation succeeded.");
    } catch {
      setError("Direct simulation trigger failed.");
    } finally {
      setIsWorking(false);
    }
  };

  const stageAction = async (confirmed = false) => {
    if (!selectedDetection) return;

    const isDestructive = selectedAction === "quarantine_drive" || selectedAction === "disable_host_nic";
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
      status: policy.approval_required ? "awaiting_approval" : "queued",
      approval_required: policy.approval_required,
      requested_by: "secops-operator@aetherix-msp.com",
      created_at: new Date().toISOString(),
      note: simulation ? "Local policy dry-run verification completed" : "Manual compliance override"
    };

    // Append optimistic action
    setStagedActions((current) => [optimistic, ...current]);
    
    // Update detection status to staged
    setDetections((current) =>
      current.map((d) => (d.id === selectedDetection.id ? { ...d, status: "staged" } : d))
    );

    try {
      // Simulate backend POST request
      await new Promise((resolve) => setTimeout(resolve, 800));
      setSuccess(`Response decision staged for approval on agent ${selectedDetection.endpoint_name}.`);
    } catch {
      setSuccess("Action staged locally in browser queue. Awaiting broker network reconnection.");
    } finally {
      setIsWorking(false);
      setConfirmRequest(null);
    }
  };

  const handleActionChange = (action: string) => {
    setSelectedAction(action);
    setSimulation(null); // Reset preview on action update to drive verification
  };

  if (isLoading) {
    return (
      <div style={{ padding: "40px", width: "100%" }}>
        <LoadingState message="Retrieving compliance telemetry from agent registries..." />
      </div>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", flex: 1, padding: "24px", boxSizing: "border-box" }}>
      
      {/* 5. Module Header Integration */}
      <ModuleHeader
        title="Device Control & Security Compliance"
        eyebrow="Endpoint Protection Module"
        icon={ShieldCheck}
        status={policy.status}
        policyVersion={policy.policy_version}
        policyLastSynced={policy.last_updated}
        onRefresh={handleSyncPolicy}
        isRefreshing={isSyncing}
        quickActions={[
          {
            label: "Initiate Sweep Scan",
            icon: RefreshCw,
            onClick: () => {
              setSuccess("Initiated device validation sweep query across scoped agents.");
            },
            variant: "secondary",
            disabled: isWorking,
          },
        ]}
      />

      {/* Notifications Row */}
      {error && <ErrorBanner message={error} />}
      {success && <SuccessBanner message={success} />}

      {/* Grid of Highlights/Metrics Cards */}
      <section
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))",
          gap: "16px",
          marginBottom: "24px",
        }}
        aria-label="Compliance Summary Statistics"
      >
        <div className="panel" style={{ padding: "16px", display: "flex", alignItems: "center", gap: "12px", background: "rgba(11, 107, 87, 0.02)" }}>
          <div style={{ color: "var(--accent)" }}><ShieldCheck size={20} /></div>
          <div>
            <div style={{ fontSize: "12px", color: "var(--muted)" }}>Module Mode</div>
            <strong style={{ fontSize: "16px" }}>Enforcement Tier Active</strong>
          </div>
        </div>
        <div className="panel" style={{ padding: "16px", display: "flex", alignItems: "center", gap: "12px" }}>
          <div style={{ color: "var(--warning)" }}><AlertTriangle size={20} /></div>
          <div>
            <div style={{ fontSize: "12px", color: "var(--muted)" }}>Active Warnings</div>
            <strong style={{ fontSize: "16px" }}>{detections.filter((d) => d.status === "new").length} Issues Pending</strong>
          </div>
        </div>
        <div className="panel" style={{ padding: "16px", display: "flex", alignItems: "center", gap: "12px" }}>
          <div><Clock size={20} style={{ color: "var(--muted)" }} /></div>
          <div>
            <div style={{ fontSize: "12px", color: "var(--muted)" }}>Approval Workflow</div>
            <strong style={{ fontSize: "16px" }}>{policy.approval_required ? "MSP Multi-Gate Gatekeeper" : "Automatic Execution"}</strong>
          </div>
        </div>
      </section>

      {/* 6. Three-Panel Layout (Work Area) */}
      <section
        style={{
          display: "flex",
          flexWrap: "wrap",
          gap: "16px",
          alignItems: "stretch",
          flex: 1,
        }}
        aria-label="Device Rules Management Core Console"
      >
        {/* Panel A: Detection Alarm List Queue */}
        <DetectionTable
          detections={detections}
          selectedId={selectedId}
          onSelect={(d) => {
            setSelectedId(d.id);
            handleActionChange(d.recommended_action);
          }}
          isLoading={isLoading}
        />

        {/* Panel B: Analytical Side panel Context */}
        <DetailPanel detection={selectedDetection} />

        {/* Panel C: Decision Action Hub & Staging Terminal */}
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
            { value: "quarantine_drive", label: "Quarantine & Interdict USB device", destructive: true },
            { value: "re_enable_encryption", label: "Re-enable Boot Volume Encryption", destructive: false },
            { value: "disable_host_nic", label: "Isolate Endpoint from Router Bridge", destructive: true },
            { value: "dismiss_alert", label: "Dismiss compliance warning manually", destructive: false },
          ]}
        />
      </section>

      {/* Policy Exclusions & Timeline Grid Section */}
      <section
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))",
          gap: "16px",
          marginTop: "24px",
        }}
      >
        {/* Exclusion Manager */}
        <article className="panel">
          <div className="panelHeader" style={{ borderBottom: "1px solid var(--line)", paddingBottom: "10px", marginBottom: "12px" }}>
            <h2 style={{ fontSize: "14px", margin: 0 }}>Approved Global Exclusions</h2>
            <span style={{ fontSize: "11px", color: "var(--muted)" }}>No local overrides are applied if matched here</span>
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: "8px", fontSize: "12px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", background: "rgba(11, 107, 87, 0.01)", padding: "8px", borderRadius: "6px", border: "1px solid var(--line)" }}>
              <code>USB-VID_0951&PID_1666</code>
              <span style={{ color: "var(--muted)" }}>Corporate Kingston Key Standard</span>
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", background: "rgba(11, 107, 87, 0.01)", padding: "8px", borderRadius: "6px", border: "1px solid var(--line)" }}>
              <code>C:\Program Files\BackupAgent\*</code>
              <span style={{ color: "var(--muted)" }}>Global Backup Service Excludes</span>
            </div>
          </div>
        </article>

        {/* Global Policy Config Toggles */}
        <article className="panel">
          <div className="panelHeader" style={{ borderBottom: "1px solid var(--line)", paddingBottom: "10px", marginBottom: "12px" }}>
            <h2 style={{ fontSize: "14px", margin: 0 }}>Policy Engine Config Map</h2>
            <span style={{ fontSize: "11px", color: "var(--muted)" }}>Effective Policy Engine parameters</span>
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

      {/* Destructive Action Modal Backdrop */}
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
              You are staging an action (<strong>{confirmRequest.action.replaceAll("_", " ")}</strong>) with high-density system modification impact metrics on endpoint <strong>{confirmRequest.detection.endpoint_name}</strong>. This can disconnect system interfaces or lock mass storage channels.
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
    </div>
  );
}
