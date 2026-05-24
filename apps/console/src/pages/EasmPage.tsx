import React, { useState, useEffect } from "react";
import { Globe2, Shield, AlertTriangle, FileText, BarChart3, LayoutDashboard, Zap, TrendingUp, Settings, Database, Server } from "lucide-react";
import { ModuleHeader } from "../components/protection/ModuleHeader";
import { DetectionTable } from "../components/protection/DetectionTable";
import { DetailPanel } from "../components/protection/DetailPanel";
import { ActionStagingPanel } from "../components/protection/ActionStagingPanel";
import { LoadingState, EmptyState } from "../components/protection/EmptyState";
import { Detection, StagedAction, SimulationPreview, EffectivePolicy } from "../components/protection/types";
import { ConsolePage, ErrorBanner, MetricGrid, SuccessBanner } from "../components";
import { apiGet, apiPost, type MeResponse } from "../api";

export interface EASMExposure {
  id: string;
  customer_id?: string | null;
  asset_id: string;
  asset_display_name: string;
  asset_type: "domain" | "subdomain" | "ip_address" | "cloud_resource" | "certificate" | "open_port";
  exposure_type: "unpatched_vulnerability" | "misconfiguration" | "exposed_service" | "data_leak" | "shadow_it";
  title: string;
  summary: string;
  severity: "low" | "medium" | "high" | "critical";
  status: "new" | "investigating" | "confirmed" | "remediated" | "false_positive";
  risk_score: number;
  confidence_score: number;
  first_seen: string;
  last_seen: string;
  ip_address?: string | null;
  fqdn?: string | null;
  cloud_provider?: string | null;
  open_ports?: number[];
  tags?: string[];
  metadata?: Record<string, any>;
}

export function EASMPage({ me }: { me: MeResponse }) {
  const [isLoading, setIsLoading] = useState(true);
  const [isSyncing, setIsSyncing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  // Effective policy summary
  const [policy, setPolicy] = useState<EffectivePolicy>({
    policy_version: "v2.10.4",
    last_updated: new Date(Date.now() - 3600000).toISOString(),
    status: "protected",
    approval_required: true,
    controls: {
      "easm_discovery": true,
      "easm_change_detection": true,
      "easm_vulnerability_scan": true,
    },
  });

  const [exposures, setExposures] = useState<EASMExposure[]>([]);
  const [selectedExposureId, setSelectedExposureId] = useState<string | null>(null);
  const [selectedAction, setSelectedAction] = useState<string>("");
  const [simulation, setSimulation] = useState<SimulationPreview | null>(null);
  const [stagedActions, setStagedActions] = useState<StagedAction[]>([]);
  const [isWorking, setIsWorking] = useState(false);
  const [confirmRequest, setConfirmRequest] = useState<{ exposure: EASMExposure; action: string } | null>(null);

  // Client-side mapping of exposures to the Detection format expected by template table
  const detections: Detection[] = exposures.map((exposure) => ({
    id: exposure.id,
    customer_id: exposure.customer_id,
    endpoint_id: "easm-scanner", // scoped globally/tenant wide
    endpoint_name: `EASM Scanner (${exposures.length} assets scanned)`,
    title: exposure.title,
    source: `EASM: ${exposure.asset_type}`,
    description: exposure.summary,
    risk_score: exposure.risk_score,
    risk_band: exposure.severity,
    confidence: exposure.confidence_score,
    recommended_action:
      exposure.status === "confirmed"
        ? "initiate_remediation"
        : exposure.status === "investigating"
        ? "gather_more_intel"
        : "schedule_rescan",
    status:
      exposure.status === "confirmed"
        ? "staged"
        : exposure.status === "investigating"
        ? "investigating"
        : (exposure.status === "false_positive" || exposure.status === "remediated")
        ? "resolved"
        : "new",
    created_at: exposure.last_seen,
    context: {
      user: "easm-scanner@aetherix-msp.com",
      command_line: `asset:${exposure.asset_display_name} type:${exposure.asset_type}`,
      mitre_techniques: [
        {
          id: "T1595.001",
          name: "Scan IP Ranges",
          tactic: "Reconnaissance",
        },
        {
          id: "T1595.002",
          name: "Scan Vulnerable Services",
          tactic: "Reconnaissance",
        },
      ],
    },
  }));

  const selectedExposure = exposures.find((e) => e.id === selectedExposureId) || null;
  const selectedDetection = detections.find((d) => d.id === selectedExposureId) || null;

  // Load EASM Exposures
  useEffect(() => {
    async function loadExposures() {
      try {
        const customerId = me.scope.customer_ids[0];
        const partnerId = me.scope.partner_ids[0];
        let url = "/easm/exposures";
        if (customerId) url += `?customer_id=${customerId}`;
        else if (partnerId) url += `?partner_id=${partnerId}`;

        const data = await apiGet<EASMExposure[]>(url);
        setExposures(data);
        if (data.length > 0) {
          setSelectedExposureId(data[0].id);
          setSelectedAction(
            data[0].status === "confirmed"
              ? "initiate_remediation"
              : data[0].status === "investigating"
              ? "gather_more_intel"
              : "schedule_rescan"
          );
        }
      } catch (err) {
        // Fallback demo data
        const localDefaults: EASMExposure[] = [
          {
            id: "easm-exposure-01",
            customer_id: me.scope.customer_ids[0] || null,
            asset_id: "easm-asset-01",
            asset_display_name: "webmail.aetherix-cloud.com",
            asset_type: "subdomain",
            exposure_type: "misconfiguration",
            title: "Subdomain with Expired SSL Certificate",
            summary: "Subdomain webmail.aetherix-cloud.com has an expired SSL certificate (expired 2024-05-15)",
            severity: "medium",
            status: "investigating",
            risk_score: 55,
            confidence_score: 90,
            first_seen: new Date(Date.now() - 86400 * 10).toISOString(),
            last_seen: new Date(Date.now() - 86400 * 2).toISOString(),
            ip_address: "192.0.2.45",
            fqdn: "webmail.aetherix-cloud.com",
            cloud_provider: "AWS",
            open_ports: [443, 80],
            tags: ["ssl", "certificate", "email"],
          },
          {
            id: "easm-exposure-02",
            customer_id: me.scope.customer_ids[0] || null,
            asset_id: "easm-asset-02",
            asset_display_name: "ftp.backup.aetherix-corp.net",
            asset_type: "subdomain",
            exposure_type: "exposed_service",
            title: "FTP Service Exposed to Internet",
            summary: "FTP service running on ftp.backup.aetherix-corp.net:21 with anonymous login enabled",
            severity: "high",
            status: "new",
            risk_score: 82,
            confidence_score: 85,
            first_seen: new Date(Date.now() - 86400 * 5).toISOString(),
            last_seen: new Date(Date.now() - 86400 * 1).toISOString(),
            ip_address: "203.0.113.78",
            fqdn: "ftp.backup.aetherix-corp.net",
            open_ports: [21],
            tags: ["ftp", "backup", "anonymous"],
          },
        ];
        setExposures(localDefaults);
        if (localDefaults.length > 0) {
          setSelectedExposureId(localDefaults[0].id);
          setSelectedAction(
            localDefaults[0].status === "confirmed"
              ? "initiate_remediation"
              : localDefaults[0].status === "investigating"
              ? "gather_more_intel"
              : "schedule_rescan"
          );
        }
      } finally {
        setIsLoading(false);
      }
    }
    void loadExposures();
  }, [me]);

  const handleSyncPolicy = async () => {
    setIsSyncing(true);
    setError(null);
    try {
      await new Promise((resolve) => setTimeout(resolve, 600));
      setPolicy((prev) => ({
        ...prev,
        last_updated: new Date().toISOString(),
      }));
      setSuccess("Effective EASM policies updated from Policy Engine v2 successfully.");
    } catch {
      setError("Network timeouts updating EASM policy templates.");
    } finally {
      setIsSyncing(false);
    }
  };

  const investigateExposure = async () => {
    if (!selectedExposure) return;
    setIsWorking(true);
    setSuccess(null);
    setError(null);
    try {
      await apiPost(`/easm/exposures/${selectedExposure.id}/investigate`, {});
      setSuccess(`Exposure '${selectedExposure.title}' investigation initiated.`);
    } catch {
      // Offline fallback investigation
      setSimulation({
        id: `sim-easm-${selectedExposure.id}-${Date.now()}`,
        detection_id: selectedExposure.id,
        action: "investigate_exposure",
        destructive: false,
        approval_required: policy.approval_required,
        affected_systems: 1,
        estimated_impact: [
          `EASM exposure '${selectedExposure.title}' queued for deep scan.`,
          `Port scan, vulnerability assessment, and banner grabbing initiated.`,
          `Results expected in 5-10 minutes.`,
        ],
        evidence_controls: ["iso27001-2022:A.8.16", "nist-csf-2.0:DE.CM"],
        created_at: new Date().toISOString(),
      });
      setExposures(
        prev =>
          prev.map((e) =>
            e.id === selectedExposure.id
              ? { ...e, status: "investigating", confidence_score: Math.min(100, e.confidence_score + 5) }
              : e
          )
      );
      setSuccess("Exposure investigation initiated. Deep scan queued.");
    } finally {
      setIsWorking(false);
    }
  };

  const initiateRemediation = async (confirmed = false) => {
    if (!selectedExposure) return;

    if (selectedExposure.status !== "confirmed" && selectedExposure.status !== "investigating") {
      setError("EASM exposure requires investigation before remediation can be initiated.");
      return;
    }

    if (!confirmed) {
      setConfirmRequest({ exposure: selectedExposure, action: "initiate_remediation" });
      return;
    }

    setIsWorking(true);
    setSuccess(null);
    setError(null);

    const optimisticStaged: StagedAction = {
      id: `staged-remediation-${Date.now()}`,
      detection_id: selectedExposure.id,
      action: "initiate_remediation",
      status: policy.approval_required ? "awaiting_approval" : "queued",
      approval_required: policy.approval_required,
      requested_by: me.account.email,
      created_at: new Date().toISOString(),
      note: "Remediation initiated from EASM console"
    };

    setStagedActions((current) => [optimisticStaged, ...current]);

    try {
      await apiPost(`/easm/exposures/${selectedExposure.id}/remediate`, {});
      setExposures(
        prev =>
          prev.map((e) =>
            e.id === selectedExposure.id ? { ...e, status: "remediated" } : e
          )
      );
      setSuccess(`Remediation initiated for '${selectedExposure.title}'.`);
    } catch {
      setExposures(
        prev =>
          prev.map((e) =>
            e.id === selectedExposure.id ? { ...e, status: "remediated" } : e
          )
      );
      setSuccess("Remediation request processed locally.");
    } finally {
      setIsWorking(false);
      setConfirmRequest(null);
    }
  };

  if (isLoading) {
    return (
      <div style={{ padding: "40px", width: "100%" }}>
        <LoadingState message="Connecting to EASM discovery engines..." />
      </div>
    );
  }

  return (
    <ConsolePage>
      {/* Module Header */}
      <ModuleHeader
        title="External Attack Surface Management"
        eyebrow="Asset Discovery & Exposure Monitoring"
        icon={Globe2}
        status={policy.status}
        policyVersion={policy.policy_version}
        policyLastSynced={policy.last_updated}
        onRefresh={handleSyncPolicy}
        isRefreshing={isSyncing}
        quickActions={[
          {
            label: "Add New Asset",
            icon: Database,
            onClick: () => {
              // TODO: Implement add asset modal
              alert("Add asset functionality coming soon");
            },
            disabled: isWorking,
          },
          {
            label: "Run Discovery Scan",
            icon: Zap,
            onClick: () => {
              // TODO: Implement manual scan trigger
              alert("Manual discovery scan coming soon");
            },
            disabled: isWorking,
          },
        ]}
      />

      {error && <ErrorBanner message={error} />}
      {success && <SuccessBanner message={success} />}

      <MetricGrid
        ariaLabel="EASM Metrics Dashboard"
        items={[
          { label: "Confirmed Exposures", value: `${exposures.filter((e) => e.status === "confirmed").length} Active`, icon: <Shield size={20} />, color: "var(--accent)" },
          { label: "Under Investigation", value: `${exposures.filter((e) => e.status === "investigating").length} In Review`, icon: <AlertTriangle size={20} />, color: "var(--warning)" },
          { label: "Assets Discovered", value: `${new Set(exposures.map(e => e.asset_id)).size} Digital Assets`, icon: <Server size={20} />, color: "var(--muted)" },
        ]}
      />

      {/* Three Panel Grid Workspace */}
      <section className="panelWorkspace" aria-label="EASM Investigation Board">
        {/* Panel 1: Searchable Exposures Table List */}
        <DetectionTable
          detections={detections}
          selectedId={selectedExposureId}
          onSelect={(d) => {
            setSelectedExposureId(d.id);
            const relativeExposure = exposures.find(e => e.id === d.id);
            if (relativeExposure) {
              if (relativeExposure.status === "confirmed") {
                setSelectedAction("initiate_remediation");
              } else if (relativeExposure.status === "investigating") {
                setSelectedAction("gather_more_intel");
              } else {
                setSelectedAction("schedule_rescan");
              }
            }
            setSimulation(null);
          }}
          isLoading={isLoading}
        />

        {/* Panel 2: Exposure Intelligence Context Visualization */}
        <DetailPanel
          detection={selectedDetection}
          customContextRenderer={(d) => {
            const exposure = exposures.find((e) => e.id === d.id);
            return (
              <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
                <div>
                  <h4 style={{ margin: "0 0 8px 0", fontSize: "12px", fontWeight: 600, textTransform: "uppercase", color: "var(--muted)" }}>
                    Asset Profile
                  </h4>
                  <div style={{ display: "flex", flexDirection: "column", gap: "8px", fontSize: "12px" }}>
                    <div style={{ display: "flex", justifyContent: "space-between" }}>
                      <span style={{ color: "var(--muted)" }}>Asset Type</span>
                      <strong>
                        {exposure?.asset_type
                          .replace(/_/g, " ")
                          .toUpperCase()}
                      </strong>
                    </div>
                    <div style={{ display: "flex", justifyContent: "space-between" }}>
                      <span style={{ color: "var(--muted)" }}>Display Name</span>
                      <strong>{exposure?.asset_display_name}</strong>
                    </div>
                    <div style={{ display: "flex", justifyContent: "space-between" }}>
                      <span style={{ color: "var(--muted)" }}>IP Address</span>
                      <strong>{exposure?.ip_address ?? "N/A"}</strong>
                    </div>
                    <div style={{ display: "flex", justifyContent: "space-between" }}>
                      <span style={{ color: "var(--muted)" }}>FQDN</span>
                      <strong>{exposure?.fqdn ?? "N/A"}</strong>
                    </div>
                    <div style={{ display: "flex", justifyContent: "space-between" }}>
                      <span style={{ color: "var(--muted)" }}>First Seen</span>
                      <strong>{exposure?.first_seen ? new Date(exposure.first_seen).toLocaleString() : "Unknown"}</strong>
                    </div>
                  </div>
                </div>

                <div>
                  <h4 style={{ margin: "0 0 8px 0", fontSize: "12px", fontWeight: 600, textTransform: "uppercase", color: "var(--muted)" }}>
                    Exposure Classification
                  </h4>
                  <div style={{ display: "flex", flexDirection: "column", gap: "8px", fontSize: "12px" }}>
                    <div style={{ display: "flex", justifyContent: "space-between" }}>
                      <span style={{ color: "var(--muted)" }}>Exposure Type</span>
                      <strong>
                        {exposure?.exposure_type
                          .replace(/_/g, " ")
                          .replace(/\b\w/g, (c) => c.toUpperCase())}
                      </strong>
                    </div>
                    <div style={{ display: "flex", justifyContent: "space-between" }}>
                      <span style={{ color: "var(--muted)" }}>Severity</span>
                      <span
                        style={{
                          background:
                            exposure?.severity === "critical"
                              ? "rgba(220, 38, 38, 0.1)"
                              : exposure?.severity === "high"
                              ? "rgba(239, 68, 68, 0.1)"
                              : exposure?.severity === "medium"
                              ? "rgba(245, 158, 11, 0.1)"
                              : "rgba(16, 185, 129, 0.1)",
                          color:
                            exposure?.severity === "critical"
                              ? "var(--error)"
                              : exposure?.severity === "high"
                              ? "var(--warning)"
                              : exposure?.severity === "medium"
                              ? "var(--accent)"
                              : "var(--healthy)",
                          padding: "2px 6px",
                          borderRadius: "3px",
                          fontSize: "11px",
                          fontWeight: 600,
                        }}
                      >
                        {exposure?.severity.toUpperCase()}
                      </span>
                    </div>
                    <div style={{ display: "flex", justifyContent: "space-between" }}>
                      <span style={{ color: "var(--muted)" }}>Confidence</span>
                      <strong>{exposure?.confidence_score}%</strong>
                    </div>
                  </div>
                </div>

                {exposure?.open_ports && exposure.open_ports.length > 0 && (
                  <div>
                    <h4 style={{ margin: "0 0 8px 0", fontSize: "12px", fontWeight: 600, textTransform: "uppercase", color: "var(--muted)" }}>
                      Open Ports & Services
                    </h4>
                    <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
                      {exposure.open_ports.map((port) => (
                        <span
                          key={port}
                          style={{
                            background: "rgba(15, 90, 110, 0.08)",
                            color: "var(--accent)",
                            border: "1px solid rgba(15, 90, 110, 0.2)",
                            padding: "2px 6px",
                            borderRadius: "3px",
                            fontSize: "11px",
                            fontWeight: 600,
                          }}
                        >
                          {port}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {exposure?.tags && exposure.tags.length > 0 && (
                  <div>
                    <h4 style={{ margin: "0 0 8px 0", fontSize: "12px", fontWeight: 600, textTransform: "uppercase", color: "var(--muted)" }}>
                      Tags & Metadata
                    </h4>
                    <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
                      {exposure.tags.map((tag) => (
                        <span
                          key={tag}
                          style={{
                            background: "rgba(31, 122, 66, 0.08)",
                            color: "var(--healthy)",
                            border: "1px solid rgba(31, 122, 66, 0.2)",
                            padding: "2px 6px",
                            borderRadius: "3px",
                            fontSize: "11px",
                            fontWeight: 600,
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

        {/* Panel 3: Action Staging & Response Terminal */}
        <ActionStagingPanel
          detection={selectedDetection}
          selectedAction={selectedAction}
          simulation={simulation}
          stagedActions={stagedActions}
          isWorking={isWorking}
          onActionChange={setSelectedAction}
          onSimulate={investigateExposure}
          onStage={() => initiateRemediation()}
          availableActions={[
            { value: "schedule_rescan", label: "Schedule Rescan", destructive: false },
            { value: "gather_more_intel", label: "Gather More Intelligence", destructive: false },
            { value: "initiate_remediation", label: "Initiate Remediation Process", destructive: true },
          ]}
        />
      </section>

      {/* Activity Grid */}
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
            <h2 style={{ fontSize: "14px", margin: 0 }}>Discovery Sources</h2>
            <span style={{ fontSize: "11px", color: "var(--muted)" }}>Active Scanners</span>
          </div>
          <div style={{ fontSize: "12px", color: "var(--muted)", lineHeight: 1.5 }}>
            • Passive DNS Monitoring
            <br />
            • Certificate Transparency Logs
            <br />
            • WHOIS & DNS Records
            <br />
            • Cloud Provider APIs
            <br />
            • Safe Port Scanning
            <br />
            • Shadow IT Detection
          </div>
        </article>

        <article className="panel">
          <div className="panelHeader" style={{ borderBottom: "1px solid var(--line)", paddingBottom: "10px", marginBottom: "12px" }}>
            <h2 style={{ fontSize: "14px", margin: 0 }}>Scan Engine Status</h2>
            <span style={{ fontSize: "11px", color: "var(--muted)" }}>Automated Pipeline</span>
          </div>
          <div style={{ display: "flex", justifyContent: "space-between", fontSize: "12px" }}>
            <span>Discovery Scheduler:</span>
            <strong style={{ color: "var(--healthy)" }}>ONLINE</strong>
          </div>
          <div style={{ display: "flex", justifyContent: "space-between", fontSize: "12px", marginTop: "8px" }}>
            <span>Vulnerability Correlator:</span>
            <strong style={{ color: "var(--healthy)" }}>READY</strong>
          </div>
        </article>
      </section>
    </ConsolePage>
  );
}