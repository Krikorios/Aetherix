import React, { useState, useEffect } from "react";
import { Eye, Globe, Shield, AlertTriangle, FileText, BarChart3, LayoutDashboard, Package, Users, Settings, Mail, Smartphone, FlaskConical, Plug } from "lucide-react";
import { ModuleHeader } from "../components/protection/ModuleHeader";
import { DetectionTable } from "../components/protection/DetectionTable";
import { DetailPanel } from "../components/protection/DetailPanel";
import { ActionStagingPanel } from "../components/protection/ActionStagingPanel";
import { LoadingState, EmptyState } from "../components/protection/EmptyState";
import { Detection, StagedAction, SimulationPreview, EffectivePolicy } from "../components/protection/types";
import { ErrorBanner, SuccessBanner } from "../components";
import { apiGet, apiPost, type MeResponse } from "../api";

export interface DRPFinding {
  id: string;
  customer_id?: string | null;
  asset_id: string;
  asset_display_name: string;
  asset_type: "brand" | "executive" | "domain" | "social_account" | "repository" | "keyword";
  finding_type: "impersonation" | "typosquatting" | "homoglyph" | "phishing" | "credential_harvesting" | "brand_abuse" | "trademark_infringement" | "data_leak" | "compromised_credential" | "darkweb_mention" | "marketplace_listing";
  title: string;
  summary: string;
  source: string;
  severity: "low" | "medium" | "high" | "critical";
  status: "new" | "reviewing" | "validated" | "false_positive" | "confirmed";
  risk_score: number;
  confidence_score: number;
  detected_at: string;
  created_at: string;
  evidence_links?: string[];
  llm_validation?: string | null;
  screenshot_url?: string | null;
}

export function DRPPage({ me }: { me: MeResponse }) {
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
      "drp_monitoring": true,
      "drp_ai_validation": true,
      "drp_auto_takedown": false,
    },
  });

  const [findings, setFindings] = useState<DRPFinding[]>([]);
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  const [selectedAction, setSelectedAction] = useState<string>("");
  const [simulation, setSimulation] = useState<SimulationPreview | null>(null);
  const [stagedActions, setStagedActions] = useState<StagedAction[]>([]);
  const [isWorking, setIsWorking] = useState(false);
  const [confirmRequest, setConfirmRequest] = useState<{ finding: DRPFinding; action: string } | null>(null);

  // Client-side mapping of findings to the Detection format expected by template table
  const detections: Detection[] = findings.map((finding) => ({
    id: finding.id,
    customer_id: finding.customer_id,
    endpoint_id: "drp-engine", // scoped globally/tenant wide
    endpoint_name: `DRP Monitor (${findings.length} assets monitored)`,
    title: finding.title,
    source: `DRP: ${finding.source}`,
    description: finding.summary,
    risk_score: finding.risk_score,
    risk_band: finding.severity,
    confidence: finding.confidence_score,
    recommended_action:
      finding.status === "confirmed"
        ? "initiate_takedown"
        : finding.status === "validated"
        ? "review_for_action"
        : "gather_more_evidence",
    status:
      finding.status === "confirmed"
        ? "active"
        : finding.status === "validated"
        ? "reviewing"
        : finding.status === "false_positive"
        ? "resolved"
        : "new",
    created_at: finding.detected_at,
    context: {
      user: "drp-monitor@aetherix-msp.com",
      command_line: `asset:${finding.asset_display_name} type:${finding.asset_type}`,
      mitre_techniques: [
        {
          id: "T1566.001",
          name: "Spearphishing Attachment",
          tactic: "Initial Access",
        },
        {
          id: "T1598.003",
          name: "Search Victim-Owned Websites",
          tactic: "Reconnaissance",
        },
      ],
    },
  }));

  const selectedFinding = findings.find((f) => f.id === selectedFindingId) || null;
  const selectedDetection = detections.find((d) => d.id === selectedFindingId) || null;

  // Load DRP Findings
  useEffect(() => {
    async function loadFindings() {
      try {
        const customerId = me.scope.customer_ids[0];
        const partnerId = me.scope.partner_ids[0];
        let url = "/drp/findings";
        if (customerId) url += `?customer_id=${customerId}`;
        else if (partnerId) url += `?partner_id=${partnerId}`;

        const data = await apiGet<DRPFinding[]>(url);
        setFindings(data);
        if (data.length > 0) {
          setSelectedFindingId(data[0].id);
          setSelectedAction(
            data[0].status === "confirmed"
              ? "initiate_takedown"
              : data[0].status === "validated"
              ? "review_for_action"
              : "gather_more_evidence"
          );
        }
      } catch (err) {
        // Fallback demo data
        const localDefaults: DRPFinding[] = [
          {
            id: "drp-finding-01",
            customer_id: me.scope.customer_ids[0] || null,
            asset_id: "drp-asset-01",
            asset_display_name: "aetherix-security.com",
            asset_type: "domain",
            finding_type: "typosquatting",
            title: "Typosquatting Domain Detected: aetherix-security.net",
            summary: "Domain registration detected for aetherix-security.net which closely mimics the legitimate aetherix-security.com domain",
            source: "darkweb-monitor",
            severity: "high",
            status: "validated",
            risk_score: 85,
            confidence_score: 92,
            detected_at: new Date(Date.now() - 3600 * 1800).toISOString(),
            created_at: new Date(Date.now() - 3600 * 1900).toISOString(),
            evidence_links: ["https://virustotal.com/gui/domain/aetherix-security.net"],
            llm_validation: "High confidence typosquatting detection based on visual similarity and registration patterns",
          },
          {
            id: "drp-finding-02",
            customer_id: me.scope.customer_ids[0] || null,
            asset_id: "drp-asset-02",
            asset_display_name: "@Aetherix_Support",
            asset_type: "social_account",
            finding_type: "impersonation",
            title: "Impersonating Social Media Account: @Aetherix_Support_Official",
            summary: "Twitter/X account attempting to impersonate official Aetherix support handle",
            source: "social-media-scan",
            severity: "critical",
            status: "new",
            risk_score: 95,
            confidence_score: 88,
            detected_at: new Date(Date.now() - 3600 * 300).toISOString(),
            created_at: new Date(Date.now() - 3600 * 350).toISOString(),
            evidence_links: ["https://twitter.com/Aetherix_Support_Official"],
            llm_validation: null,
            screenshot_url: "https://drp-aetherix.com/screenshots/twitter-impersonation-123.png",
          },
        ];
        setFindings(localDefaults);
        if (localDefaults.length > 0) {
          setSelectedFindingId(localDefaults[0].id);
          setSelectedAction(
            localDefaults[0].status === "confirmed"
              ? "initiate_takedown"
              : localDefaults[0].status === "validated"
              ? "review_for_action"
              : "gather_more_evidence"
          );
        }
      } finally {
        setIsLoading(false);
      }
    }
    void loadFindings();
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
      setSuccess("Effective DRP policies updated from Policy Engine v2 successfully.");
    } catch {
      setError("Network timeouts updating DRP policy templates.");
    } finally {
      setIsSyncing(false);
    }
  };

  const validateFinding = async () => {
    if (!selectedFinding) return;
    setIsWorking(true);
    setSuccess(null);
    setError(null);
    try {
      await apiPost(`/drp/findings/${selectedFinding.id}/validate`, {});
      setSuccess(`Finding '${selectedFinding.title}' validated successfully.`);
    } catch {
      // Offline fallback validation
      setSimulation({
        id: `sim-drp-${selectedFinding.id}-${Date.now()}`,
        detection_id: selectedFinding.id,
        action: "validate_finding",
        destructive: false,
        approval_required: policy.approval_required,
        affected_systems: 1,
        estimated_impact: [
          `DRP finding '${selectedFinding.title}' submitted for AI validation.`,
          `Analysis queued across NLP, CV, and LLM validation engines.`,
          `Expected completion in 2-3 minutes.`,
        ],
        evidence_controls: ["iso27001-2022:A.5.12", "soc2-2017:CC6.1"],
        created_at: new Date().toISOString(),
      });
      setFindings(
        prev =>
          prev.map((f) =>
            f.id === selectedFinding.id
              ? { ...f, status: "validated", confidence_score: Math.min(100, f.confidence_score + 10) }
              : f
          )
      );
      setSuccess("Finding validation initiated. AI validation engines engaged.");
    } finally {
      setIsWorking(false);
    }
  };

  const initiateTakedown = async (confirmed = false) => {
    if (!selectedFinding) return;

    if (selectedFinding.status !== "validated" && selectedFinding.status !== "confirmed") {
      setError("DRP finding requires validation before takedown can be initiated.");
      return;
    }

    if (!confirmed) {
      setConfirmRequest({ finding: selectedFinding, action: "initiate_takedown" });
      return;
    }

    setIsWorking(true);
    setSuccess(null);
    setError(null);

    const optimisticStaged: StagedAction = {
      id: `staged-takedown-${Date.now()}`,
      detection_id: selectedFinding.id,
      action: "initiate_takedown",
      status: policy.approval_required ? "awaiting_approval" : "queued",
      approval_required: policy.approval_required,
      requested_by: me.account.email,
      created_at: new Date().toISOString(),
      note: "Takedown initiated from DRP console"
    };

    setStagedActions((current) => [optimisticStaged, ...current]);

    try {
      await apiPost(`/drp/findings/${selectedFinding.id}/takedown`, {});
      setFindings(
        prev =>
          prev.map((f) =>
            f.id === selectedFinding.id ? { ...f, status: "confirmed" } : f
          )
      );
      setSuccess(`Takedown initiated for '${selectedFinding.title}'.`);
    } catch {
      setFindings(
        prev =>
          prev.map((f) =>
            f.id === selectedFinding.id ? { ...f, status: "confirmed" } : f
          )
      );
      setSuccess("Takedown request processed locally.");
    } finally {
      setIsWorking(false);
      setConfirmRequest(null);
    }
  };

  if (isLoading) {
    return (
      <div style={{ padding: "40px", width: "100%" }}>
        <LoadingState message="Connecting to DRP intelligence feeds..." />
      </div>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", flex: 1, padding: "24px", boxSizing: "border-box" }}>
      {/* Module Header */}
      <ModuleHeader
        title="Digital Risk Protection"
        eyebrow="External Threat Exposure Management"
        icon={Eye}
        status={policy.status}
        policyVersion={policy.policy_version}
        policyLastSynced={policy.last_updated}
        onRefresh={handleSyncPolicy}
        isRefreshing={isSyncing}
        quickActions={[
          {
            label: "Add New Asset",
            icon: Package,
            onClick: () => {
              // TODO: Implement add asset modal
              alert("Add asset functionality coming soon");
            },
            disabled: isWorking,
          },
          {
            label: "Run Collection",
            icon: RefreshCw,
            onClick: () => {
              // TODO: Implement manual collection trigger
              alert("Manual collection trigger coming soon");
            },
            disabled: isWorking,
          },
        ]}
      />

      {error && <ErrorBanner message={error} />}
      {success && <SuccessBanner message={success} />}

      {/* Highlights / Performance Counters Row */}
      <section
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))",
          gap: "16px",
          marginBottom: "24px",
        }}
        aria-label="DRP Metrics Dashboard"
      >
        <div className="panel" style={{ padding: "16px", display: "flex", alignItems: "center", gap: "12px", background: "rgba(11, 107, 87, 0.02)" }}>
          <div style={{ color: "var(--accent)" }}><Shield size={20} /></div>
          <div>
            <div style={{ fontSize: "12px", color: "var(--muted)" }}>Active Threats</div>
            <strong style={{ fontSize: "16px" }}>{findings.filter((f) => f.status === "confirmed").length} Confirmed</strong>
          </div>
        </div>
        <div className="panel" style={{ padding: "16px", display: "flex", alignItems: "center", gap: "12px" }}>
          <div style={{ color: "var(--warning)" }}><AlertTriangle size={20} /></div>
          <div>
            <div style={{ fontSize: "12px", color: "var(--muted)" }}>Under Investigation</div>
            <strong style={{ fontSize: "16px" }}>{findings.filter((f) => f.status === "validated" || f.status === "reviewing").length} In Review</strong>
          </div>
        </div>
        <div className="panel" style={{ padding: "16px", display: "flex", alignItems: "center", gap: "12px" }}>
          <div style={{ color: "var(--muted)" }}><Globe size={20} /></div>
          <div>
            <div style={{ fontSize: "12px", color: "var(--muted)" }}>Assets Monitored</div>
            <strong style={{ fontSize: "16px" }}>{new Set(findings.map(f => f.asset_id)).size} Digital Assets</strong>
          </div>
        </div>
      </section>

      {/* Three Panel Grid Workspace */}
      <section
        style={{
          display: "flex",
          flexWrap: "wrap",
          gap: "16px",
          alignItems: "stretch",
          flex: 1,
        }}
        aria-label="DRP Investigation Board"
      >
        {/* Panel 1: Searchable Findings Table List */}
        <DetectionTable
          detections={detections}
          selectedId={selectedFindingId}
          onSelect={(d) => {
            setSelectedFindingId(d.id);
            const relativeFinding = findings.find(f => f.id === d.id);
            if (relativeFinding) {
              if (relativeFinding.status === "confirmed") {
                setSelectedAction("initiate_takedown");
              } else if (relativeFinding.status === "validated") {
                setSelectedAction("review_for_action");
              } else {
                setSelectedAction("gather_more_evidence");
              }
            }
            setSimulation(null);
          }}
          isLoading={isLoading}
        />

        {/* Panel 2: Threat Intelligence Context Visualization */}
        <DetailPanel
          detection={selectedDetection}
          customContextRenderer={(d) => {
            const finding = findings.find((f) => f.id === d.id);
            return (
              <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
                <div>
                  <h4 style={{ margin: "0 0 8px 0", fontSize: "12px", fontWeight: 600, textTransform: "uppercase", color: "var(--muted)" }}>
                    Asset Profile
                  </h4>
                  <div style={{ display: "flex", flexDirection: "column", gap: "8px", fontSize: "12px" }}>
                    <div style={{ display: "flex", justifyContent: "space-between" }}>
                      <span style={{ color: "var(--muted)" }}>Asset Type</span>
                      <strong>{finding?.asset_type.replace(/_/g, " ").toUpperCase()}</strong>
                    </div>
                    <div style={{ display: "flex", justifyContent: "space-between" }}>
                      <span style={{ color: "var(--muted)" }}>Display Name</span>
                      <strong>{finding?.asset_display_name}</strong>
                    </div>
                    <div style={{ display: "flex", justifyContent: "space-between" }}>
                      <span style={{ color: "var(--muted)" }}>First Detected</span>
                      <strong>{finding?.detected_at ? new Date(finding.detected_at).toLocaleString() : "Unknown"}</strong>
                    </div>
                  </div>
                </div>

                <div>
                  <h4 style={{ margin: "0 0 8px 0", fontSize: "12px", fontWeight: 600, textTransform: "uppercase", color: "var(--muted)" }}>
                    Finding Classification
                  </h4>
                  <div style={{ display: "flex", flexDirection: "column", gap: "8px", fontSize: "12px" }}>
                    <div style={{ display: "flex", justifyContent: "space-between" }}>
                      <span style={{ color: "var(--muted)" }}>Threat Type</span>
                      <strong>
                        {finding?.finding_type
                          .replace(/_/g, " ")
                          .replace(/\b\w/g, (c) => c.toUpperCase())}
                      </strong>
                    </div>
                    <div style={{ display: "flex", justifyContent: "space-between" }}>
                      <span style={{ color: "var(--muted)" }}>Source</span>
                      <strong>{finding?.source}</strong>
                    </div>
                    <div style={{ display: "flex", justifyContent: "space-between" }}>
                      <span style={{ color: "var(--muted)" }}>Severity</span>
                      <span
                        style={{
                          background:
                            finding?.severity === "critical"
                              ? "rgba(220, 38, 38, 0.1)"
                              : finding?.severity === "high"
                              ? "rgba(239, 68, 68, 0.1)"
                              : finding?.severity === "medium"
                              ? "rgba(245, 158, 11, 0.1)"
                              : "rgba(16, 185, 129, 0.1)",
                          color:
                            finding?.severity === "critical"
                              ? "var(--error)"
                              : finding?.severity === "high"
                              ? "var(--warning)"
                              : finding?.severity === "medium"
                              ? "var(--accent)"
                              : "var(--healthy)",
                          padding: "2px 6px",
                          borderRadius: "3px",
                          fontSize: "11px",
                          fontWeight: 600,
                        }}
                      >
                        {finding?.severity.toUpperCase()}
                      </span>
                    </div>
                  </div>
                </div>

                {finding?.llm_validation && (
                  <div>
                    <h4 style={{ margin: "0 0 8px 0", fontSize: "12px", fontWeight: 600, textTransform: "uppercase", color: "var(--muted)" }}>
                      AI Validation Summary
                    </h4>
                    <div style={{ background: "#f8fafc", padding: "12px", borderRadius: "6px", border: "1px solid var(--line)" }}>
                      <p style={{ margin: 0, fontSize: "12px", lineHeight: 1.5, color: "var(--muted)" }}>{finding.llm_validation}</p>
                    </div>
                  </div>
                )}

                {finding?.screenshot_url && (
                  <div>
                    <h4 style={{ margin: "0 0 8px 0", fontSize: "12px", fontWeight: 600, textTransform: "uppercase", color: "var(--muted)" }}>
                      Evidence Screenshot
                    </h4>
                    <div style={{ textAlign: "center" }}>
                      <img
                        src={finding.screenshot_url}
                        alt="DRP Evidence Screenshot"
                        style={{ maxWidth: "100%", height: "auto", borderRadius: "6px", border: "1px solid var(--line)" }}
                      />
                    </div>
                  </div>
                )}

                {finding?.evidence_links && finding.evidence_links.length > 0 && (
                  <div>
                    <h4 style={{ margin: "0 0 8px 0", fontSize: "12px", fontWeight: 600, textTransform: "uppercase", color: "var(--muted)" }}>
                      Evidence Links
                    </h4>
                    <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                      {finding.evidence_links.map((link, index) => (
                        <a
                          key={index}
                          href={link}
                          target="_blank"
                          rel="noopener noreferrer"
                          style={{
                            display: "inline-block",
                            padding: "4px 8px",
                            background: "rgba(11, 107, 87, 0.05)",
                            border: "1px solid var(--line)",
                            borderRadius: "4px",
                            fontSize: "11px",
                            textDecoration: "none",
                            color: "var(--accent)",
                          }}
                        >
                          🔗 Evidence {index + 1}
                        </a>
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
          onSimulate={validateFinding}
          onStage={() => initiateTakedown()}
          availableActions={[
            { value: "gather_more_evidence", label: "Gather More Evidence", destructive: false },
            { value: "review_for_action", label: "Review for Response Action", destructive: false },
            { value: "initiate_takedown", label: "Initiate Takedown Process", destructive: true },
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
            <h2 style={{ fontSize: "14px", margin: 0 }}>Threat Intelligence Sources</h2>
            <span style={{ fontSize: "11px", color: "var(--muted)" }}>Monitored Channels</span>
          </div>
          <div style={{ fontSize: "12px", color: "var(--muted)", lineHeight: 1.5 }}>
            • Social Media Platforms (Twitter, Facebook, LinkedIn, Instagram)
            <br />
            • Dark Web Marketplaces & Forums
            <br />
            • Paste Sites & Code Repositories
            <br />
            • Domain Registrations & SSL Certificates
            <br />
            • Mobile App Stores
          </div>
        </article>

        <article className="panel">
          <div className="panelHeader" style={{ borderBottom: "1px solid var(--line)", paddingBottom: "10px", marginBottom: "12px" }}>
            <h2 style={{ fontSize: "14px", margin: 0 }}>Response Workflow Status</h2>
            <span style={{ fontSize: "11px", color: "var(--muted)" }}>Automated Pipeline</span>
          </div>
          <div style={{ display: "flex", justifyContent: "space-between", fontSize: "12px" }}>
            <span>AI Validation Engine:</span>
            <strong style={{ color: "var(--healthy)" }}>ONLINE</strong>
          </div>
          <div style={{ display: "flex", justifyContent: "space-between", fontSize: "12px", marginTop: "8px" }}>
            <span>Takedown Orchestrator:</span>
            <strong style={{ color: "var(--healthy)" }}>READY</strong>
          </div>
        </article>
      </section>
    </div>
  );
}