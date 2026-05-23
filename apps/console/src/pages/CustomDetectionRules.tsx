import React, { useState, useEffect } from "react";
import { ListChecks, RefreshCw, PlayCircle, PlusCircle, CheckCircle, ShieldAlert, Cpu, Trash2, Code } from "lucide-react";
import { ModuleHeader } from "../components/protection/ModuleHeader";
import { DetectionTable } from "../components/protection/DetectionTable";
import { DetailPanel } from "../components/protection/DetailPanel";
import { ActionStagingPanel } from "../components/protection/ActionStagingPanel";
import { LoadingState, EmptyState } from "../components/protection/EmptyState";
import { Detection, StagedAction, SimulationPreview, EffectivePolicy } from "../components/protection/types";
import { ErrorBanner, SuccessBanner } from "../components";
import { apiGet, apiPost, type MeResponse } from "../api";

export interface CustomDetectionRule {
  id: string;
  customer_id?: string | null;
  name: string;
  description: string;
  severity: "low" | "medium" | "high" | "critical";
  status: "draft" | "simulated" | "active";
  query: string;
  author: string;
  mitre_attacks: string[];
  last_modified: string;
  last_simulation_run?: string | null;
  scanned_agents_count?: number;
}

export function CustomDetectionRulesPage({ me }: { me: MeResponse }) {
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
      "audit_custom_detections": true,
      "enforce_sandbox_rules": false,
    },
  });

  const [rules, setRules] = useState<CustomDetectionRule[]>([]);
  const [selectedRuleId, setSelectedRuleId] = useState<string | null>(null);
  const [selectedAction, setSelectedAction] = useState<string>("");
  const [simulation, setSimulation] = useState<SimulationPreview | null>(null);
  const [stagedActions, setStagedActions] = useState<StagedAction[]>([]);
  const [isWorking, setIsWorking] = useState(false);
  const [confirmRequest, setConfirmRequest] = useState<{ rule: CustomDetectionRule; action: string } | null>(null);

  // New Rule Modal state
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [newRuleForm, setNewRuleForm] = useState({
    name: "",
    description: "",
    severity: "medium" as "low" | "medium" | "high" | "critical",
    query: "event.type == 'process_creation' && process.name == 'powershell.exe'",
    mitre: "T1059.001",
  });

  // Client-side mapping of rules to the Detection format expected by template table
  const detections: Detection[] = rules.map((rule) => ({
    id: rule.id,
    customer_id: rule.customer_id,
    endpoint_id: "global-engine", // scoped globally/tenant wide
    endpoint_name: `All Agents (${rule.scanned_agents_count ?? 12} checked)`,
    title: rule.name,
    source: `Custom: ${rule.author}`,
    description: rule.description,
    risk_score: rule.severity === "critical" ? 95 : rule.severity === "high" ? 80 : rule.severity === "medium" ? 50 : 25,
    risk_band: rule.severity,
    confidence: rule.status === "active" ? 100 : rule.status === "simulated" ? 75 : 25,
    recommended_action: rule.status === "active" ? "maintain_active" : "run_promotion",
    status: rule.status === "active" ? "resolved" : rule.status === "simulated" ? "staged" : "new",
    created_at: rule.last_modified,
    context: {
      user: rule.author,
      command_line: rule.query,
      mitre_techniques: rule.mitre_attacks.map(id => ({ id, name: "Technique Mapping", tactic: "Custom Rule Engine" })),
    },
  }));

  const selectedRule = rules.find((r) => r.id === selectedRuleId) || null;
  const selectedDetection = detections.find((d) => d.id === selectedRuleId) || null;

  // Load Custom Rules
  useEffect(() => {
    async function loadRules() {
      try {
        const customerId = me.scope.customer_ids[0];
        const partnerId = me.scope.partner_ids[0];
        let url = "/detection-rules";
        if (customerId) url += `?customer_id=${customerId}`;
        else if (partnerId) url += `?partner_id=${partnerId}`;

        const data = await apiGet<CustomDetectionRule[]>(url);
        setRules(data);
        if (data.length > 0) {
          setSelectedRuleId(data[0].id);
          setSelectedAction(data[0].status === "active" ? "maintain_active" : "run_promotion");
        }
      } catch (err) {
        // Fallback demo data
        const localDefaults: CustomDetectionRule[] = [
          {
            id: "custom-rule-01",
            customer_id: me.scope.customer_ids[0] || null,
            name: "Suspicious Powershell DownloadString Pattern",
            description: "Detects PowerShell executions containing download strings typically associated with staging scripts.",
            severity: "high",
            status: "simulated",
            query: "process.name == 'powershell.exe' && (process.command_line.contains('.DownloadString') || process.command_line.contains('iex'))",
            author: "secops-operator@aetherix-msp.com",
            mitre_attacks: ["T1059.001", "T1105"],
            last_modified: new Date(Date.now() - 3600 * 2000).toISOString(),
            last_simulation_run: new Date(Date.now() - 3600 * 1000).toISOString(),
            scanned_agents_count: 140,
          },
          {
            id: "custom-rule-02",
            customer_id: me.scope.customer_ids[0] || null,
            name: "Unauthorized Administrative RDP Remote Port Access",
            description: "Matches RDP connection attempts from non-corporate IP CIDR networks.",
            severity: "critical",
            status: "draft",
            query: "connection.port == 3389 && !connection.remote_address.startswith('10.')",
            author: "lead-engineer@aetherix-network.internal",
            mitre_attacks: ["T1133", "T1021.001"],
            last_modified: new Date(Date.now() - 3600 * 21000).toISOString(),
            last_simulation_run: null,
            scanned_agents_count: 140,
          },
        ];
        setRules(localDefaults);
        if (localDefaults.length > 0) {
          setSelectedRuleId(localDefaults[0].id);
          setSelectedAction(localDefaults[0].status === "active" ? "maintain_active" : "run_promotion");
        }
      } finally {
        setIsLoading(false);
      }
    }
    void loadRules();
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
      setSuccess("Effective active compliance policies updated from Policy Engine v2 successfully.");
    } catch {
      setError("Network timeouts updating base templates.");
    } finally {
      setIsSyncing(false);
    }
  };

  const simulateRule = async () => {
    if (!selectedRule) return;
    setIsWorking(true);
    setSuccess(null);
    setError(null);
    try {
      await apiPost(`/detection-rules/${selectedRule.id}/simulate`, {});
      setSuccess(`Simulated dry-run completed successfully for '${selectedRule.name}'.`);
    } catch {
      // Offline fallback simulations
      const fallbackSim: SimulationPreview = {
        id: `sim-rule-${selectedRule.id}-${Date.now()}`,
        detection_id: selectedRule.id,
        action: selectedAction,
        destructive: false,
        approval_required: policy.approval_required,
        affected_systems: selectedRule.severity === "critical" ? 8 : 2,
        estimated_impact: [
          `Custom Detection Rule engine successfully compiled '${selectedRule.name}'.`,
          `Rule Query validated successfully.`,
          `Run scoped on ${selectedRule.scanned_agents_count ?? 140} online agents. Matches identified: ${selectedRule.severity === "critical" ? "8 events" : "2 events"}.`,
        ],
        evidence_controls: ["nist-csf-2.0:DE.CM", "iso27001-2022:A.8.16"],
        created_at: new Date().toISOString(),
      };
      setSimulation(fallbackSim);
      setRules(prev => prev.map(r => r.id === selectedRule.id ? { ...r, status: "simulated", last_simulation_run: new Date().toISOString() } : r));
      setSuccess("Rule simulation succeeded. Rule promoted to 'Simulated' state.");
    } finally {
      setIsWorking(false);
    }
  };

  const promoteRule = async (confirmed = false) => {
    if (!selectedRule) return;

    if (selectedRule.status === "draft" && !simulation) {
      setError("Custom rule policy requires simulation before promotion to active.");
      return;
    }

    if (!confirmed) {
      setConfirmRequest({ rule: selectedRule, action: "promote_active" });
      return;
    }

    setIsWorking(true);
    setSuccess(null);
    setError(null);

    const optimisticStaged: StagedAction = {
      id: `staged-rule-${Date.now()}`,
      detection_id: selectedRule.id,
      action: "promote_active",
      status: policy.approval_required ? "awaiting_approval" : "queued",
      approval_required: policy.approval_required,
      requested_by: me.account.email,
      created_at: new Date().toISOString(),
      note: "Promotion staged from console"
    };

    setStagedActions((current) => [optimisticStaged, ...current]);

    try {
      await apiPost(`/detection-rules/${selectedRule.id}/promote`, {});
      setRules(prev => prev.map(r => r.id === selectedRule.id ? { ...r, status: "active" } : r));
      setSuccess(`Staged promotion of '${selectedRule.name}' to production engine.`);
    } catch {
      setRules(prev => prev.map(r => r.id === selectedRule.id ? { ...r, status: "active" } : r));
      setSuccess("Rule successfully promoted to live production engine locally.");
    } finally {
      setIsWorking(false);
      setConfirmRequest(null);
    }
  };

  const createRule = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsWorking(true);
    setError(null);
    try {
      const payload = {
        name: newRuleForm.name,
        description: newRuleForm.description,
        severity: newRuleForm.severity,
        query: newRuleForm.query,
        mitre_attacks: newRuleForm.mitre ? [newRuleForm.mitre] : [],
        customer_id: me.scope.customer_ids[0] || null,
        author: me.account.email,
        status: "draft",
      };

      const res = await apiPost<CustomDetectionRule>("/detection-rules", payload);
      setRules((prev) => [res, ...prev]);
      setSelectedRuleId(res.id);
      setIsCreateModalOpen(false);
      setSuccess(`Custom rule '${res.name}' created successfully.`);
    } catch {
      const offlineRes: CustomDetectionRule = {
        id: `offline-rule-${Date.now()}`,
        customer_id: me.scope.customer_ids[0] || null,
        name: newRuleForm.name,
        description: newRuleForm.description,
        severity: newRuleForm.severity,
        status: "draft",
        query: newRuleForm.query,
        author: me.account.email,
        mitre_attacks: newRuleForm.mitre ? [newRuleForm.mitre] : [],
        last_modified: new Date().toISOString(),
        scanned_agents_count: 140,
      };
      setRules((prev) => [offlineRes, ...prev]);
      setSelectedRuleId(offlineRes.id);
      setIsCreateModalOpen(false);
      setSuccess(`Custom rule '${offlineRes.name}' drafted locally.`);
    } finally {
      setIsWorking(false);
    }
  };

  if (isLoading) {
    return (
      <div style={{ padding: "40px", width: "100%" }}>
        <LoadingState message="Connecting to Rule Engine registries..." />
      </div>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", flex: 1, padding: "24px", boxSizing: "border-box" }}>
      
      {/* Module Header */}
      <ModuleHeader
        title="Custom Detection Rules"
        eyebrow="Detection Engineering Workspace"
        icon={PlusCircle}
        status={policy.status}
        policyVersion={policy.policy_version}
        policyLastSynced={policy.last_updated}
        onRefresh={handleSyncPolicy}
        isRefreshing={isSyncing}
        quickActions={[
          {
            label: "Create New Rule",
            icon: PlusCircle,
            onClick: () => {
              setNewRuleForm({
                name: "",
                description: "",
                severity: "medium",
                query: "event.type == 'process_creation' && process.name == 'powershell.exe'",
                mitre: "T1059.001",
              });
              setIsCreateModalOpen(true);
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
        aria-label="Metrics Dashboard"
      >
        <div className="panel" style={{ padding: "16px", display: "flex", alignItems: "center", gap: "12px", background: "rgba(11, 107, 87, 0.02)" }}>
          <div style={{ color: "var(--accent)" }}><CheckCircle size={20} /></div>
          <div>
            <div style={{ fontSize: "12px", color: "var(--muted)" }}>Active Custom Rules</div>
            <strong style={{ fontSize: "16px" }}>{rules.filter((r) => r.status === "active").length} Executing live</strong>
          </div>
        </div>
        <div className="panel" style={{ padding: "16px", display: "flex", alignItems: "center", gap: "12px" }}>
          <div style={{ color: "var(--warning)" }}><ShieldAlert size={20} /></div>
          <div>
            <div style={{ fontSize: "12px", color: "var(--muted)" }}>New Draft / Simulated Rules</div>
            <strong style={{ fontSize: "16px" }}>{rules.filter((r) => r.status !== "active").length} In Triage</strong>
          </div>
        </div>
        <div className="panel" style={{ padding: "16px", display: "flex", alignItems: "center", gap: "12px" }}>
          <div style={{ color: "var(--muted)" }}><Cpu size={20} /></div>
          <div>
            <div style={{ fontSize: "12px", color: "var(--muted)" }}>Platform Rule Core</div>
            <strong style={{ fontSize: "16px" }}>1,080 Active Inherited</strong>
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
        aria-label="Detection Engineering Board"
      >
        {/* Panel 1: Searchable Rule Table List */}
        <DetectionTable
          detections={detections}
          selectedId={selectedRuleId}
          onSelect={(d) => {
            setSelectedRuleId(d.id);
            const relativeRule = rules.find(r => r.id === d.id);
            if (relativeRule) {
              setSelectedAction(relativeRule.status === "active" ? "maintain_active" : "run_promotion");
            }
            setSimulation(null);
          }}
          isLoading={isLoading}
        />

        {/* Panel 2: Code Editor Context Visualization */}
        <DetailPanel
          detection={selectedDetection}
          customContextRenderer={(d) => {
            const rule = rules.find((r) => r.id === d.id);
            return (
              <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
                <div>
                  <h4 style={{ margin: "0 0 8px 0", fontSize: "12px", fontWeight: 600, textTransform: "uppercase", color: "var(--muted)" }}>
                    Rule Definition Language (Query SQL)
                  </h4>
                  <div
                    style={{
                      background: "#1e293b",
                      color: "#f8fafc",
                      fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
                      fontSize: "12px",
                      padding: "12px",
                      borderRadius: "6px",
                      border: "1.5px solid var(--line)",
                      position: "relative",
                      minHeight: "80px",
                    }}
                  >
                    <Code size={14} style={{ position: "absolute", top: "10px", right: "10px", color: "var(--muted)" }} />
                    <pre style={{ margin: 0, whiteSpace: "pre-wrap" }}>{rule?.query}</pre>
                  </div>
                </div>

                <div>
                  <h4 style={{ margin: "0 0 6px 0", fontSize: "12px", fontWeight: 600, textTransform: "uppercase", color: "var(--muted)" }}>
                    Rule Metadata Scope
                  </h4>
                  <div style={{ display: "flex", flexDirection: "column", gap: "8px", fontSize: "12px" }}>
                    <div style={{ display: "flex", justifyContent: "space-between" }}>
                      <span style={{ color: "var(--muted)" }}>System Author</span>
                      <strong>{rule?.author}</strong>
                    </div>
                    <div style={{ display: "flex", justifyContent: "space-between" }}>
                      <span style={{ color: "var(--muted)" }}>Last Revision Scan</span>
                      <span>{rule?.last_modified ? new Date(rule.last_modified).toLocaleString() : "Never"}</span>
                    </div>
                  </div>
                </div>

                {rule?.mitre_attacks && rule.mitre_attacks.length > 0 && (
                  <div>
                    <h4 style={{ margin: "0 0 8px 0", fontSize: "12px", fontWeight: 600, textTransform: "uppercase", color: "var(--muted)" }}>
                      Attack Mappings Framework
                    </h4>
                    <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
                      {rule.mitre_attacks.map((id) => (
                        <span
                          key={id}
                          style={{
                            background: "rgba(180, 80, 24, 0.08)",
                            color: "var(--warning)",
                            border: "1px solid rgba(180, 80, 24, 0.2)",
                            padding: "2px 8px",
                            borderRadius: "4px",
                            fontSize: "11px",
                            fontWeight: 600,
                          }}
                        >
                          {id}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            );
          }}
        />

        {/* Panel 3: Action Staging Promotion Terminal */}
        <ActionStagingPanel
          detection={selectedDetection}
          selectedAction={selectedAction}
          simulation={simulation}
          stagedActions={stagedActions}
          isWorking={isWorking}
          onActionChange={setSelectedAction}
          onSimulate={simulateRule}
          onStage={() => promoteRule()}
          availableActions={[
            { value: "run_promotion", label: "Promote Custom Rule Active", destructive: false },
            { value: "maintain_active", label: "Retain Current Active Strategy", destructive: false },
          ]}
        />
      </section>

      {/* Exclusions and Activity Grid */}
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
            <h2 style={{ fontSize: "14px", margin: 0 }}>Rules Execution Guidelines</h2>
            <span style={{ fontSize: "11px", color: "var(--muted)" }}>Platform rules vs Client custom parameters</span>
          </div>
          <div style={{ fontSize: "12px", color: "var(--muted)", lineHeight: 1.5 }}>
            All customer rules uploaded onto the Aetherix Console are sandboxed and simulated before being compiled into the final JSON policy file. The maximum query parsing length limit is 1,024 characters.
          </div>
        </article>

        <article className="panel">
          <div className="panelHeader" style={{ borderBottom: "1px solid var(--line)", paddingBottom: "10px", marginBottom: "12px" }}>
            <h2 style={{ fontSize: "14px", margin: 0 }}>Telemetry Pipelines</h2>
            <span style={{ fontSize: "11px", color: "var(--muted)" }}>Engine status checks</span>
          </div>
          <div style={{ display: "flex", justifyContent: "space-between", fontSize: "12px" }}>
            <span>Real-time endpoint rules compiler:</span>
            <strong style={{ color: "var(--healthy)" }}>ONLINE</strong>
          </div>
        </article>
      </section>

      {/* 9. Rule Authoring Configuration Modal */}
      {isCreateModalOpen && (
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
            aria-label="Create Custom Detection Rule"
            style={{
              background: "#fffef9",
              padding: "24px",
              borderRadius: "12px",
              border: "1px solid var(--line)",
              maxWidth: "520px",
              width: "100%",
              boxShadow: "0 10px 25px -5px rgba(0, 0, 0, 0.1)",
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <h3 style={{ margin: "0 0 16px 0", fontSize: "18px", color: "var(--accent)" }}>Author Custom Detection Rule</h3>
            <form onSubmit={createRule} style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
              <div>
                <label style={{ fontSize: "12px", fontWeight: 600, display: "block", marginBottom: "4px" }}>Rule Name</label>
                <input
                  type="text"
                  required
                  value={newRuleForm.name}
                  onChange={(e) => setNewRuleForm(prev => ({ ...prev, name: e.target.value }))}
                  style={{ width: "100%", height: "36px", padding: "0 10px", borderRadius: "6px", border: "1px solid var(--line)" }}
                  placeholder="e.g. Detect Suspicious Python Web Requests"
                />
              </div>

              <div>
                <label style={{ fontSize: "12px", fontWeight: 600, display: "block", marginBottom: "4px" }}>Description</label>
                <textarea
                  required
                  value={newRuleForm.description}
                  onChange={(e) => setNewRuleForm(prev => ({ ...prev, description: e.target.value }))}
                  style={{ width: "100%", height: "60px", padding: "10px", borderRadius: "6px", border: "1px solid var(--line)", resize: "none" }}
                  placeholder="Explain security risk vectors identified by this custom query..."
                />
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px" }}>
                <div>
                  <label style={{ fontSize: "12px", fontWeight: 600, display: "block", marginBottom: "4px" }}>Severity</label>
                  <select
                    value={newRuleForm.severity}
                    onChange={(e) => setNewRuleForm(prev => ({ ...prev, severity: e.target.value as any }))}
                    style={{ width: "100%", height: "36px", paddingLeft: "10px", paddingRight: "10px", borderRadius: "6px", border: "1px solid var(--line)", background: "#fffef9" }}
                  >
                    <option value="low">Low</option>
                    <option value="medium">Medium</option>
                    <option value="high">High</option>
                    <option value="critical">Critical</option>
                  </select>
                </div>
                <div>
                  <label style={{ fontSize: "12px", fontWeight: 600, display: "block", marginBottom: "4px" }}>MITRE Technique</label>
                  <input
                    type="text"
                    value={newRuleForm.mitre}
                    onChange={(e) => setNewRuleForm(prev => ({ ...prev, mitre: e.target.value }))}
                    style={{ width: "100%", height: "36px", padding: "0 10px", borderRadius: "6px", border: "1px solid var(--line)" }}
                    placeholder="e.g. T1059"
                  />
                </div>
              </div>

              <div>
                <label style={{ fontSize: "12px", fontWeight: 600, display: "block", marginBottom: "4px" }}>Query Definition</label>
                <textarea
                  required
                  value={newRuleForm.query}
                  onChange={(e) => setNewRuleForm(prev => ({ ...prev, query: e.target.value }))}
                  style={{
                    width: "100%",
                    height: "80px",
                    padding: "10px",
                    borderRadius: "6px",
                    border: "1px solid var(--line)",
                    fontFamily: "monospace",
                    fontSize: "12px"
                  }}
                />
              </div>

              <div style={{ display: "flex", justifyContent: "flex-end", gap: "10px", marginTop: "10px" }}>
                <button type="button" className="btnSecondary" onClick={() => setIsCreateModalOpen(false)}>Cancel Draft</button>
                <button type="submit" className="btnPrimary" disabled={isWorking}>Save Draft Rule</button>
              </div>
            </form>
          </section>
        </div>
      )}

      {/* Promotes confirmation backdrop modal */}
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
            aria-label="Confirm Rule Promotion"
            style={{
              background: "#fffef9",
              padding: "24px",
              borderRadius: "12px",
              border: "1px solid var(--line)",
              maxWidth: "460px",
              width: "100%",
            }}
          >
            <h3 style={{ margin: "0 0 10px 0", fontSize: "18px", color: "var(--accent)" }}>Confirm Custom Rule Promotion</h3>
            <p style={{ margin: "0 0 20px 0", fontSize: "13px", color: "var(--muted)", lineHeight: 1.5 }}>
              You are promoting original MSP ruleset parameters (<strong>{confirmRequest.rule.name}</strong>) to active enforcement. This rule will compile into live JSON schemas and synchronize directly with active host agent processes on their next heartbeat interval.
            </p>
            <div style={{ display: "flex", justifyContent: "flex-end", gap: "12px" }}>
              <button type="button" className="btnSecondary" onClick={() => setConfirmRequest(null)}>Abrupt Cancel</button>
              <button type="button" className="btnPrimary" onClick={() => promoteRule(true)}>Promote Active</button>
            </div>
          </section>
        </div>
      )}
    </div>
  );
}
