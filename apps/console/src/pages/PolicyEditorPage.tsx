import React, { useEffect, useState } from "react";
import { ArrowLeft, ChevronDown, ChevronRight, Save, ShieldAlert, FlaskConical } from "lucide-react";
import {
  apiGet,
  apiPost,
  apiPut,
  type CompanySummaryPage,
  type EffectivePolicyResponse,
  type PolicyDocumentV2Input,
  type PolicyGetResponse,
  type PolicySimulationRecord,
} from "../api";
import { ErrorBanner, SuccessBanner } from "../components";

// Types (extracted/adapted from the old monolithic editor)
type FieldType = "boolean" | "select" | "text";

interface ModuleField {
  key: string;
  label: string;
  type: FieldType;
  options?: string[];
}

interface ModuleConfig {
  key: string;
  title: string;
  addon?: string;
  fields: ModuleField[];
}

const CORE_MODULES = new Set(["general", "tenant_scope", "entitlements", "compliance_evidence"]);

const MODULES: ModuleConfig[] = [
  { key: "general", title: "General", fields: [{ key: "enabled", label: "Enabled", type: "boolean" }, { key: "agent_update_channel", label: "Update channel", type: "select", options: ["stable", "slow", "fast"] }] },
  { key: "tenant_scope", title: "Tenant Scope", fields: [{ key: "enabled", label: "Enabled", type: "boolean" }] },
  { key: "entitlements", title: "Entitlements", fields: [{ key: "enabled", label: "Enabled", type: "boolean" }] },
  {
    key: "deployment_profile",
    title: "Deployment Profile",
    fields: [
      { key: "enabled", label: "Enabled", type: "boolean" },
      { key: "update_channel", label: "Update channel", type: "select", options: ["stable", "slow", "fast"] },
      { key: "update_interval_hours", label: "Update interval (hours)", type: "text" },
      { key: "deployment_ring", label: "Deployment ring", type: "select", options: ["stable", "slow", "fast"] },
      { key: "rollout_percentage", label: "Rollout percentage", type: "text" },
      { key: "proxy_enabled", label: "Proxy enabled", type: "boolean" },
      { key: "proxy_server", label: "Proxy server", type: "text" },
      { key: "proxy_port", label: "Proxy port", type: "text" },
      { key: "silent_mode", label: "Silent mode", type: "boolean" },
      { key: "show_alerts", label: "Show alert pop-ups", type: "boolean" },
      { key: "telemetry_enabled", label: "Security Telemetry", type: "boolean" },
      { key: "relay_auto_discovery", label: "Relay auto-discovery", type: "boolean" },
      { key: "use_proxy_for_relay", label: "Use proxy for relay", type: "boolean" },
      { key: "use_proxy_for_cloud", label: "Use proxy for cloud", type: "boolean" },
      { key: "reboot_postpone", label: "Postpone reboot", type: "boolean" },
      { key: "managed_update_fallback", label: "Managed update fallback", type: "boolean" },
    ],
  },
  { key: "antimalware", title: "Antimalware", fields: [{ key: "enabled", label: "Enabled", type: "boolean" }, { key: "response_action", label: "Response action", type: "select", options: ["allow", "review", "block"] }] },
  { key: "behavior_monitoring", title: "Behavior Monitoring", fields: [{ key: "enabled", label: "Enabled", type: "boolean" }, { key: "high_confidence_action", label: "High-confidence action", type: "select", options: ["review", "isolate"] }] },
  { key: "anti_exploit", title: "Anti Exploit", fields: [{ key: "enabled", label: "Enabled", type: "boolean" }, { key: "high_confidence_action", label: "High-confidence action", type: "select", options: ["review", "block"] }] },
  { key: "ransomware_mitigation", title: "Ransomware Mitigation", fields: [{ key: "enabled", label: "Enabled", type: "boolean" }, { key: "rollback_approval", label: "Rollback approval", type: "select", options: ["operator_required", "automatic"] }] },
  { key: "firewall", title: "Firewall", fields: [{ key: "enabled", label: "Enabled", type: "boolean" }, { key: "profile", label: "Protection profile", type: "select", options: ["ruleset_allow", "ruleset_ask", "ruleset_deny", "known_allow", "known_ask", "known_deny"] }, { key: "log_level", label: "Log verbosity", type: "select", options: ["low", "normal", "high"] }] },
  { key: "network_protection", title: "Network Protection", fields: [{ key: "enabled", label: "Enabled", type: "boolean" }, { key: "encrypted_traffic_interception", label: "Encrypted traffic interception", type: "boolean" }, { key: "tls_handshake_interception", label: "TLS handshake interception", type: "boolean" }, { key: "network_attack_signature_action", label: "Network attack action", type: "select", options: ["allow", "review", "block"] }] },
  { key: "web_protection", title: "Web Protection", fields: [{ key: "enabled", label: "Enabled", type: "boolean" }, { key: "content_control_enabled", label: "Content control", type: "boolean" }, { key: "antiphishing_action", label: "Antiphishing action", type: "select", options: ["allow", "review", "block"] }, { key: "infected_website_action", label: "Infected website action", type: "select", options: ["allow", "review", "block"] }, { key: "email_scan_enabled", label: "Email traffic scanning", type: "boolean" }, { key: "custom_pages_enabled", label: "Custom pages", type: "boolean" }, { key: "sensitive_upload_action", label: "Sensitive upload action", type: "select", options: ["allow", "review", "block"] }] },
  { key: "classification_labeling", title: "Classification & Labeling", addon: "semantic_dlp", fields: [{ key: "enabled", label: "Enabled", type: "boolean" }] },
  {
    key: "semantic_dlp",
    title: "Semantic DLP",
    addon: "semantic_dlp",
    fields: [
      { key: "enabled", label: "Enabled", type: "boolean" },
      { key: "sensitivity_labels_csv", label: "Sensitivity labels (comma-separated)", type: "text" },
      { key: "genai_destinations_csv", label: "GenAI destinations (comma-separated)", type: "text" },
      { key: "paste_sensitive_action", label: "Paste sensitive action", type: "select", options: ["allow", "review", "block"] },
      { key: "upload_restricted_action", label: "Upload restricted action", type: "select", options: ["allow", "review", "block"] },
      { key: "copy_to_genai_action", label: "Copy to GenAI action", type: "select", options: ["allow", "review", "block"] },
      { key: "presidio_detector", label: "Use Presidio detector", type: "boolean" },
      { key: "llm_semantic_detector", label: "Use LLM semantic detector", type: "boolean" },
      { key: "custom_classifiers_csv", label: "Custom classifiers (comma-separated)", type: "text" },
    ],
  },
  {
    key: "genai_guardrails",
    title: "GenAI Guardrails",
    addon: "semantic_dlp",
    fields: [
      { key: "enabled", label: "Enabled", type: "boolean" },
      { key: "destinations_csv", label: "Guarded destinations (comma-separated)", type: "text" },
      { key: "browser_enforcement", label: "Browser enforcement", type: "boolean" },
      { key: "endpoint_enforcement", label: "Endpoint enforcement", type: "boolean" },
      { key: "paste_sensitive_action", label: "Paste sensitive action", type: "select", options: ["allow", "review", "block"] },
      { key: "upload_restricted_action", label: "Upload restricted action", type: "select", options: ["allow", "review", "block"] },
      { key: "copy_to_genai_action", label: "Copy to GenAI action", type: "select", options: ["allow", "review", "block"] },
    ],
  },
  { key: "device_control", title: "Device Control", fields: [{ key: "enabled", label: "Enabled", type: "boolean" }] },
  { key: "sandbox_analyzer", title: "Sandbox Analyzer", addon: "sandbox", fields: [{ key: "enabled", label: "Enabled", type: "boolean" }, { key: "analysis_mode", label: "Analysis mode", type: "select", options: ["monitoring", "blocking"] }, { key: "default_action", label: "Default action", type: "select", options: ["report", "isolate", "block"] }] },
  { key: "patch_management", title: "Patch Management", addon: "patch_management", fields: [{ key: "enabled", label: "Enabled", type: "boolean" }, { key: "maintenance_window", label: "Maintenance window", type: "select", options: ["none", "business_hours", "after_hours", "weekend"] }] },
  { key: "siem_hids", title: "SIEM / HIDS", addon: "xdr", fields: [{ key: "enabled", label: "Enabled", type: "boolean" }] },
  { key: "integrity_monitoring", title: "Integrity Monitoring", addon: "xdr", fields: [{ key: "enabled", label: "Enabled", type: "boolean" }] },
  { key: "vulnerability_inventory", title: "Vulnerability Inventory", addon: "xdr", fields: [{ key: "enabled", label: "Enabled", type: "boolean" }] },
  { key: "digital_risk_protection", title: "Digital Risk Protection", addon: "digital_risk_protection", fields: [{ key: "enabled", label: "Enabled", type: "boolean" }] },
  { key: "external_attack_surface_management", title: "External Attack Surface Management", addon: "external_attack_surface_management", fields: [{ key: "enabled", label: "Enabled", type: "boolean" }] },
  { key: "threat_intelligence", title: "Threat Intelligence", addon: "threat_intelligence", fields: [{ key: "enabled", label: "Enabled", type: "boolean" }] },
  { key: "takedown_workflows", title: "Takedown Workflows", addon: "threat_intelligence", fields: [{ key: "enabled", label: "Enabled", type: "boolean" }] },
  { key: "incident_correlation", title: "Incident Correlation", addon: "xdr", fields: [{ key: "enabled", label: "Enabled", type: "boolean" }] },
  { key: "agentic_response", title: "Agentic Response", addon: "agentic_ir", fields: [{ key: "enabled", label: "Enabled", type: "boolean" }, { key: "default_response", label: "Default response", type: "select", options: ["review", "isolate"] }] },
  { key: "ai_settings", title: "AI Settings", addon: "agentic_ir", fields: [{ key: "enabled", label: "Enabled", type: "boolean" }] },
  { key: "ai_reports", title: "AI Reports", addon: "agentic_ir", fields: [{ key: "enabled", label: "Enabled", type: "boolean" }] },
  { key: "compliance_evidence", title: "Compliance Evidence", fields: [{ key: "enabled", label: "Enabled", type: "boolean" }] },
  { key: "integrations", title: "Integrations", fields: [{ key: "enabled", label: "Enabled", type: "boolean" }] },
  { key: "platform_observability", title: "Platform Observability", fields: [{ key: "enabled", label: "Enabled", type: "boolean" }] },
  { key: "white_label", title: "White Label", fields: [{ key: "enabled", label: "Enabled", type: "boolean" }, { key: "display_name", label: "Display name", type: "text" }] },
];

const ALL_MODULE_KEYS = MODULES.map((m) => m.key);

interface PolicyEditorPageProps {
  me?: any;
  mode?: "new" | "edit";
  policyId?: string | null;
  onBack?: () => void;
}

export function PolicyEditorPage({ me, mode = "new", policyId, onBack }: PolicyEditorPageProps) {
  const [draft, setDraft] = useState<PolicyDocumentV2Input>(() => {
    const base: Record<string, Record<string, unknown>> = {};
    for (const module of MODULES) {
      base[module.key] = { enabled: CORE_MODULES.has(module.key) };
    }
    return {
      schema_version: "2.0",
      name: mode === "new" ? "New Policy" : "",
      scope: { partner_id: null, customer_id: null, group_id: null, endpoint_id: null },
      lineage: { parent_policy_id: null, inheritance_mode: "inherit_with_overrides" },
      modules: base,
      white_label_names: {},
    };
  });

  const [companyRows, setCompanyRows] = useState<CompanySummaryPage["items"]>([]);
  const [simulation, setSimulation] = useState<PolicySimulationRecord | null>(null);
  const [isLoadingCompanies, setIsLoadingCompanies] = useState(false);

  // Load companies for scope selection
  useEffect(() => {
    const loadCompanies = async () => {
      setIsLoadingCompanies(true);
      try {
        const res = await apiGet<CompanySummaryPage>("/companies/summary?limit=100");
        setCompanyRows(res.items || []);
      } catch (e) {
        console.error("Failed to load companies for policy scope", e);
      } finally {
        setIsLoadingCompanies(false);
      }
    };
    loadCompanies();
  }, []);

  // Load existing policy when editing
  const [isLoadingPolicy, setIsLoadingPolicy] = useState(false);
  useEffect(() => {
    if (mode !== "edit" || !policyId) return;

    const loadExisting = async () => {
      setIsLoadingPolicy(true);
      setError(null);
      try {
        const res = await apiGet<PolicyGetResponse>(`/policies/${policyId}`);
        const payload = res.latest_version?.payload;
        if (payload) {
          setDraft(payload as PolicyDocumentV2Input);
        }
      } catch (e: any) {
        setError(e?.message || "Failed to load policy for editing");
      } finally {
        setIsLoadingPolicy(false);
      }
    };
    void loadExisting();
  }, [mode, policyId]);

  const [openModules, setOpenModules] = useState<Set<string>>(new Set(["general", "antimalware", "semantic_dlp"]));
  const [isSaving, setIsSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const toggleModuleOpen = (key: string) => {
    setOpenModules((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  const setModuleField = (moduleKey: string, fieldKey: string, value: any) => {
    setDraft((current) => ({
      ...current,
      modules: {
        ...current.modules,
        [moduleKey]: {
          ...current.modules[moduleKey],
          [fieldKey]: value,
        },
      },
    }));
  };

  const isLocked = (moduleKey: string) => {
    // Placeholder - in real implementation this would check entitlements
    return false;
  };

  const lockedReason = (module: ModuleConfig) => {
    return module.addon ? `Requires ${module.addon} add-on` : "Not available in current plan";
  };

  // Scope / lineage helpers (used by the scope + inheritance selects)
  const setScopeField = <K extends keyof PolicyDocumentV2Input["scope"]>(
    key: K,
    value: PolicyDocumentV2Input["scope"][K]
  ) => {
    setDraft((current) => ({
      ...current,
      scope: { ...current.scope, [key]: value },
    }));
  };

  const setLineageField = <K extends keyof PolicyDocumentV2Input["lineage"]>(
    key: K,
    value: PolicyDocumentV2Input["lineage"][K]
  ) => {
    setDraft((current) => ({
      ...current,
      lineage: { ...current.lineage, [key]: value },
    }));
  };

  // Run simulation against the current draft (new) or the saved policy (edit)
  const runSimulation = async () => {
    setError(null);
    setSuccess(null);
    try {
      let result: PolicySimulationRecord;
      if (mode === "edit" && policyId) {
        result = await apiPost<PolicySimulationRecord>(`/policies/${policyId}/simulate`, {});
      } else {
        // For new policies we simulate the in-memory draft
        result = await apiPost<PolicySimulationRecord>("/policies/document/simulate", draft);
      }
      setSimulation(result);
      setSuccess(`Simulation complete — ${result.summary.modules_with_destructive_actions} module(s) have destructive actions.`);
    } catch (err: any) {
      setError(err?.message || "Simulation failed");
    }
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSaving(true);
    setError(null);
    setSuccess(null);

    try {
      if (mode === "edit" && policyId) {
        // Update existing policy document (PUT semantics via the available client helper)
        await apiPut(`/policies/${policyId}`, draft);
        setSuccess("Policy updated successfully. Changes will be picked up by assigned agents on next heartbeat.");
      } else {
        await apiPost("/policies", draft);
        setSuccess("Policy created successfully! Close this editor and assign it from the Policies list.");
      }

      setTimeout(() => {
        if (onBack) onBack();
      }, 1400);
    } catch (err: any) {
      setError(err?.message || (mode === "edit" ? "Failed to update policy" : "Failed to create policy"));
    } finally {
      setIsSaving(false);
    }
  };

  return (
    <div className="policyEditorPage" style={{ padding: "24px", maxWidth: "1200px", margin: "0 auto" }}>
      <div style={{ display: "flex", alignItems: "center", gap: "12px", marginBottom: "24px" }}>
        <button className="btnGhost" onClick={onBack} style={{ display: "flex", alignItems: "center", gap: "6px" }}>
          <ArrowLeft size={16} /> Back to Policies
        </button>
        <h1 style={{ margin: 0 }}>
          {mode === "new" ? "Create New Policy" : "Edit Policy"}
          {isLoadingPolicy ? " (loading…)" : ""}
        </h1>
      </div>

      {error && <ErrorBanner message={error} />}
      {success && <SuccessBanner message={success} />}

      <form onSubmit={handleSave}>
        {/* Basic Info */}
        <div className="policyEditorGrid" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px", marginBottom: "32px" }}>
          <label>
            Policy Name *
            <input
              value={draft.name}
              onChange={(e) => setDraft({ ...draft, name: e.target.value })}
              placeholder="Enter policy name"
              required
            />
          </label>

          <label>
            Company Scope
            <select
              value={draft.scope.customer_id ?? ""}
              onChange={(e) => setScopeField("customer_id", e.target.value || null)}
              disabled={isLoadingCompanies}
            >
              <option value="">Global / Partner-level</option>
              {companyRows.map((row) => (
                <option key={row.customer.id} value={row.customer.id}>
                  {row.customer.name}
                </option>
              ))}
            </select>
          </label>

          <label>
            Parent Policy
            <select
              value={draft.lineage.parent_policy_id ?? ""}
              onChange={(e) => setLineageField("parent_policy_id", e.target.value || null)}
            >
              <option value="">None (Standalone)</option>
              {/* In a full implementation we would load policies here for selection */}
            </select>
          </label>

          <label>
            Inheritance Mode
            <select
              value={draft.lineage.inheritance_mode}
              onChange={(e) => setLineageField("inheritance_mode", e.target.value as "inherit_with_overrides" | "replace")}
            >
              <option value="inherit_with_overrides">Inherit with overrides</option>
              <option value="replace">Replace (no inheritance)</option>
            </select>
          </label>
        </div>

        {/* Modules */}
        <h2 style={{ marginBottom: "16px" }}>Modules</h2>

        <div className="policyAccordionList">
          {MODULES.map((module) => {
            const isOpen = openModules.has(module.key);
            const locked = isLocked(module.key);
            const payload = draft.modules[module.key] ?? {};

            return (
              <article key={module.key} className="policyModuleCard" style={{ border: "1px solid #e2e8f0", borderRadius: "8px", marginBottom: "12px" }}>
                <button
                  type="button"
                  className="policyModuleHead"
                  onClick={() => toggleModuleOpen(module.key)}
                  style={{ width: "100%", textAlign: "left", padding: "12px 16px", display: "flex", justifyContent: "space-between", alignItems: "center", background: "none", border: "none", cursor: "pointer" }}
                >
                  <span>
                    <strong>{module.title}</strong> <small style={{ color: "#64748b" }}>({module.key})</small>
                  </span>
                  <span>
                    {locked && <ShieldAlert size={14} style={{ marginRight: 6, color: "var(--danger)" }} />}
                    {isOpen ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
                  </span>
                </button>

                {isOpen && (
                  <div className="policyModuleBody" style={{ padding: "0 16px 16px" }}>
                    {locked && (
                      <div style={{ padding: "12px", background: "#fef2f2", borderLeft: "4px solid var(--danger)", marginBottom: "12px", borderRadius: "4px" }}>
                        <strong>Locked: {lockedReason(module)}</strong>
                      </div>
                    )}

                    <div style={{ display: "flex", flexDirection: "column", gap: "12px", opacity: locked ? 0.6 : 1 }}>
                      {module.fields.map((field) => {
                        const value = payload[field.key];
                        if (field.type === "boolean") {
                          return (
                            <label key={field.key} style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                              <input
                                type="checkbox"
                                checked={Boolean(value)}
                                disabled={locked && field.key !== "enabled"}
                                onChange={(e) => setModuleField(module.key, field.key, e.target.checked)}
                              />
                              {field.label}
                            </label>
                          );
                        }
                        if (field.type === "select") {
                          return (
                            <label key={field.key}>
                              {field.label}
                              <select
                                value={String(value ?? field.options?.[0] ?? "")}
                                disabled={locked}
                                onChange={(e) => setModuleField(module.key, field.key, e.target.value)}
                                style={{ width: "100%", marginTop: "4px" }}
                              >
                                {field.options?.map((opt) => (
                                  <option key={opt} value={opt}>{opt}</option>
                                ))}
                              </select>
                            </label>
                          );
                        }
                        return (
                          <label key={field.key}>
                            {field.label}
                            <input
                              value={String(value ?? "")}
                              disabled={locked}
                              onChange={(e) => setModuleField(module.key, field.key, e.target.value)}
                              style={{ width: "100%", marginTop: "4px" }}
                            />
                          </label>
                        );
                      })}
                    </div>
                  </div>
                )}
              </article>
            );
          })}
        </div>

        {/* Powerful Editor Actions */}
        <div style={{ marginTop: "32px", paddingTop: "24px", borderTop: "1px solid #e2e8f0" }}>
          <div style={{ display: "flex", gap: "12px", alignItems: "center", flexWrap: "wrap" }}>
            <button 
              type="submit" 
              className="btnPrimary" 
              disabled={isSaving || isLoadingPolicy}
              style={{ minWidth: "160px" }}
            >
              {isSaving
                ? (mode === "edit" ? "Saving Changes..." : "Creating Policy...")
                : (mode === "new" ? "Create & Save Policy" : "Save Changes")}
            </button>

            <button 
              type="button" 
              className="btn" 
              onClick={runSimulation}
            >
              Run Simulation &amp; Impact Analysis
            </button>

            <button 
              type="button" 
              className="btnGhost" 
              onClick={() => alert("Promotion flow will be available after creation in this editor.")}
            >
              Simulate Promotion
            </button>
          </div>

          <p style={{ marginTop: "12px", fontSize: "12px", color: "#64748b" }}>
            This dedicated editor will support live simulation, destructive action warnings, 
            inheritance previews, and direct promotion — all without leaving the powerful editing experience.
          </p>

          {/* Simulation Results */}
          {simulation && (
            <div style={{ marginTop: "24px", padding: "16px", background: "#f8fafc", borderRadius: "8px" }}>
              <h3 style={{ marginTop: 0 }}>Simulation Results</h3>
              <div style={{ display: "flex", gap: "16px", flexWrap: "wrap" }}>
                <div>Total Modules: <strong>{simulation.summary.modules_total}</strong></div>
                <div>Enabled: <strong>{simulation.summary.modules_enabled}</strong></div>
                <div>Would Block: <strong>{simulation.summary.would_block}</strong></div>
                <div>Destructive Actions: <strong>{simulation.summary.modules_with_destructive_actions}</strong></div>
              </div>
              <p style={{ fontSize: "13px", marginTop: "8px" }}>
                {simulation.summary.modules_with_destructive_actions > 0 
                  ? "This policy contains destructive actions and will require explicit promotion approval."
                  : "This policy looks safe to promote without additional gates."}
              </p>
            </div>
          )}
        </div>
      </form>
    </div>
  );
}
