import { FormEvent, useEffect, useMemo, useRef, useState } from "react";
import { Check, ChevronDown, ChevronRight, FlaskConical, Link, Plus, RefreshCw } from "lucide-react";
import {
  apiGet,
  apiPost,
  type CompanySummaryPage,
  type CustomerGroup,
  type EffectivePolicyResponse,
  type Endpoint,
  type InstallerPlatform,
  type PolicyAssignmentV2,
  type PolicyCreateResponse,
  type PolicyDocumentV2Input,
  type PolicyGetResponse,
  type PolicyListItemV2,
  type PolicySimulationRecord,
  type Subscription,
} from "../api";
import { EmptyState, ErrorBanner, LoadingRow, PageHeader, SideSheet, SuccessBanner } from "../components";
import { formatDate } from "../utils";

type FieldType = "boolean" | "select" | "text";

type ModuleField = {
  key: string;
  label: string;
  type: FieldType;
  options?: string[];
};

type ModuleConfig = {
  key: string;
  title: string;
  addon?: string;
  fields: ModuleField[];
};

const CORE_MODULES = new Set([
  "general",
  "tenant_scope",
  "entitlements",
  "deployment_profile",
  "antimalware",
  "behavior_monitoring",
  "anti_exploit",
  "ransomware_mitigation",
  "firewall",
  "network_protection",
  "web_protection",
  "device_control",
  "compliance_evidence",
  "integrations",
  "platform_observability",
  "white_label",
]);

const MODULES: ModuleConfig[] = [
  { key: "general", title: "General", fields: [{ key: "enabled", label: "Enabled", type: "boolean" }, { key: "agent_update_channel", label: "Update channel", type: "select", options: ["stable", "slow", "fast"] }] },
  { key: "tenant_scope", title: "Tenant Scope", fields: [{ key: "enabled", label: "Enabled", type: "boolean" }] },
  { key: "entitlements", title: "Entitlements", fields: [{ key: "enabled", label: "Enabled", type: "boolean" }] },
  { key: "deployment_profile", title: "Deployment Profile", fields: [{ key: "enabled", label: "Enabled", type: "boolean" }] },
  { key: "antimalware", title: "Antimalware", fields: [{ key: "enabled", label: "Enabled", type: "boolean" }, { key: "response_action", label: "Response action", type: "select", options: ["allow", "review", "block"] }] },
  { key: "behavior_monitoring", title: "Behavior Monitoring", fields: [{ key: "enabled", label: "Enabled", type: "boolean" }, { key: "high_confidence_action", label: "High-confidence action", type: "select", options: ["review", "isolate"] }] },
  { key: "anti_exploit", title: "Anti Exploit", fields: [{ key: "enabled", label: "Enabled", type: "boolean" }, { key: "high_confidence_action", label: "High-confidence action", type: "select", options: ["review", "block"] }] },
  { key: "ransomware_mitigation", title: "Ransomware Mitigation", fields: [{ key: "enabled", label: "Enabled", type: "boolean" }, { key: "rollback_approval", label: "Rollback approval", type: "select", options: ["operator_required", "automatic"] }] },
  { key: "firewall", title: "Firewall", fields: [{ key: "enabled", label: "Enabled", type: "boolean" }] },
  { key: "network_protection", title: "Network Protection", fields: [{ key: "enabled", label: "Enabled", type: "boolean" }, { key: "network_attack_signature_action", label: "Network attack action", type: "select", options: ["allow", "review", "block"] }] },
  { key: "web_protection", title: "Web Protection", fields: [{ key: "enabled", label: "Enabled", type: "boolean" }, { key: "sensitive_upload_action", label: "Sensitive upload action", type: "select", options: ["allow", "review", "block"] }] },
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

const ALL_MODULE_KEYS = MODULES.map((module) => module.key);

const PLATFORM_OPTIONS: InstallerPlatform[] = ["windows_msi", "macos_pkg", "linux_deb"];

function defaultModules(): Record<string, Record<string, unknown>> {
  const base: Record<string, Record<string, unknown>> = {};
  for (const module of MODULES) {
    base[module.key] = { enabled: CORE_MODULES.has(module.key) };
  }
  base.antimalware.response_action = "review";
  base.behavior_monitoring.high_confidence_action = "isolate";
  base.anti_exploit.high_confidence_action = "block";
  base.ransomware_mitigation.rollback_approval = "operator_required";
  base.network_protection.network_attack_signature_action = "review";
  base.web_protection.sensitive_upload_action = "block";
  base.semantic_dlp.sensitivity_labels_csv = "Public, Internal, Confidential, Restricted";
  base.semantic_dlp.genai_destinations_csv = "copilot, claude, gemini, chatgpt, custom";
  base.semantic_dlp.paste_sensitive_action = "review";
  base.semantic_dlp.upload_restricted_action = "block";
  base.semantic_dlp.copy_to_genai_action = "review";
  base.semantic_dlp.presidio_detector = true;
  base.semantic_dlp.llm_semantic_detector = true;
  base.semantic_dlp.custom_classifiers_csv = "";
  base.semantic_dlp.actions = {
    paste_sensitive: "review",
    upload_restricted: "block",
    copy_to_genai: "review",
  };
  base.semantic_dlp.detectors = {
    presidio: true,
    llm_semantic: true,
    custom_classifiers: [],
  };
  base.semantic_dlp.sensitivity_labels = ["Public", "Internal", "Confidential", "Restricted"];
  base.semantic_dlp.genai_destinations = ["copilot", "claude", "gemini", "chatgpt", "custom"];

  base.genai_guardrails.destinations_csv = "copilot, claude, gemini, chatgpt, custom";
  base.genai_guardrails.browser_enforcement = true;
  base.genai_guardrails.endpoint_enforcement = true;
  base.genai_guardrails.paste_sensitive_action = "review";
  base.genai_guardrails.upload_restricted_action = "block";
  base.genai_guardrails.copy_to_genai_action = "review";
  base.genai_guardrails.actions = {
    paste_sensitive: "review",
    upload_restricted: "block",
    copy_to_genai: "review",
  };
  base.genai_guardrails.destinations = ["copilot", "claude", "gemini", "chatgpt", "custom"];
  base.agentic_response.default_response = "review";
  base.white_label.display_name = "Default";
  return base;
}

function defaultDraft(): PolicyDocumentV2Input {
  return {
    schema_version: "2.0",
    name: "Default Policy v1.01",
    scope: { partner_id: null, customer_id: null, group_id: null, endpoint_id: null },
    lineage: { parent_policy_id: null, inheritance_mode: "inherit_with_overrides" },
    modules: defaultModules(),
    white_label_names: {},
  };
}

function queryString(filters: Record<string, string | null | undefined>): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(filters)) {
    if (value) params.set(key, value);
  }
  const raw = params.toString();
  return raw ? `?${raw}` : "";
}

export function PolicyPage() {
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [policies, setPolicies] = useState<PolicyListItemV2[]>([]);
  const [selectedPolicyId, setSelectedPolicyId] = useState<string | null>(null);
  const [selectedPolicy, setSelectedPolicy] = useState<PolicyGetResponse | null>(null);
  const [simulation, setSimulation] = useState<PolicySimulationRecord | null>(null);
  const [isWorking, setIsWorking] = useState(false);
  const [openModules, setOpenModules] = useState<Set<string>>(new Set(["general", "antimalware", "semantic_dlp"]));
  const [draft, setDraft] = useState<PolicyDocumentV2Input>(defaultDraft());
  const [companyRows, setCompanyRows] = useState<CompanySummaryPage["items"]>([]);
  const [endpoints, setEndpoints] = useState<Endpoint[]>([]);
  const [subscriptions, setSubscriptions] = useState<Subscription[]>([]);
  const [groups, setGroups] = useState<CustomerGroup[]>([]);
  const [assignmentOpen, setAssignmentOpen] = useState(false);
  const [assignment, setAssignment] = useState({
    target: "customer" as "customer" | "group" | "endpoint",
    customerId: "",
    groupId: "",
    endpointId: "",
    quickDeploy: false,
    platforms: ["windows_msi"] as InstallerPlatform[],
    search: "",
  });
  const [effectivePreview, setEffectivePreview] = useState<EffectivePolicyResponse | null>(null);
  const [filterStatus, setFilterStatus] = useState<string>("");
  const [filterModule, setFilterModule] = useState<string>("");
  const mountedRef = useRef(true);

  async function loadPolicies() {
    const list = await apiGet<PolicyListItemV2[]>(
      `/policies${queryString({ status: filterStatus || null, module: filterModule || null })}`,
    );
    if (!mountedRef.current) return;
    setPolicies(list);
    if (!selectedPolicyId && list[0]) setSelectedPolicyId(list[0].id);
  }

  async function loadBaseData() {
    const [summary, endpointRows, subs] = await Promise.all([
      apiGet<CompanySummaryPage>("/companies/summary?limit=250&offset=0"),
      apiGet<Endpoint[]>("/endpoints"),
      apiGet<Subscription[]>("/subscriptions"),
    ]);
    if (!mountedRef.current) return;
    setCompanyRows(summary.items);
    setEndpoints(endpointRows);
    setSubscriptions(subs);
  }

  async function loadPolicyDetails(policyId: string) {
    const detail = await apiGet<PolicyGetResponse>(`/policies/${policyId}`);
    if (!mountedRef.current) return;
    setSelectedPolicy(detail);
    setDraft(detail.latest_version.payload);
  }

  useEffect(() => {
    mountedRef.current = true;
    setIsLoading(true);
    setError(null);
    Promise.all([loadPolicies(), loadBaseData()])
      .catch((err: unknown) => {
        if (mountedRef.current) setError(err instanceof Error ? err.message : "Failed to load policies");
      })
      .finally(() => {
        if (mountedRef.current) setIsLoading(false);
      });
    return () => {
      mountedRef.current = false;
    };
  }, [filterStatus, filterModule]);

  useEffect(() => {
    if (!selectedPolicyId) return;
    setSimulation(null);
    void loadPolicyDetails(selectedPolicyId).catch((err: unknown) => {
      if (mountedRef.current) setError(err instanceof Error ? err.message : "Failed to load policy");
    });
  }, [selectedPolicyId]);

  useEffect(() => {
    if (!assignmentOpen) {
      setEffectivePreview(null);
      return;
    }
    const endpointId = assignment.target === "endpoint" ? assignment.endpointId : null;
    const customerId = assignment.target === "customer" || assignment.target === "group" ? assignment.customerId : null;
    const groupId = assignment.target === "group" ? assignment.groupId : null;
    if (!endpointId && !customerId) {
      setEffectivePreview(null);
      return;
    }
    void apiGet<EffectivePolicyResponse>(
      `/policies/effective${queryString({ endpoint_id: endpointId || null, customer_id: customerId || null, group_id: groupId || null })}`,
    )
      .then((preview) => {
        if (mountedRef.current) setEffectivePreview(preview);
      })
      .catch(() => {
        if (mountedRef.current) setEffectivePreview(null);
      });
  }, [assignmentOpen, assignment.target, assignment.endpointId, assignment.customerId, assignment.groupId]);

  useEffect(() => {
    if (!assignment.customerId || assignment.target !== "group") {
      setGroups([]);
      return;
    }
    void apiGet<CustomerGroup[]>(`/customers/${assignment.customerId}/groups`)
      .then((rows) => {
        if (mountedRef.current) setGroups(rows);
      })
      .catch(() => {
        if (mountedRef.current) setGroups([]);
      });
  }, [assignment.customerId, assignment.target]);

  const companyMap = useMemo(() => {
    const map = new Map<string, CompanySummaryPage["items"][number]>();
    for (const row of companyRows) map.set(row.customer.id, row);
    return map;
  }, [companyRows]);

  const visibleCompanies = useMemo(() => {
    const q = assignment.search.trim().toLowerCase();
    if (!q) return companyRows;
    return companyRows.filter((row) => `${row.customer.name} ${row.customer.customer_number}`.toLowerCase().includes(q));
  }, [assignment.search, companyRows]);

  const visibleEndpoints = useMemo(() => {
    const q = assignment.search.trim().toLowerCase();
    if (!q) return endpoints;
    return endpoints.filter((ep) => `${ep.hostname} ${ep.id}`.toLowerCase().includes(q));
  }, [assignment.search, endpoints]);

  function customerEntitlements(customerId: string | null): Set<string> {
    if (!customerId) return new Set(ALL_MODULE_KEYS);
    const company = companyMap.get(customerId);
    const modules = new Set<string>(CORE_MODULES);
    if (!company?.license) return modules;
    const sub = subscriptions.find((item) => item.sku === company.license?.subscription_sku);
    for (const feature of sub?.core_features ?? []) modules.add(feature);
    for (const addon of company.license.addons) {
      if (addon === "semantic_dlp") {
        modules.add("semantic_dlp");
        modules.add("classification_labeling");
        modules.add("genai_guardrails");
      } else if (addon === "xdr") {
        modules.add("siem_hids");
        modules.add("integrity_monitoring");
        modules.add("vulnerability_inventory");
        modules.add("incident_correlation");
        modules.add("agentic_response");
        modules.add("ai_reports");
      } else if (addon === "agentic_ir") {
        modules.add("agentic_response");
        modules.add("incident_correlation");
        modules.add("ai_reports");
        modules.add("ai_settings");
      } else {
        modules.add(addon);
      }
    }
    return modules;
  }

  const enabledModules = customerEntitlements(draft.scope.customer_id);

  function isLocked(moduleKey: string): boolean {
    if (CORE_MODULES.has(moduleKey)) return false;
    return !enabledModules.has(moduleKey);
  }

  function lockedReason(module: ModuleConfig): string | null {
    if (!isLocked(module.key)) return null;
    if (!draft.scope.customer_id) return "Set company scope to evaluate add-on entitlement";
    return module.addon ? `Requires ${module.addon} add-on` : "Not included in company subscription";
  }

  function setScopeField<K extends keyof PolicyDocumentV2Input["scope"]>(key: K, value: PolicyDocumentV2Input["scope"][K]) {
    setDraft((current) => ({ ...current, scope: { ...current.scope, [key]: value } }));
  }

  function setModuleField(moduleKey: string, fieldKey: string, value: unknown) {
    setDraft((current) => ({
      ...current,
      modules: {
        ...current.modules,
        [moduleKey]: {
          ...(current.modules[moduleKey] ?? {}),
          [fieldKey]: value,
        },
      },
    }));
  }

  function toggleModuleOpen(moduleKey: string) {
    setOpenModules((current) => {
      const next = new Set(current);
      if (next.has(moduleKey)) next.delete(moduleKey);
      else next.add(moduleKey);
      return next;
    });
  }

  function validateDraft(): string | null {
    if (!draft.name.trim()) return "Policy name is required";
    const lockedEnabled = MODULES.filter((module) => isLocked(module.key) && Boolean(draft.modules[module.key]?.enabled));
    if (lockedEnabled.length > 0) {
      return `Disable locked modules first: ${lockedEnabled.map((module) => module.key).join(", ")}`;
    }
    return null;
  }

  async function createDraft(event: FormEvent) {
    event.preventDefault();
    setError(null);
    setSuccess(null);
    const validation = validateDraft();
    if (validation) {
      setError(validation);
      return;
    }
    setIsWorking(true);
    try {
      const created = await apiPost<PolicyCreateResponse>("/policies", draft);
      setSuccess(`Created draft ${created.policy.name} (v${created.version.version})`);
      await loadPolicies();
      setSelectedPolicyId(created.policy.id);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create draft");
    } finally {
      setIsWorking(false);
    }
  }

  async function simulateSelectedPolicy() {
    if (!selectedPolicyId) return;
    setError(null);
    setSuccess(null);
    setIsWorking(true);
    try {
      const result = await apiPost<PolicySimulationRecord>(`/policies/${selectedPolicyId}/simulate`, {});
      setSimulation(result);
      setSuccess(`Simulation complete: ${result.summary.modules_with_destructive_actions} module(s) trigger approval gates.`);
      await loadPolicyDetails(selectedPolicyId);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Simulation failed");
    } finally {
      setIsWorking(false);
    }
  }

  async function promoteSelectedPolicy() {
    if (!selectedPolicyId || !simulation) return;
    setError(null);
    setSuccess(null);
    setIsWorking(true);
    const requiresApproval = simulation.summary.approval_required;
    try {
      await apiPost(`/policies/${selectedPolicyId}/promote`, {
        simulation_id: simulation.id,
        operator_approved: requiresApproval,
        approval_reason: requiresApproval ? "Operator approved after simulation review" : null,
      });
      setSuccess("Policy promoted successfully.");
      await loadPolicies();
      await loadPolicyDetails(selectedPolicyId);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Promotion failed");
    } finally {
      setIsWorking(false);
    }
  }

  async function assignPolicy() {
    if (!selectedPolicyId) return;
    if (!assignment.customerId && !assignment.endpointId) {
      setError("Select a target company or endpoint before assigning policy");
      return;
    }
    setError(null);
    setSuccess(null);
    setIsWorking(true);
    try {
      const payload = {
        policy_id: selectedPolicyId,
        customer_id: assignment.target === "customer" || assignment.target === "group" ? assignment.customerId : null,
        group_id: assignment.target === "group" ? assignment.groupId : null,
        endpoint_id: assignment.target === "endpoint" ? assignment.endpointId : null,
      };
      await apiPost<PolicyAssignmentV2>("/policies/assign", payload);

      if (assignment.quickDeploy && payload.customer_id) {
        await apiPost(`/customers/${payload.customer_id}/installers`, {
          platforms: assignment.platforms,
          group_id: payload.group_id,
          ttl_seconds: 86400,
          created_by: "policy-editor",
        });
      }

      setAssignmentOpen(false);
      setSuccess(assignment.quickDeploy ? "Policy assigned and installers queued." : "Policy assigned successfully.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Assignment failed");
    } finally {
      setIsWorking(false);
    }
  }

  const destructiveCount = simulation?.summary.modules_with_destructive_actions ?? 0;

  return (
    <>
      <PageHeader
        eyebrow="Policy Engine v2"
        title="Policies"
        subtitle="Create module-driven policies, simulate impact, promote with approvals, and assign across tenant scope"
      />

      {error ? <ErrorBanner message={error} /> : null}
      {success ? <SuccessBanner message={success} /> : null}

      <section className="panel policyV2ListPanel">
        <div className="panelHeader">
          <div>
            <h2>Policy list</h2>
            <span>{policies.length} policy document(s)</span>
          </div>
          <div className="policyV2Actions">
            <select value={filterStatus} onChange={(event) => setFilterStatus(event.target.value)}>
              <option value="">All statuses</option>
              <option value="draft">Draft</option>
              <option value="active">Active</option>
              <option value="archived">Archived</option>
            </select>
            <select value={filterModule} onChange={(event) => setFilterModule(event.target.value)}>
              <option value="">All modules</option>
              {MODULES.map((module) => (
                <option key={module.key} value={module.key}>{module.title}</option>
              ))}
            </select>
            <button className="btnGhost" type="button" onClick={() => void loadPolicies()}>
              <RefreshCw size={16} /> Refresh
            </button>
          </div>
        </div>

        <div className="policyV2TableHead">
          <span>Name</span>
          <span>Scope</span>
          <span>Status</span>
          <span>Version</span>
          <span>Updated</span>
          <span>Actions</span>
        </div>
        {isLoading ? <LoadingRow label="Loading policies" /> : null}
        {!isLoading && policies.length === 0 ? <EmptyState>No policy documents found for your scope.</EmptyState> : null}
        {policies.map((policy) => (
          <article key={policy.id} className={`policyV2Row ${selectedPolicyId === policy.id ? "active" : ""}`}>
            <span>{policy.name}</span>
            <span className="mono">{policy.scope.customer_id ?? policy.scope.partner_id ?? "Global"}</span>
            <span><strong className={`statusPill status-${policy.status}`}>{policy.status}</strong></span>
            <span>v{policy.latest_version}</span>
            <span>{formatDate(policy.updated_at)}</span>
            <div className="policyV2RowActions">
              <button type="button" className="btnGhost" onClick={() => setSelectedPolicyId(policy.id)}>Edit</button>
              <button type="button" className="btnGhost" onClick={() => { setSelectedPolicyId(policy.id); void simulateSelectedPolicy(); }}>
                <FlaskConical size={14} /> Simulate
              </button>
              <button type="button" className="btnGhost" onClick={() => { setSelectedPolicyId(policy.id); setAssignmentOpen(true); }}>
                <Link size={14} /> Assign
              </button>
            </div>
          </article>
        ))}
      </section>

      <section className="panel policyV2EditorPanel">
        <div className="panelHeader">
          <div>
            <h2>Policy editor</h2>
            <span>Module-by-module editing with entitlement checks and simulation gates</span>
          </div>
          <div className="policyV2Actions">
            <button className="btnPrimary" type="button" disabled={isWorking} onClick={() => setDraft(defaultDraft())}>
              <Plus size={16} /> New template
            </button>
          </div>
        </div>

        <form onSubmit={createDraft} className="policyEditorForm">
          <div className="policyEditorGrid">
            <label>
              Policy name
              <input value={draft.name} onChange={(event) => setDraft((current) => ({ ...current, name: event.target.value }))} />
            </label>
            <label>
              Company scope
              <select
                value={draft.scope.customer_id ?? ""}
                onChange={(event) => {
                  const id = event.target.value || null;
                  const company = id ? companyMap.get(id) : null;
                  setScopeField("customer_id", id);
                  setScopeField("partner_id", company?.customer.partner_id ?? null);
                }}
              >
                <option value="">Global / Partner-level</option>
                {companyRows.map((row) => (
                  <option key={row.customer.id} value={row.customer.id}>{row.customer.name}</option>
                ))}
              </select>
            </label>
            <label>
              Parent policy
              <select
                value={draft.lineage.parent_policy_id ?? ""}
                onChange={(event) => setDraft((current) => ({
                  ...current,
                  lineage: { ...current.lineage, parent_policy_id: event.target.value || null },
                }))}
              >
                <option value="">None</option>
                {policies.map((policy) => (
                  <option key={policy.id} value={policy.id}>{policy.name} (v{policy.latest_version})</option>
                ))}
              </select>
            </label>
            <label>
              Inheritance mode
              <select
                value={draft.lineage.inheritance_mode}
                onChange={(event) => setDraft((current) => ({
                  ...current,
                  lineage: { ...current.lineage, inheritance_mode: event.target.value as PolicyDocumentV2Input["lineage"]["inheritance_mode"] },
                }))}
              >
                <option value="inherit_with_overrides">Inherit with overrides</option>
                <option value="replace">Replace</option>
              </select>
            </label>
          </div>

          <div className="policyAccordionList">
            {MODULES.map((module) => {
              const open = openModules.has(module.key);
              const locked = isLocked(module.key);
              const reason = lockedReason(module);
              const payload = draft.modules[module.key] ?? {};
              return (
                <article key={module.key} className="policyModuleCard">
                  <button type="button" className="policyModuleHead" onClick={() => toggleModuleOpen(module.key)}>
                    <span>
                      <strong>{module.title}</strong>
                      <small>{module.key}</small>
                    </span>
                    <span className="policyModuleHeadRight">
                      {locked ? <em className="lockBadge">Locked</em> : null}
                      {open ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
                    </span>
                  </button>
                  {open ? (
                    <div className="policyModuleBody">
                      {reason ? <p className="policyLockReason">{reason}</p> : null}
                      <div className="policyModuleFields">
                        {module.fields.map((field) => {
                          const value = payload[field.key];
                          if (field.type === "boolean") {
                            return (
                              <label key={field.key} className="toggleRow">
                                <input
                                  type="checkbox"
                                  checked={Boolean(value)}
                                  disabled={locked && field.key !== "enabled"}
                                  onChange={(event) => setModuleField(module.key, field.key, event.target.checked)}
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
                                  onChange={(event) => setModuleField(module.key, field.key, event.target.value)}
                                >
                                  {field.options?.map((option) => (
                                    <option key={option} value={option}>{option}</option>
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
                                onChange={(event) => setModuleField(module.key, field.key, event.target.value)}
                              />
                            </label>
                          );
                        })}
                      </div>
                    </div>
                  ) : null}
                </article>
              );
            })}
          </div>

          <div className="policyEditorActions">
            <button className="btnPrimary" type="submit" disabled={isWorking}>Save draft</button>
            <button className="btnGhost" type="button" disabled={!selectedPolicyId || isWorking} onClick={() => void simulateSelectedPolicy()}>
              <FlaskConical size={14} /> Simulate selected
            </button>
            <button className="btnGhost" type="button" disabled={!selectedPolicyId || !simulation || isWorking} onClick={() => void promoteSelectedPolicy()}>
              <Check size={14} /> Promote selected
            </button>
            <button className="btnGhost" type="button" disabled={!selectedPolicyId || isWorking} onClick={() => setAssignmentOpen(true)}>
              <Link size={14} /> Assign selected
            </button>
          </div>
        </form>
      </section>

      <section className="panel policyV2SimulationPanel">
        <div className="panelHeader">
          <div>
            <h2>Simulation impact</h2>
            <span>{simulation ? `Last run ${formatDate(simulation.created_at)}` : "Run simulation to populate impact preview"}</span>
          </div>
        </div>
        {!simulation ? <EmptyState>No simulation has been run for the selected policy.</EmptyState> : null}
        {simulation ? (
          <>
            <div className="policySimulationSummary">
              <span>Modules: {simulation.summary.modules_total}</span>
              <span>Enabled: {simulation.summary.modules_enabled}</span>
              <span>Block: {simulation.summary.would_block}</span>
              <span>Isolate: {simulation.summary.would_isolate}</span>
              <span>Rollback: {simulation.summary.would_rollback}</span>
            </div>
            <p className="policyGateHint">
              {destructiveCount > 0
                ? `Approval gate active: ${destructiveCount} module(s) include block/isolate/rollback actions.`
                : "No destructive actions detected; promotion can proceed without explicit approval."}
            </p>
            <div className="policyOutcomeList">
              {simulation.outcomes.map((outcome) => (
                <article key={outcome.module} className="policyOutcomeRow">
                  <strong>{outcome.module}</strong>
                  <span>{outcome.enabled ? "enabled" : "disabled"}</span>
                  <span>{outcome.destructive_actions.length > 0 ? outcome.destructive_actions.join(", ") : "no destructive action"}</span>
                </article>
              ))}
            </div>
          </>
        ) : null}
      </section>

      <SideSheet
        open={assignmentOpen}
        onClose={() => setAssignmentOpen(false)}
        title="Assign policy"
        subtitle="Choose a target scope and preview effective inheritance"
      >
        <div className="policyAssignBody">
          <label>
            Search
            <input
              value={assignment.search}
              onChange={(event) => setAssignment((current) => ({ ...current, search: event.target.value }))}
              placeholder="Search company or endpoint"
            />
          </label>
          <div className="policyAssignTypeSwitch">
            {(["customer", "group", "endpoint"] as const).map((type) => (
              <button
                key={type}
                type="button"
                className={assignment.target === type ? "active" : ""}
                onClick={() => setAssignment((current) => ({ ...current, target: type }))}
              >
                {type}
              </button>
            ))}
          </div>

          {assignment.target === "endpoint" ? (
            <label>
              Endpoint
              <select
                value={assignment.endpointId}
                onChange={(event) => setAssignment((current) => ({ ...current, endpointId: event.target.value }))}
              >
                <option value="">Select endpoint</option>
                {visibleEndpoints.map((endpoint) => (
                  <option key={endpoint.id} value={endpoint.id}>{endpoint.hostname} ({endpoint.id})</option>
                ))}
              </select>
            </label>
          ) : (
            <label>
              Company
              <select
                value={assignment.customerId}
                onChange={(event) => setAssignment((current) => ({ ...current, customerId: event.target.value, groupId: "" }))}
              >
                <option value="">Select company</option>
                {visibleCompanies.map((row) => (
                  <option key={row.customer.id} value={row.customer.id}>{row.customer.name}</option>
                ))}
              </select>
            </label>
          )}

          {assignment.target === "group" ? (
            <label>
              Group
              <select
                value={assignment.groupId}
                onChange={(event) => setAssignment((current) => ({ ...current, groupId: event.target.value }))}
              >
                <option value="">Select group</option>
                {groups.map((group) => (
                  <option key={group.id} value={group.id}>{group.name}</option>
                ))}
              </select>
            </label>
          ) : null}

          {assignment.target !== "endpoint" ? (
            <>
              <label className="toggleRow">
                <input
                  type="checkbox"
                  checked={assignment.quickDeploy}
                  onChange={(event) => setAssignment((current) => ({ ...current, quickDeploy: event.target.checked }))}
                />
                One-click assign and generate installers
              </label>
              {assignment.quickDeploy ? (
                <label>
                  Platforms
                  <select
                    value={assignment.platforms[0]}
                    onChange={(event) => setAssignment((current) => ({ ...current, platforms: [event.target.value as InstallerPlatform] }))}
                  >
                    {PLATFORM_OPTIONS.map((platform) => (
                      <option key={platform} value={platform}>{platform}</option>
                    ))}
                  </select>
                </label>
              ) : null}
            </>
          ) : null}

          <div className="policyAssignPreview">
            <h3>Inheritance preview</h3>
            {!effectivePreview ? <p className="muted">Select a target to preview effective policy resolution.</p> : null}
            {effectivePreview ? (
              <>
                <p className="muted">Assignments applied: {effectivePreview.assignments_applied.length}</p>
                <div className="policyPreviewModules">
                  {Object.entries(effectivePreview.resolved_policy.modules).map(([key, value]) => (
                    <span key={key} className={value.enabled ? "badge" : "badge band-medium"}>
                      {key}
                    </span>
                  ))}
                </div>
              </>
            ) : null}
          </div>

          <div className="policyAssignActions">
            <button className="btnGhost" type="button" onClick={() => setAssignmentOpen(false)}>Cancel</button>
            <button className="btnPrimary" type="button" disabled={isWorking || !selectedPolicyId} onClick={() => void assignPolicy()}>
              Assign policy
            </button>
          </div>
        </div>
      </SideSheet>
    </>
  );
}
