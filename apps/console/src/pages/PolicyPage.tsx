import { FormEvent, useEffect, useMemo, useRef, useState } from "react";
import { Check, ChevronDown, ChevronRight, CircleDot, CircleMinus, Columns3, Copy, FlaskConical, Link, Plus, RefreshCw, ShieldAlert, ShieldCheck, AlertTriangle, ArrowUpRight } from "lucide-react";
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
  type PolicyListResponseV2,
  type PolicySimulationRecord,
  type Subscription,
} from "../api";
import { DeviceControlSection } from "../components/protection/DeviceControlSection";
import { EmptyState, ErrorBanner, LoadingRow, SideSheet, SuccessBanner } from "../components";
import { formatDate } from "../utils";

type FieldType = "boolean" | "select" | "text";
type PolicySection =
  | "details"
  | "inheritance"
  | "agentNotifications"
  | "agentSettings"
  | "agentCommunication"
  | "agentUpdate"
  | "agentTelemetry"
  | "relayCommunication"
  | "relayUpdate"
  | "antimalwareOnAccess"
  | "antimalwareOnExecute"
  | "antimalwareOnDemand"
  | "antimalwareIntegrity"
  | "antimalwareHyperDetect"
  | "antimalwareAdvancedExploit"
  | "antimalwareSecurityServers"
  | "antimalwareSettings"
  | "antimalwareExclusions"
  | "sandboxAnalyzerEndpoint"
  | "firewallGeneral"
  | "firewallSettings"
  | "firewallRules"
  | "networkProtectionGeneral"
  | "networkProtectionContent"
  | "networkProtectionWeb"
  | "networkProtectionAttacks"
  | "networkProtectionCustomPages"
  | "patchManagement"
  | "deviceControl"
  | "integrityMonitoring"
  | "exchangeProtection"
  | "encryption"
  | "incidentsSensor"
  | "storageProtection"
  | "riskManagementGeneral"
  | "riskManagementPhasr"
  | "blocklist"
  | "liveSearch"
  | "modules";

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

const ALL_MODULE_KEYS = MODULES.map((module) => module.key);

const POLICY_MODULE_GROUPS = [
  { label: "Web, DLP & GenAI", meta: "5/7", modules: ["web_protection", "classification_labeling", "semantic_dlp", "genai_guardrails"] },
  { label: "SIEM / HIDS", meta: "2/4", modules: ["siem_hids", "integrity_monitoring", "vulnerability_inventory"] },
  { label: "Agentic Response", meta: "On", modules: ["incident_correlation", "agentic_response", "ai_settings", "ai_reports"] },
  { label: "Digital Risk & EASM", meta: "Off", modules: ["digital_risk_protection", "external_attack_surface_management", "threat_intelligence", "takedown_workflows"] },
  { label: "Compliance Evidence", meta: "On", modules: ["compliance_evidence"] },
  { label: "Integrations & Branding", meta: "2/2", modules: ["integrations", "platform_observability", "white_label"] },
];

const PLATFORM_OPTIONS: InstallerPlatform[] = ["windows_msi", "macos_pkg", "linux_deb"];

interface DeploymentProfileData {
  enabled: boolean;
  update_channel: string;
  update_interval_hours: number;
  deployment_ring: string;
  rollout_percentage: number;
  proxy_enabled: boolean;
  proxy_server: string;
  proxy_port: string;
  silent_mode: boolean;
  show_alerts: boolean;
  show_notifications: boolean;
  endpoint_issues_visibility: boolean;
  telemetry_enabled: boolean;
  siem_url: string;
  siem_token: string;
  uninstall_password: string | null;
  power_user_password: string | null;
  relay_auto_discovery: boolean;
  allowed_upload_domains: string[];
  update_locations: Array<{ server: string; use_proxy: boolean }>;
  communication_assignments: Array<{ priority: number; name: string; ip: string }>;
  use_proxy_for_relay: boolean;
  use_proxy_for_cloud: boolean;
  use_proxy_for_siem: boolean;
  reboot_postpone: boolean;
  reboot_time: string;
  managed_update_fallback: boolean;
}

function defaultModules(): Record<string, Record<string, unknown>> {
  const base: Record<string, Record<string, unknown>> = {};
  for (const module of MODULES) {
    base[module.key] = { enabled: CORE_MODULES.has(module.key) };
  }
  base.antimalware.response_action = "review";
  base.behavior_monitoring.high_confidence_action = "isolate";
  base.anti_exploit.high_confidence_action = "block";
  base.ransomware_mitigation.rollback_approval = "operator_required";
  base.firewall.profile = "known_allow";
  base.firewall.log_level = "low";
  base.network_protection.encrypted_traffic_interception = false;
  base.network_protection.tls_handshake_interception = true;
  base.network_protection.network_attack_signature_action = "review";
  base.web_protection.content_control_enabled = false;
  base.web_protection.antiphishing_action = "block";
  base.web_protection.infected_website_action = "block";
  base.web_protection.email_scan_enabled = false;
  base.web_protection.custom_pages_enabled = false;
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
  base.sandbox_analyzer.analysis_mode = "monitoring";
  base.sandbox_analyzer.default_action = "report";
  base.patch_management.maintenance_window = "none";
  base.device_control.enabled = false;
  base.device_control.device_access = "monitor";
  base.integrity_monitoring.scan_mode = "monitor";
  base.exchange_protection = { enabled: false, user_groups_enabled: true, antispam_enabled: true, spoof_protection: false };
  base.encryption = { enabled: false, removable_media_action: "ask" };
  base.incidents_sensor = { enabled: true, retention_days: 30 };
  base.storage_protection = { enabled: false, scan_archives: true };
  base.risk_management = { enabled: false, missed_runtime_action: true, recurrence_days: 1 };
  base.phasr = { enabled: false, living_off_land_action: "off", remote_admin_action: "off", tampering_action: "off", piracy_action: "off", crypto_miner_action: "off" };
  base.blocklist = { enabled: true, application_hash: true, dll_files: false, script_files: false, application_path: false, network_connection: true };
  base.live_search = { enabled: false };
  base.deployment_profile.update_channel = "stable";
  base.deployment_profile.update_interval_hours = 1;
  base.deployment_profile.deployment_ring = "stable";
  base.deployment_profile.rollout_percentage = 100;
  base.deployment_profile.proxy_enabled = false;
  base.deployment_profile.proxy_server = "";
  base.deployment_profile.proxy_port = "8080";
  base.deployment_profile.silent_mode = false;
  base.deployment_profile.show_alerts = true;
  base.deployment_profile.telemetry_enabled = false;
  base.deployment_profile.relay_auto_discovery = false;
  base.deployment_profile.use_proxy_for_relay = true;
  base.deployment_profile.use_proxy_for_cloud = true;
  base.deployment_profile.reboot_postpone = true;
  base.deployment_profile.managed_update_fallback = true;
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
  const [viewMode, setViewMode] = useState<"catalog" | "detail">("catalog");
  const [detailMode, setDetailMode] = useState<"new" | "existing">("new");
  const [policySection, setPolicySection] = useState<PolicySection>("details");
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
  
  const [filterModule] = useState<string>("");

  const [filterName, setFilterName] = useState("");
  
  const [simulatedPolicyIds, setSimulatedPolicyIds] = useState<Set<string>>(new Set());
  const [promotedPolicyIds, setPromotedPolicyIds] = useState<Set<string>>(new Set());
  const [promotionOpen, setPromotionOpen] = useState(false);
  const [operatorApproved, setOperatorApproved] = useState(false);
  const [operatorJustification, setOperatorJustification] = useState("");

  // Note: New policy creation now uses the dedicated PolicyEditorPage route.
  // The old SideSheet approach has been superseded by the cleaner dedicated page.
  const [filterCompany, setFilterCompany] = useState("");
  const [selectedPolicyIds, setSelectedPolicyIds] = useState<Set<string>>(new Set());
  const [expandedSections, setExpandedSections] = useState<Record<string, boolean>>({
    general: true,
    protection: true,
    agent: true,
    relay: true,
    antimalware: true,
    sandbox: true,
    firewall: true,
    network: true,
    risk: false,
  });
  const mountedRef = useRef(true);

  async function loadPolicies() {
    const page = await apiGet<PolicyListResponseV2>(
      `/policies${queryString({ status: filterStatus || null, module: filterModule || null })}`,
    );
    if (!mountedRef.current) return;
    const list = page.items;
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

  const visiblePolicies = useMemo(() => {
    const nameQuery = filterName.trim().toLowerCase();
    return policies.filter((policy) => {
      const companyId = policy.scope.customer_id ?? "";
      const matchesName = !nameQuery || policy.name.toLowerCase().includes(nameQuery);
      
      const isSimulated = simulatedPolicyIds.has(policy.id) || policy.latest_version > 1;
      const isPromoted = promotedPolicyIds.has(policy.id) || policy.status === "active";
      
      let statusLabel = "draft";
      if (policy.status === "active") {
        statusLabel = "active";
      } else if (isPromoted) {
        statusLabel = "promoted";
      } else if (isSimulated) {
        statusLabel = "simulated";
      }
      
      const matchesStatus = !filterStatus || statusLabel === filterStatus.toLowerCase();
      
      let matchesCompany = true;
      if (filterCompany) {
         if (filterCompany === "global") {
           matchesCompany = !companyId;
         } else {
           matchesCompany = companyId === filterCompany;
         }
      }
      return matchesName && matchesStatus && matchesCompany;
    });
  }, [filterCompany, filterName, filterStatus, policies, simulatedPolicyIds, promotedPolicyIds]);

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
      } else if (addon === "sandbox") {
        modules.add("sandbox_analyzer");
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
      setSimulatedPolicyIds((prev) => {
        const next = new Set(prev);
        next.add(selectedPolicyId);
        return next;
      });
      setSuccess(`Simulation complete: ${result.summary.modules_with_destructive_actions} module(s) trigger approval gates.`);
      await loadPolicyDetails(selectedPolicyId);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Simulation failed");
    } finally {
      setIsWorking(false);
    }
  }

  function openPromotionGate() {
    if (!selectedPolicyId || !simulation) return;
    setOperatorApproved(false);
    setOperatorJustification("");
    setPromotionOpen(true);
  }

  async function promoteSelectedPolicy() {
    if (!selectedPolicyId || !simulation) return;
    const requiresApproval = simulation.summary.approval_required;
    if (requiresApproval && !operatorApproved) {
      setError("Double-confirmation sign-off is required to promote this policy containing destructive actions.");
      return;
    }
    setError(null);
    setSuccess(null);
    setIsWorking(true);
    try {
      await apiPost(`/policies/${selectedPolicyId}/promote`, {
        simulation_id: simulation.id,
        operator_approved: operatorApproved || !requiresApproval,
        approval_reason: operatorJustification || (requiresApproval ? "Operator approved after simulation review" : "Automated promotion"),
      });
      setPromotedPolicyIds((prev) => {
        const next = new Set(prev);
        next.add(selectedPolicyId);
        return next;
      });
      setSuccess("Policy promoted successfully.");
      setPromotionOpen(false);
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

  function togglePolicySelection(policyId: string) {
    setSelectedPolicyIds((current) => {
      const next = new Set(current);
      if (next.has(policyId)) next.delete(policyId);
      else next.add(policyId);
      return next;
    });
  }

  function toggleVisiblePolicySelection() {
    setSelectedPolicyIds((current) => {
      const allVisibleSelected = visiblePolicies.length > 0 && visiblePolicies.every((policy) => current.has(policy.id));
      if (allVisibleSelected) return new Set([...current].filter((id) => !visiblePolicies.some((policy) => policy.id === id)));
      const next = new Set(current);
      for (const policy of visiblePolicies) next.add(policy.id);
      return next;
    });
  }

  const destructiveCount = simulation?.summary.modules_with_destructive_actions ?? 0;
  const selectedCount = selectedPolicyIds.size;
  const allVisibleSelected = visiblePolicies.length > 0 && visiblePolicies.every((policy) => selectedPolicyIds.has(policy.id));
  // Note: New policy creation has been moved to the dedicated PolicyEditorPage route.
  // The old monolithic editor code below is being phased out.

  // "Add Policy" now opens the dedicated PolicyEditorPage (clean route-based experience).
  function openNewPolicy() {
    const event = new CustomEvent("aetherix:navigate", { 
      detail: "policyEditor" 
    });
    window.dispatchEvent(event);
  }

  function openExistingPolicy(policyId: string) {
    setDetailMode("existing");
    setSelectedPolicyId(policyId);
    setPolicySection("details");
    setViewMode("detail");
  }

  function closeDetail() {
    setError(null);
    setSuccess(null);
    setViewMode("catalog");
  }

  function openPolicyModules(moduleKeys: string[]) {
    setOpenModules((current) => new Set([...current, ...moduleKeys]));
    setPolicySection("modules");
  }

  const currentPolicyName = detailMode === "new" ? draft.name : selectedPolicy?.policy.name ?? draft.name;
  const detailTitle = detailMode === "new" ? "Add policy" : currentPolicyName;
  const sectionTitle: Record<PolicySection, string> = {
    details: "Details",
    inheritance: "Inheritance rules",
    agentNotifications: "Notifications",
    agentSettings: "Settings",
    agentCommunication: "Communication",
    agentUpdate: "Update",
    agentTelemetry: "Security Telemetry",
    relayCommunication: "Communication",
    relayUpdate: "Update",
    antimalwareOnAccess: "On-Access",
    antimalwareOnExecute: "On-Execute",
    antimalwareOnDemand: "On-Demand",
    antimalwareIntegrity: "Integrity Protection",
    antimalwareHyperDetect: "Hyper Detect",
    antimalwareAdvancedExploit: "Advanced Anti-Exploit",
    antimalwareSecurityServers: "Security Servers",
    antimalwareSettings: "Settings",
    antimalwareExclusions: "Exclusions",
    sandboxAnalyzerEndpoint: "Endpoint Sensor",
    firewallGeneral: "General",
    firewallSettings: "Settings",
    firewallRules: "Rules",
    networkProtectionGeneral: "General",
    networkProtectionContent: "Content Control",
    networkProtectionWeb: "Web Protection",
    networkProtectionAttacks: "Network Attacks",
    networkProtectionCustomPages: "Custom Pages",
    patchManagement: "Patch Management",
    deviceControl: "Device Control",
    integrityMonitoring: "Integrity Monitoring",
    exchangeProtection: "Exchange Protection",
    encryption: "Encryption",
    incidentsSensor: "Incidents Sensor",
    storageProtection: "Storage Protection",
    riskManagementGeneral: "General",
    riskManagementPhasr: "PHASR",
    blocklist: "Blocklist",
    liveSearch: "Live Search",
    modules: "Aetherix modules",
  };

  function sectionParent(section: PolicySection): "Policy" | "Agent" | "Relay" | "Antimalware" | "Sandbox Analyzer" | "Firewall" | "Network Protection" | "Patch Management" | "Device Control" | "Integrity Monitoring" | "Exchange Protection" | "Encryption" | "Incidents Sensor" | "Storage Protection" | "Risk Management" | "Blocklist" | "Live Search" | "Aetherix" {
    if (section === "details" || section === "inheritance") return "Policy";
    if (section === "modules") return "Aetherix";
    if (section === "relayCommunication" || section === "relayUpdate") return "Relay";
    if (section.startsWith("antimalware")) return "Antimalware";
    if (section === "sandboxAnalyzerEndpoint") return "Sandbox Analyzer";
    if (section.startsWith("firewall")) return "Firewall";
    if (section.startsWith("networkProtection")) return "Network Protection";
    if (section === "patchManagement") return "Patch Management";
    if (section === "deviceControl") return "Device Control";
    if (section === "integrityMonitoring") return "Integrity Monitoring";
    if (section === "exchangeProtection") return "Exchange Protection";
    if (section === "encryption") return "Encryption";
    if (section === "incidentsSensor") return "Incidents Sensor";
    if (section === "storageProtection") return "Storage Protection";
    if (section === "riskManagementGeneral" || section === "riskManagementPhasr") return "Risk Management";
    if (section === "blocklist") return "Blocklist";
    if (section === "liveSearch") return "Live Search";
    return "Agent";
  }

  const antimalwareEnabled = draft.modules.antimalware?.enabled !== false;
  const behaviorEnabled = draft.modules.behavior_monitoring?.enabled !== false;
  const antiExploitEnabled = draft.modules.anti_exploit?.enabled !== false;
  const ransomwareEnabled = draft.modules.ransomware_mitigation?.enabled === true;
  const sandboxEnabled = draft.modules.sandbox_analyzer?.enabled === true;
  const firewallEnabled = draft.modules.firewall?.enabled !== false;
  const networkProtectionEnabled = draft.modules.network_protection?.enabled !== false;
  const contentControlEnabled = draft.modules.web_protection?.content_control_enabled === true;
  const webProtectionEnabled = draft.modules.web_protection?.enabled !== false;
  const customPagesEnabled = draft.modules.web_protection?.custom_pages_enabled === true;
  const patchManagementEnabled = draft.modules.patch_management?.enabled === true;
  const deviceControlEnabled = draft.modules.device_control?.enabled === true;
  const integrityMonitoringEnabled = draft.modules.integrity_monitoring?.enabled === true;
  const exchangeProtectionEnabled = draft.modules.exchange_protection?.enabled === true;
  const encryptionEnabled = draft.modules.encryption?.enabled === true;
  const incidentsSensorEnabled = draft.modules.incidents_sensor?.enabled !== false;
  const storageProtectionEnabled = draft.modules.storage_protection?.enabled === true;
  const riskManagementEnabled = draft.modules.risk_management?.enabled === true;
  const phasrEnabled = draft.modules.phasr?.enabled === true;
  const blocklistEnabled = draft.modules.blocklist?.enabled === true;
  const liveSearchEnabled = draft.modules.live_search?.enabled === true;

  function renderSwitchTitle(title: string, enabled = true) {
    return (
      <h1 className="policySwitchTitle">
        <span className={`policySwitch ${enabled ? "on" : ""}`} aria-hidden="true" />
        {title}
      </h1>
    );
  }

  function renderAgentNotifications() {
    const dp = (draft.modules.deployment_profile ?? {}) as unknown as DeploymentProfileData;
    return (
      <section className="policyDetailSection policyAgentBlock">
        {renderSwitchTitle("Notifications", !dp.silent_mode)}
        <p>Customize how the security agent displays notifications on the endpoint. Disabling notifications activates Silent Mode.</p>
        <div className="policyAgentStack">
          <label className="policySwitchRow" onClick={() => setModuleField("deployment_profile", "silent_mode", !dp.silent_mode)}>
            <span className={`policySwitch ${!dp.silent_mode ? "on" : ""}`} aria-hidden="true" />
            Show icon in notification area
          </label>
          <p>A system reboot may be required to apply this setting.</p>
          <label className="policySwitchRow" onClick={() => setModuleField("deployment_profile", "show_alerts", !dp.show_alerts)}>
            <span className={`policySwitch ${dp.show_alerts ? "on" : ""}`} aria-hidden="true" />
            Display alert pop-ups
          </label>
          <p>Alert pop-ups require user action. Disabling this option applies the recommended action on the endpoint.</p>
          <label className="policySwitchRow" onClick={() => setModuleField("deployment_profile", "show_notifications", !dp.show_notifications)}>
            <span className={`policySwitch ${dp.show_notifications !== false ? "on" : ""}`} aria-hidden="true" />
            Display notification pop-ups
          </label>
          <p>Notifications provide endpoint users with critical security event information without user interaction.</p>
          <label className="policySwitchRow" onClick={() => setModuleField("deployment_profile", "endpoint_issues_visibility", !dp.endpoint_issues_visibility)}>
            <span className={`policySwitch ${dp.endpoint_issues_visibility !== false ? "on" : ""}`} aria-hidden="true" />
            Endpoint issues visibility
          </label>
          <p>Status alerts notify endpoint users of current security issues within specified categories.</p>
        </div>
      </section>
    );
  }

  function renderAgentSettings() {
    const dp = (draft.modules.deployment_profile ?? {}) as unknown as DeploymentProfileData;
    return (
      <section className="policyDetailSection policyAgentBlock">
        <h1>Settings</h1>
        <div className="policyAgentStack">
          <h2>Uninstall password configuration</h2>
          <label className="policyRadioRow"><input type="radio" name="uninstall" defaultChecked={!dp.uninstall_password} /> Keep installation settings</label>
          <label className="policyRadioRow"><input type="radio" name="uninstall" defaultChecked={!!dp.uninstall_password} /> Set uninstall password</label>
          <p>Setting an uninstall password requires users to enter this password to uninstall the security agent.</p>
          <label className="policyInlineField"><span>Password:</span><input type="password" value={dp.uninstall_password ?? ""} onChange={(e) => setModuleField("deployment_profile", "uninstall_password", e.target.value)} /></label>
        </div>
        <div className="policyAgentSubsection">
          <label className="policySwitchRow" onClick={() => setModuleField("deployment_profile", "proxy_enabled", !dp.proxy_enabled)}>
            <span className={`policySwitch ${dp.proxy_enabled ? "on" : ""}`} aria-hidden="true" />
            Proxy configuration
          </label>
          <label className="policyInlineField"><span>Server:</span><input placeholder="http://proxy" value={dp.proxy_server ?? ""} onChange={(e) => setModuleField("deployment_profile", "proxy_server", e.target.value)} disabled={!dp.proxy_enabled} /></label>
          <label className="policyInlineField"><span>Port:</span><input type="number" value={dp.proxy_port ?? "8080"} onChange={(e) => setModuleField("deployment_profile", "proxy_port", e.target.value)} disabled={!dp.proxy_enabled} /></label>
        </div>
        <div className="policyAgentSubsection">
          <label className="policySwitchRow" onClick={() => setModuleField("deployment_profile", "power_user_password", dp.power_user_password ? null : "changeme")}>
            <span className={`policySwitch ${dp.power_user_password ? "on" : ""}`} aria-hidden="true" />
            Power user
          </label>
          <label className="policyInlineField"><span>Password:</span><input type="password" value={dp.power_user_password ?? ""} onChange={(e) => setModuleField("deployment_profile", "power_user_password", e.target.value)} /></label>
        </div>
      </section>
    );
  }

  function renderAgentCommunication() {
    const dp = (draft.modules.deployment_profile ?? {}) as unknown as DeploymentProfileData;
    return (
      <section className="policyDetailSection policyAgentBlock wideAgent">
        <h1>Communication</h1>
        <h2>Endpoint communication assignment</h2>
        <p>Assign one or more Aetherix relays or control-plane communication endpoints to the target endpoints.</p>
        <div className="policyCommunicationBuilder">
          <input type="number" placeholder="Priority" aria-label="Priority" onChange={(e) => {
            const assignments = [...(dp.communication_assignments ?? [])];
            assignments.push({ priority: parseInt(e.target.value) || 1, name: "", ip: "" });
            setModuleField("deployment_profile", "communication_assignments", assignments);
          }} />
        </div>
        <div className="policyAssignmentTable">
          <div><span>Priority</span><span>Name</span><span>IP address</span></div>
          {(dp.communication_assignments ?? []).length === 0 ? <p>No assignments</p> :
            (dp.communication_assignments ?? []).map((a: Record<string, unknown>, i: number) => (
              <div key={i}><span>{String(a.priority ?? "")}</span><span>{String(a.name ?? "")}</span><span>{String(a.ip ?? "")}</span></div>
            ))}
        </div>
        <h2>Communication between endpoints and Aetherix relays</h2>
        <label className="policyRadioRow" onClick={() => setModuleField("deployment_profile", "use_proxy_for_relay", true)}>
          <input type="radio" name="relayProxy" checked={dp.use_proxy_for_relay !== false} readOnly /> Use previous settings
        </label>
        <label className="policyRadioRow" onClick={() => setModuleField("deployment_profile", "use_proxy_for_relay", false)}>
          <input type="radio" name="relayProxy" checked={dp.use_proxy_for_relay === false} readOnly /> Do not use proxy
        </label>
        <h2>Communication between endpoints and Cloud Services</h2>
        <label className="policyRadioRow" onClick={() => setModuleField("deployment_profile", "use_proxy_for_cloud", true)}>
          <input type="radio" name="cloudProxy" checked={dp.use_proxy_for_cloud !== false} readOnly /> Use previous settings
        </label>
        <label className="policyRadioRow" onClick={() => setModuleField("deployment_profile", "use_proxy_for_cloud", false)}>
          <input type="radio" name="cloudProxy" checked={dp.use_proxy_for_cloud === false} readOnly /> Do not use proxy
        </label>
      </section>
    );
  }

  function renderAgentUpdate() {
    const dp = (draft.modules.deployment_profile ?? {}) as unknown as DeploymentProfileData;
    return (
      <section className="policyDetailSection policyAgentBlock wideAgent">
        {renderSwitchTitle("Product update", dp.update_channel !== "stable")}
        <p>Configure the frequency with which security agents and Security Servers download and install updates.</p>
        <h2>Scheduler</h2>
        <label className="policyInlineField"><span>Recurrence:</span><select value={dp.update_interval_hours === 1 ? "hourly" : "daily"} onChange={(e) => setModuleField("deployment_profile", "update_interval_hours", e.target.value === "hourly" ? 1 : 24)}><option value="hourly">Hourly</option><option value="daily">Daily</option></select></label>
        <label className="policyInlineField"><span>Check for updates every:</span><input type="number" value={dp.update_interval_hours ?? 1} onChange={(e) => setModuleField("deployment_profile", "update_interval_hours", parseInt(e.target.value) || 1)} /></label>
        <h2>Endpoint reboot scheduler</h2>
        <label className="policyCheckboxRow"><input type="checkbox" checked={dp.reboot_postpone !== false} onChange={(e) => setModuleField("deployment_profile", "reboot_postpone", e.target.checked)} /> Postpone reboot</label>
        <label className="policyInlineField"><span>Reboot time (if needed):</span><select value={dp.reboot_time ?? "daily"} onChange={(e) => setModuleField("deployment_profile", "reboot_time", e.target.value)}><option value="daily">Daily</option><option value="weekly">Weekly</option><option value="manual">Manual</option></select></label>
        {renderSwitchTitle("Security content update")}
        <p>Configure the frequency of security content updates, including scan engines, models, and threat components.</p>
        <h2>Update locations</h2>
        <div className="policyUpdateLocation"><input placeholder="Add location" /><label><input type="checkbox" /> Use proxy</label><button type="button" onClick={() => {
          const locations = [...(dp.update_locations ?? [])];
          locations.push({ server: "", use_proxy: false });
          setModuleField("deployment_profile", "update_locations", locations);
        }}>+</button></div>
        <div className="policyAssignmentTable updateTable">
          <div><span>Priority</span><span>Server</span><span>Proxy</span><span>Actions</span></div>
          {(dp.update_locations ?? []).length === 0 ? (
            <>
              <div><span>1</span><span>Aetherix Relay Pool</span><span><input type="checkbox" /></span><span>Edit</span></div>
              <div><span>2</span><span>https://updates.aetherix.local</span><span><input type="checkbox" /></span><span>Edit</span></div>
            </>
          ) : (dp.update_locations ?? []).map((loc: Record<string, unknown>, i: number) => (
            <div key={i}><span>{i + 1}</span><span>{String(loc.server ?? "")}</span><span><input type="checkbox" checked={!!loc.use_proxy} readOnly /></span><span>Edit</span></div>
          ))}
        </div>
        <label className="policyCheckboxRow"><input type="checkbox" checked={dp.managed_update_fallback !== false} onChange={(e) => setModuleField("deployment_profile", "managed_update_fallback", e.target.checked)} /> Use Aetherix managed update service as fallback</label>
        <h2>Update ring</h2>
        <label className="policyInlineField"><span>Select update ring:</span><select value={dp.deployment_ring ?? "stable"} onChange={(e) => setModuleField("deployment_profile", "deployment_ring", e.target.value)}><option value="slow">Slow ring</option><option value="fast">Fast ring</option><option value="stable">Stable</option></select></label>
      </section>
    );
  }

  function renderAgentTelemetry() {
    const dp = (draft.modules.deployment_profile ?? {}) as unknown as DeploymentProfileData;
    return (
      <section className="policyDetailSection policyAgentBlock">
        {renderSwitchTitle("Security Telemetry", dp.telemetry_enabled)}
        <p>Export security event raw data from protected endpoints to SIEM solutions for advanced analysis and correlation.</p>
        <label className="policySwitchRow" onClick={() => setModuleField("deployment_profile", "telemetry_enabled", !dp.telemetry_enabled)}>
          <span className={`policySwitch ${dp.telemetry_enabled ? "on" : ""}`} aria-hidden="true" />
          Enable Security Telemetry
        </label>
        {dp.telemetry_enabled ? (
          <>
            <h2>SIEM connection settings</h2>
            <label className="policyInlineField"><span>SIEM solution:</span><select defaultValue="splunk"><option value="splunk">Splunk (HTTP)</option></select></label>
            <label className="policyInlineField"><span>Server URL:</span><input placeholder="Server URL" value={dp.siem_url ?? ""} onChange={(e) => setModuleField("deployment_profile", "siem_url", e.target.value)} /></label>
            <label className="policyInlineField"><span>Token:</span><input type="password" value={dp.siem_token ?? ""} onChange={(e) => setModuleField("deployment_profile", "siem_token", e.target.value)} /></label>
            <h2>Communication between endpoints and SIEMs</h2>
            <label className="policyRadioRow" onClick={() => setModuleField("deployment_profile", "use_proxy_for_siem", true)}>
              <input type="radio" name="siemProxy" checked={dp.use_proxy_for_siem === true} readOnly /> Use the proxy defined in Agent &gt; Settings
            </label>
            <label className="policyRadioRow" onClick={() => setModuleField("deployment_profile", "use_proxy_for_siem", false)}>
              <input type="radio" name="siemProxy" checked={dp.use_proxy_for_siem !== true} readOnly /> Do not use a proxy
            </label>
          </>
        ) : null}
      </section>
    );
  }

  function renderRelayCommunication() {
    const dp = (draft.modules.deployment_profile ?? {}) as unknown as DeploymentProfileData;
    return (
      <section className="policyDetailSection policyAgentBlock wideAgent">
        <h1>Relay</h1>
        <p>Define communication settings for endpoints that use an Aetherix relay profile.</p>
        <h2>Communication</h2>
        <label className="policyCheckboxRow">
          <input type="checkbox" checked={dp.relay_auto_discovery === true} onChange={(e) => setModuleField("deployment_profile", "relay_auto_discovery", e.target.checked)} />
          Automatic discovery of new endpoints
        </label>
        <p>When enabled, relays periodically discover endpoints in approved network ranges and report them to the Aetherix control plane.</p>
        <h2>Allowed upload domains for relay tasks</h2>
        <p>Specify domains that relay-managed tasks may use when uploading Live Search and evidence results.</p>
        <div className="policyUpdateLocation relayDomains">
          <input placeholder="Domain" aria-label="Allowed relay upload domain" id="relay-domain-input" />
          <button type="button" aria-label="Add allowed relay upload domain" onClick={() => {
            const input = document.getElementById("relay-domain-input") as HTMLInputElement;
            if (input?.value?.trim()) {
              const domains = [...(dp.allowed_upload_domains ?? [])];
              domains.push(input.value.trim());
              setModuleField("deployment_profile", "allowed_upload_domains", domains);
              input.value = "";
            }
          }}>+</button>
        </div>
        <div className="policyAssignmentTable updateTable">
          <div><span>Priority</span><span>Domain</span><span>Status</span><span>Actions</span></div>
          {(dp.allowed_upload_domains ?? []).length === 0 ? <p>Add item</p> :
            (dp.allowed_upload_domains ?? []).map((domain: string, i: number) => (
              <div key={i}><span>{i + 1}</span><span>{domain}</span><span>Active</span><span>Edit</span></div>
            ))}
        </div>
      </section>
    );
  }

  function renderRelayUpdate() {
    const dp = (draft.modules.deployment_profile ?? {}) as unknown as DeploymentProfileData;
    return (
      <section className="policyDetailSection policyAgentBlock wideAgent">
        <h1>Update</h1>
        <p>Define update settings for endpoints that use an Aetherix relay profile.</p>
        <label className="policyInlineField"><span><input type="checkbox" checked={dp.managed_update_fallback !== false} onChange={(e) => setModuleField("deployment_profile", "managed_update_fallback", e.target.checked)} /> Check for updates every (hours):</span><input type="number" value={dp.update_interval_hours ?? 1} onChange={(e) => setModuleField("deployment_profile", "update_interval_hours", parseInt(e.target.value) || 1)} /></label>
        <h2>Update locations</h2>
        <div className="policyUpdateLocation">
          <input placeholder="Add location" id="relay-update-location" />
          <label><input type="checkbox" /> Use proxy</label>
          <button type="button" onClick={() => {
            const input = document.getElementById("relay-update-location") as HTMLInputElement;
            if (input?.value?.trim()) {
              const locations = [...(dp.update_locations ?? [])];
              locations.push({ server: input.value.trim(), use_proxy: false });
              setModuleField("deployment_profile", "update_locations", locations);
              input.value = "";
            }
          }}>+</button>
        </div>
        <div className="policyAssignmentTable updateTable">
          <div><span>Priority</span><span>Server</span><span>Proxy</span><span>Actions</span></div>
          {(dp.update_locations ?? []).length === 0 ? (
            <div><span>1</span><span>https://relay-updates.aetherix.local:443</span><span><input type="checkbox" /></span><span>Edit</span></div>
          ) : (dp.update_locations ?? []).map((loc: Record<string, unknown>, i: number) => (
            <div key={i}><span>{i + 1}</span><span>{String(loc.server ?? "")}</span><span><input type="checkbox" checked={!!loc.use_proxy} readOnly /></span><span>Edit</span></div>
          ))}
        </div>
      </section>
    );
  }

  function renderScanProfileCards(selected: string, onChange: (value: string) => void) {
    return (
      <div className="policyScanProfiles" role="radiogroup" aria-label="Scan options">
        {[
          ["aggressive", "Aggressive", "Advanced security, moderate use of resources", "Scan every accessed file, including local and network drives, archives, low-risk files, email, and web traffic."],
          ["normal", "Normal", "Standard security, low use of resources", "Scan malware-prone file types and accessed applications from local drives and network drives."],
          ["permissive", "Permissive", "Basic security, very low use of resources", "Scan accessed application files from local and network drives while excluding low-risk file categories."],
          ["custom", "Custom", "Administrator-defined settings", "Configure scan settings to match your tenant baseline."],
        ].map(([value, label, summary, description]) => (
          <button key={value} type="button" className={selected === value ? "selected" : ""} onClick={() => onChange(value)} role="radio" aria-checked={selected === value}>
            <span className="policyRadioDot" />
            <strong>{label}</strong>
            <b>{summary}</b>
            <small>{description}</small>
          </button>
        ))}
      </div>
    );
  }

  function renderAntimalwareOnAccess() {
    const action = String(draft.modules.antimalware?.response_action ?? "review");
    return (
      <section className="policyDetailSection policyAgentBlock wideAgent">
        {renderSwitchTitle("On-Access Scanning", antimalwareEnabled)}
        <p>Scan files, process memory, boot sectors, and potentially unwanted applications when endpoints access them.</p>
        <h2>Scan options</h2>
        {renderScanProfileCards(action === "block" ? "aggressive" : action === "allow" ? "permissive" : "normal", (value) => setModuleField("antimalware", "response_action", value === "aggressive" ? "block" : value === "permissive" ? "allow" : "review"))}
        <h2>File location</h2>
        <label className="policyCheckboxRow"><input type="checkbox" checked={antimalwareEnabled} onChange={(event) => setModuleField("antimalware", "enabled", event.target.checked)} /> Scan local files</label>
        <label className="policyInlineField"><span>File types:</span><select defaultValue="all"><option value="all">All files</option><option value="executables">Executables and scripts</option></select></label>
        <label className="policyCheckboxRow"><input type="checkbox" defaultChecked /> Scan network files</label>
        <label className="policyInlineField"><span>Maximum size:</span><input type="number" defaultValue="20" /></label>
        <h2>Scan</h2>
        <label className="policyCheckboxRow"><input type="checkbox" defaultChecked /> New or changed files only</label>
        <label className="policyCheckboxRow"><input type="checkbox" defaultChecked /> Boot sectors</label>
        <label className="policyCheckboxRow"><input type="checkbox" /> Process memory</label>
        <label className="policyCheckboxRow"><input type="checkbox" defaultChecked /> Keylogger behavior</label>
        <label className="policyCheckboxRow"><input type="checkbox" defaultChecked /> Potentially unwanted applications</label>
        <h2>Scan actions</h2>
        <label className="policyInlineField"><span>Action for infected objects:</span><select value={action} onChange={(event) => setModuleField("antimalware", "response_action", event.target.value)}><option value="block">Remediate</option><option value="review">Report only</option><option value="allow">Allow</option></select></label>
      </section>
    );
  }

  function renderAntimalwareOnExecute() {
    const behaviorAction = String(draft.modules.behavior_monitoring?.high_confidence_action ?? "isolate");
    const exploitAction = String(draft.modules.anti_exploit?.high_confidence_action ?? "block");
    return (
      <section className="policyDetailSection policyAgentBlock wideAgent">
        <h1>On-Execute Scanning</h1>
        <p>Analyze files and applications as they launch, preventing malicious code from executing.</p>
        {renderSwitchTitle("Cloud-assisted Threat Detection", behaviorEnabled)}
        <p>Aetherix uses tenant policy, local behavior signals, and optional AI analysis to identify advanced threats with lower local overhead.</p>
        {renderSwitchTitle("Advanced Threat Control", behaviorEnabled)}
        <label className="policyInlineField"><span>Action for infected applications:</span><select value={behaviorAction} onChange={(event) => setModuleField("behavior_monitoring", "high_confidence_action", event.target.value)}><option value="review">Report only</option><option value="isolate">Isolate endpoint</option></select></label>
        {renderScanProfileCards(behaviorAction === "isolate" ? "normal" : "permissive", (value) => setModuleField("behavior_monitoring", "high_confidence_action", value === "permissive" ? "review" : "isolate"))}
        <label className="policyCheckboxRow"><input type="checkbox" checked={antiExploitEnabled} onChange={(event) => setModuleField("anti_exploit", "enabled", event.target.checked)} /> Sensitive registry protection</label>
        <label className="policyCheckboxRow"><input type="checkbox" defaultChecked /> Kernel API monitoring</label>
        {renderSwitchTitle("Fileless Attack Protection", antiExploitEnabled)}
        <label className="policyCheckboxRow"><input type="checkbox" checked={antiExploitEnabled} onChange={(event) => setModuleField("anti_exploit", "enabled", event.target.checked)} /> Command-line scanner</label>
        <label className="policyInlineField"><span>Exploit response:</span><select value={exploitAction} onChange={(event) => setModuleField("anti_exploit", "high_confidence_action", event.target.value)}><option value="review">Report only</option><option value="block">Block execution</option></select></label>
        {renderSwitchTitle("Ransomware Mitigation", ransomwareEnabled)}
        <label className="policyCheckboxRow"><input type="checkbox" checked={ransomwareEnabled} onChange={(event) => setModuleField("ransomware_mitigation", "enabled", event.target.checked)} /> Recover encrypted file changes after confirmed ransomware behavior</label>
        <label className="policyInlineField"><span>Recovery approval:</span><select value={String(draft.modules.ransomware_mitigation?.rollback_approval ?? "operator_required")} onChange={(event) => setModuleField("ransomware_mitigation", "rollback_approval", event.target.value)}><option value="operator_required">Operator approval</option><option value="automatic">Automatic</option></select></label>
      </section>
    );
  }

  function renderAntimalwareOnDemand() {
    return (
      <section className="policyDetailSection policyAgentBlock wideAgent">
        <h1>On-Demand Scanning</h1>
        <p>Inspect endpoints for threats through scheduled scan tasks and operator-triggered response workflows.</p>
        <h2>Scan tasks</h2>
        <div className="policyV2Actions"><button className="btnGhost" type="button">Add</button><button className="policyDangerButton" type="button">Delete</button></div>
        <div className="policyAssignmentTable updateTable"><div><span>Task name</span><span>Scan type</span><span>Repeat interval</span><span>First run</span></div><p>No tasks</p></div>
        <h2>Scan settings</h2>
        <label className="policyInlineField"><span>Contextual scan:</span><select defaultValue="custom"><option value="custom">Custom</option><option value="normal">Normal</option></select></label>
        <label className="policyInlineField"><span>External device scan:</span><select defaultValue="normal"><option value="normal">Normal</option><option value="aggressive">Aggressive</option></select></label>
        {renderSwitchTitle("Device scanning", true)}
        <p>Automatically detect and scan external storage devices when connected to endpoints.</p>
        <label className="policyCheckboxRow"><input type="checkbox" defaultChecked /> CD/DVD media</label>
        <label className="policyCheckboxRow"><input type="checkbox" defaultChecked /> USB storage devices</label>
      </section>
    );
  }

  function renderAntimalwareIntegrity() {
    return (
      <section className="policyDetailSection policyAgentBlock wideAgent">
        {renderSwitchTitle("Anti-Tampering", antiExploitEnabled)}
        <p>Detect attempts to disable the Aetherix agent, alter protected drivers, or weaken endpoint security controls.</p>
        <h2>Pre-tampering</h2>
        <label className="policyCheckboxRow"><input type="checkbox" checked={antiExploitEnabled} onChange={(event) => setModuleField("anti_exploit", "enabled", event.target.checked)} /> Vulnerable drivers</label>
        <label className="policyRadioRow"><input type="radio" name="driverAction" defaultChecked /> Deny access</label>
        <label className="policyRadioRow"><input type="radio" name="driverAction" /> Disconnect endpoint</label>
        <label className="policyRadioRow"><input type="radio" name="driverAction" /> Report only</label>
        <h2>Post-tampering</h2>
        <label className="policyCheckboxRow"><input type="checkbox" checked={behaviorEnabled} onChange={(event) => setModuleField("behavior_monitoring", "enabled", event.target.checked)} /> Callback evasion</label>
        <label className="policyCheckboxRow"><input type="checkbox" /> Isolate endpoint</label>
        <label className="policyCheckboxRow"><input type="checkbox" /> Reboot endpoint</label>
      </section>
    );
  }

  function renderAntimalwareHyperDetect() {
    const behaviorAction = String(draft.modules.behavior_monitoring?.high_confidence_action ?? "isolate");
    return (
      <section className="policyDetailSection policyAgentBlock wideAgent">
        {renderSwitchTitle("Hyper Detect", behaviorEnabled)}
        <p>Identify advanced attacks and suspicious activity before execution by combining local behavior signals with Aetherix policy intelligence.</p>
        <h2>Protection level</h2>
        <div className="policyMatrixTable hyperDetectTable">
          <div><span>Category</span><span>Aggressive</span><span>Normal</span><span>Permissive</span></div>
          {["All", "Targeted attack", "Suspicious files and network traffic", "Exploits", "Ransomware", "Grayware"].map((row) => (
            <div key={row}>
              <label><input type="checkbox" defaultChecked /> {row}</label>
              <label><input type="radio" name={`${row}-level`} checked={behaviorAction === "isolate"} onChange={() => setModuleField("behavior_monitoring", "high_confidence_action", "isolate")} /> Aggressive</label>
              <label><input type="radio" name={`${row}-level`} checked={behaviorAction !== "review"} onChange={() => setModuleField("behavior_monitoring", "high_confidence_action", "isolate")} /> Normal</label>
              <label><input type="radio" name={`${row}-level`} checked={behaviorAction === "review"} onChange={() => setModuleField("behavior_monitoring", "high_confidence_action", "review")} /> Permissive</label>
            </div>
          ))}
        </div>
        <h2>Actions</h2>
        <p>Actions apply to detections up to and including the selected protection level. Higher-confidence detections can still be reported for analyst review.</p>
        <label className="policyInlineField"><span>Files:</span><select value={behaviorAction} onChange={(event) => setModuleField("behavior_monitoring", "high_confidence_action", event.target.value)}><option value="review">Report only</option><option value="isolate">Isolate endpoint</option></select></label>
        <label className="policyCheckboxRow"><input type="checkbox" /> Extend reporting on higher levels</label>
      </section>
    );
  }

  function renderAntimalwareAdvancedExploit() {
    const exploitAction = String(draft.modules.anti_exploit?.high_confidence_action ?? "block");
    return (
      <section className="policyDetailSection policyAgentBlock wideAgent">
        {renderSwitchTitle("Advanced Anti-Exploit", antiExploitEnabled)}
        <p>Protect against exploit techniques in browsers, productivity apps, document readers, and kernel-level activity after an exploit has started.</p>
        <h2>System-wide detections</h2>
        <div className="policyMatrixTable exploitTable">
          <div><span>Windows detections</span><span>Report only</span><span>Block only</span><span>Block and report</span><span>Kill process</span></div>
          {["All", "Process introspection", "Privilege escalation", "LSASS protection"].map((row) => (
            <div key={row}>
              <label><input type="checkbox" defaultChecked /> {row}</label>
              <label><input type="radio" name={`${row}-exploit`} checked={exploitAction === "review"} onChange={() => setModuleField("anti_exploit", "high_confidence_action", "review")} /> Report only</label>
              <label><input type="radio" name={`${row}-exploit`} checked={exploitAction === "block"} onChange={() => setModuleField("anti_exploit", "high_confidence_action", "block")} /> Block only</label>
              <label><input type="radio" name={`${row}-exploit`} /> Block and report</label>
              <label><input type="radio" name={`${row}-exploit`} /> Kill process</label>
            </div>
          ))}
        </div>
        <h2>Predefined protected applications</h2>
        <div className="policyAssignmentTable appProtectionTable">
          <div><span>Application</span><span>Process name</span><span>Status</span><span>Policy source</span></div>
          <div><span>Archive tools</span><span>7z.exe</span><span>Default</span><span>Aetherix baseline</span></div>
          <div><span>Document readers</span><span>reader.exe</span><span>Default</span><span>Aetherix baseline</span></div>
          <div><span>Office productivity</span><span>office.exe</span><span>Default</span><span>Aetherix baseline</span></div>
        </div>
      </section>
    );
  }

  function renderAntimalwareSecurityServers() {
    return (
      <section className="policyDetailSection policyAgentBlock wideAgent">
        <h1>Security Servers</h1>
        <p>Assign Aetherix scan nodes to endpoints and set their priority for offloading resource-intensive scanning tasks.</p>
        <h2>Scan node assignment</h2>
        <div className="policyCommunicationBuilder">
          <input type="number" defaultValue="1" aria-label="Scan node priority" />
          <select aria-label="Scan node"><option>Aetherix Scan Node</option></select>
          <input placeholder="IP" aria-label="Scan node IP" />
          <input placeholder="Custom node name/IP" aria-label="Custom scan node name/IP" />
          <button type="button" aria-label="Add scan node">+</button>
        </div>
        <div className="policyAssignmentTable"><div><span>Priority</span><span>Scan node</span><span>IP</span><span>Actions</span></div><p>Add item</p></div>
        <h2>Load balancing</h2>
        <label className="policyRadioRow"><input type="radio" name="scanNodeBalance" defaultChecked /> Redundancy mode</label>
        <label className="policyRadioRow"><input type="radio" name="scanNodeBalance" /> Equal distribution mode</label>
        <h2>Communication between scan nodes and endpoints</h2>
        <label className="policyCheckboxRow"><input type="checkbox" /> Use an encrypted connection</label>
        <h2>Scan node configuration</h2>
        <label className="policyInlineField"><span>Concurrent on-demand scan limit:</span><select defaultValue="low"><option value="low">Low</option><option value="medium">Medium</option><option value="high">High</option></select></label>
      </section>
    );
  }

  function renderAntimalwareSettings() {
    return (
      <section className="policyDetailSection policyAgentBlock">
        <h1>Settings</h1>
        <p>Configure additional antimalware options for this policy.</p>
        <h2>Quarantine</h2>
        <label className="policyInlineField"><span>Delete files older than (days):</span><input type="number" defaultValue="30" /></label>
        <label className="policyCheckboxRow"><input type="checkbox" defaultChecked /> Submit quarantined files to Aetherix Labs every (hours)</label>
        <label className="policyInlineField"><span>Submission interval:</span><input type="number" defaultValue="1" /></label>
        <label className="policyCheckboxRow"><input type="checkbox" defaultChecked /> Rescan quarantine after security content updates</label>
        <label className="policyCheckboxRow"><input type="checkbox" defaultChecked /> Copy files to quarantine before remediation</label>
        <label className="policyCheckboxRow"><input type="checkbox" defaultChecked /> Allow users to take actions on local quarantine</label>
      </section>
    );
  }

  function renderAntimalwareExclusions() {
    return (
      <section className="policyDetailSection policyAgentBlock">
        <h1>Exclusions</h1>
        <p>Create policy-specific exclusions, attach approved configuration profiles, or use Aetherix recommended exclusions.</p>
        <label className="policySwitchRow"><span className="policySwitch" /> In-policy exclusions</label>
        <p>Create and configure exclusions specific to this policy.</p>
        <label className="policySwitchRow"><span className="policySwitch" /> Exclusions from configuration profiles</label>
        <p>Assign approved exclusion lists from configuration profiles to this policy.</p>
        <label className="policySwitchRow"><span className="policySwitch on" /> Aetherix recommended exclusions</label>
        <p>Apply recommended exclusions maintained by Aetherix. Select custom entries when you need a narrower tenant-specific baseline.</p>
        <label className="policyRadioRow"><input type="radio" name="recommendedExclusions" defaultChecked /> All recommended exclusions</label>
        <label className="policyRadioRow"><input type="radio" name="recommendedExclusions" /> Custom</label>
        <div className="policyUpdateLocation relayDomains"><select aria-label="Recommended exclusion"><option>Select product or workload</option><option>Developer workstation baseline</option><option>Server workload baseline</option></select><button type="button" aria-label="Add recommended exclusion">+</button></div>
      </section>
    );
  }

  function renderSandboxAnalyzerEndpoint() {
    const analysisMode = String(draft.modules.sandbox_analyzer?.analysis_mode ?? "monitoring");
    const defaultAction = String(draft.modules.sandbox_analyzer?.default_action ?? "report");
    return (
      <section className="policyDetailSection policyAgentBlock wideAgent">
        <h1>Sandbox Analyzer</h1>
        <p>Analyze suspicious objects with Aetherix detonation and behavior scoring before allowing them to spread across managed endpoints.</p>
        <h2>Connection settings</h2>
        <label className="policyCheckboxRow"><input type="checkbox" checked={sandboxEnabled} onChange={(event) => setModuleField("sandbox_analyzer", "enabled", event.target.checked)} /> Use Aetherix Detonation Cloud</label>
        <p>The endpoint sensor submits suspicious samples to the Aetherix detonation service according to this policy and tenant entitlement.</p>
        <label className="policyCheckboxRow"><input type="checkbox" /> Use proxy configuration</label>
        <p>Connect the endpoint sensor and detonation service through the proxy defined in Agent settings.</p>
        {renderSwitchTitle("Automatic sample submission from managed endpoints", sandboxEnabled)}
        <p>Enable the endpoint sensor to submit suspicious objects for in-depth behavioral analysis.</p>
        <h2>Analysis mode</h2>
        <label className="policyRadioRow"><input type="radio" name="sandboxMode" checked={analysisMode === "monitoring"} onChange={() => setModuleField("sandbox_analyzer", "analysis_mode", "monitoring")} /> Monitoring</label>
        <p>Endpoint users can access objects during analysis while detections are reported to Aetherix.</p>
        <label className="policyRadioRow"><input type="radio" name="sandboxMode" checked={analysisMode === "blocking"} onChange={() => setModuleField("sandbox_analyzer", "analysis_mode", "blocking")} /> Blocking</label>
        <p>Endpoint users can access objects only after analysis confirms they are clean.</p>
        <h2>Remediation actions</h2>
        <label className="policyInlineField"><span>Default action:</span><select value={defaultAction} onChange={(event) => setModuleField("sandbox_analyzer", "default_action", event.target.value)}><option value="report">Report only</option><option value="isolate">Isolate endpoint</option><option value="block">Block object</option></select></label>
        <div className="policyInfoCallout">Submission targets and exclusions follow Antimalware On-Access settings and Aetherix recommended exclusions.</div>
        <h2>Content prefiltering</h2>
        <p>This module scans suspicious files, command-line arguments, and URLs, then submits objects for detonation based on the configured risk threshold.</p>
      </section>
    );
  }

  function renderFirewallGeneral() {
    const logLevel = String(draft.modules.firewall?.log_level ?? "low");
    const networkAction = String(draft.modules.network_protection?.network_attack_signature_action ?? "review");
    return (
      <section className="policyDetailSection policyAgentBlock wideAgent">
        {renderSwitchTitle("Firewall", firewallEnabled)}
        <p>Protect endpoints from unauthorized inbound and outbound connection attempts using Aetherix network-control policy.</p>
        <label className="policyCheckboxRow"><input type="checkbox" checked={firewallEnabled} onChange={(event) => setModuleField("firewall", "enabled", event.target.checked)} /> Enable endpoint firewall controls</label>
        <label className="policyCheckboxRow"><input type="checkbox" /> Allow local connection sharing on trusted networks</label>
        <label className="policyCheckboxRow"><input type="checkbox" /> Monitor Wi-Fi network changes</label>
        <label className="policyInlineField"><span>Log verbosity level:</span><select value={logLevel} onChange={(event) => setModuleField("firewall", "log_level", event.target.value)}><option value="low">Low</option><option value="normal">Normal</option><option value="high">High</option></select></label>
        <label className="policyCheckboxRow"><input type="checkbox" checked={networkProtectionEnabled} onChange={(event) => setModuleField("network_protection", "enabled", event.target.checked)} /> Block port scans</label>
        <h2>Network intrusion detection</h2>
        {renderSwitchTitle("Intrusion Detection System", networkProtectionEnabled)}
        <p>Detect suspicious network behavior and hostile connection attempts using Aetherix network protection signals.</p>
        {renderScanProfileCards(networkAction === "block" ? "aggressive" : networkAction === "allow" ? "permissive" : "normal", (value) => setModuleField("network_protection", "network_attack_signature_action", value === "aggressive" ? "block" : value === "permissive" ? "allow" : "review"))}
      </section>
    );
  }

  function renderFirewallSettings() {
    return (
      <section className="policyDetailSection policyAgentBlock wideAgent">
        <h1>Settings</h1>
        <p>Define Aetherix firewall network profiles based on trust levels, networks, and adapters.</p>
        <h2>Networks</h2>
        <div className="policyCommunicationBuilder firewallNetworkBuilder">
          <input placeholder="Name" aria-label="Firewall network name" />
          <select aria-label="Firewall network profile"><option>Home/Office</option><option>Public</option><option>Trusted</option></select>
          <select aria-label="Firewall network identification"><option>IP</option><option>MAC</option><option>SSID</option></select>
          <input placeholder="IP or MAC" aria-label="Firewall network identifier" />
          <button type="button" aria-label="Add firewall network">+</button>
        </div>
        <div className="policyAssignmentTable firewallTable"><div><span>Network name</span><span>Network profile</span><span>Identification</span><span>Actions</span></div><p>Add item</p></div>
        <h2>Adapters</h2>
        <p>For undefined networks, firewall settings vary based on the adapter type and selected discovery behavior.</p>
        <div className="policyAssignmentTable firewallAdapterTable">
          <div><span>Adapter type</span><span>Network profile</span><span>Network discovery</span><span>Actions</span></div>
          <div><span>Wired</span><span>Home/Office</span><span>Yes</span><span>Edit</span></div>
          <div><span>Wireless</span><span>Public</span><span>Yes</span><span>Edit</span></div>
          <div><span>Virtual</span><span>Trusted</span><span>Yes</span><span>Edit</span></div>
        </div>
      </section>
    );
  }

  function renderFirewallRules() {
    const profile = String(draft.modules.firewall?.profile ?? "known_allow");
    return (
      <section className="policyDetailSection policyAgentBlock wideAgent">
        <h1>Rules</h1>
        <p>Configure Aetherix network access and data traffic rules for applications and connection types.</p>
        <h2>Settings</h2>
        <label className="policyInlineField"><span>Protection level:</span><select value={profile} onChange={(event) => setModuleField("firewall", "profile", event.target.value)}><option value="ruleset_allow">Ruleset and allow</option><option value="ruleset_ask">Ruleset and ask</option><option value="ruleset_deny">Ruleset and deny</option><option value="known_allow">Ruleset, known files and allow</option><option value="known_ask">Ruleset, known files and ask</option><option value="known_deny">Ruleset, known files and deny</option></select></label>
        <div className="policyInfoCallout">Ask-based firewall profiles require endpoint notification pop-ups. Use allow or deny profiles when silent endpoint operation is required.</div>
        <label className="policyCheckboxRow"><input type="checkbox" /> Create aggressive rules</label>
        <label className="policyCheckboxRow"><input type="checkbox" defaultChecked /> Create rules for applications blocked by network intrusion detection</label>
        <label className="policyCheckboxRow"><input type="checkbox" defaultChecked /> Monitor process changes</label>
        <h2>Rules</h2>
        <div className="policyV2Actions"><button className="btnGhost" type="button">Add</button><button className="btnGhost" type="button">Export</button><button className="btnGhost" type="button">Import</button><button className="policyDangerButton" type="button">Delete</button></div>
        <div className="policyAssignmentTable firewallRulesTable">
          <div><span>Priority</span><span>Rule name</span><span>Status</span><span>Rule type</span><span>Network</span><span>Protocol</span><span>Permission</span></div>
          <div><span>1</span><span>Incoming ICMP</span><span>Enabled</span><span>Application</span><span>Office, Public</span><span>ICMP</span><span>Allow</span></div>
          <div><span>2</span><span>Remote administration</span><span>Enabled</span><span>Connection</span><span>Office</span><span>TCP</span><span>Allow</span></div>
          <div><span>3</span><span>Web browsing HTTP</span><span>Enabled</span><span>Application</span><span>Office, Public</span><span>TCP</span><span>Allow</span></div>
        </div>
      </section>
    );
  }

  function renderNetworkProtectionGeneral() {
    const encryptedTraffic = draft.modules.network_protection?.encrypted_traffic_interception === true;
    const tlsHandshake = draft.modules.network_protection?.tls_handshake_interception !== false;
    return (
      <section className="policyDetailSection policyAgentBlock wideAgent networkProtectionBlock">
        {renderSwitchTitle("Network Protection", networkProtectionEnabled)}
        <p>Configure Aetherix content filtering, data protection, web access, traffic scanning, antiphishing, and network attack detection from one policy area.</p>
        <h2>General settings</h2>
        <label className="policyCheckboxRow"><input type="checkbox" checked={encryptedTraffic} onChange={(event) => setModuleField("network_protection", "encrypted_traffic_interception", event.target.checked)} /> Intercept encrypted traffic</label>
        <div className="policyIndentedOptions">
          <label className="policyCheckboxRow"><input type="checkbox" disabled={!encryptedTraffic} /> Scan HTTPS <span>Windows, macOS</span></label>
          <label className="policyCheckboxRow"><input type="checkbox" disabled={!encryptedTraffic} /> Additional browser processes</label>
          <label className="policyCheckboxRow"><input type="checkbox" disabled={!encryptedTraffic} /> Scan FTPS <span>Linux</span></label>
          <label className="policyCheckboxRow"><input type="checkbox" disabled={!encryptedTraffic} /> Scan SCP/SSH <span>Linux</span></label>
          <label className="policyCheckboxRow"><input type="checkbox" disabled={!encryptedTraffic} /> Scan IMAPS <span>Windows</span></label>
          <label className="policyCheckboxRow"><input type="checkbox" disabled={!encryptedTraffic} /> Scan MAPI <span>Windows</span></label>
          <p>MAPI scanning is available for Microsoft 365-compatible tenant domains. Verify compatibility before enabling.</p>
          <label className="policyCheckboxRow"><input type="checkbox" disabled={!encryptedTraffic} /> Scan POP3S <span>Windows</span></label>
          <label className="policyCheckboxRow"><input type="checkbox" disabled={!encryptedTraffic} /> Scan SMTPS <span>Windows</span></label>
          <label className="policyCheckboxRow"><input type="checkbox" disabled={!encryptedTraffic} /> Exclude finance domains <span>Windows, macOS</span></label>
        </div>
        <div className="policyWarningCallout">Encrypted mail scanning can affect compatibility with some mail clients. Validate protocol coverage before enabling IMAPS, MAPI, POP3S, or SMTPS scanning.</div>
        <label className="policyCheckboxRow"><input type="checkbox" checked={tlsHandshake} onChange={(event) => setModuleField("network_protection", "tls_handshake_interception", event.target.checked)} /> Intercept TLS handshake</label>
        <div className="policyIndentedOptions">
          <label className="policyRadioRow"><input type="radio" name="tlsHandshakeAction" defaultChecked /> Respond with an Aetherix access denied page <span>Windows</span></label>
          <label className="policyRadioRow"><input type="radio" name="tlsHandshakeAction" /> Reset connection <span>Windows</span></label>
        </div>
        {renderSwitchTitle("Exclusions", false)}
        <p>Configure exclusions to skip specific traffic types during scanning.</p>
      </section>
    );
  }

  function renderNetworkProtectionContent() {
    const dlpEnabled = draft.modules.semantic_dlp?.enabled === true;
    return (
      <section className="policyDetailSection policyAgentBlock wideAgent networkProtectionBlock">
        {renderSwitchTitle("Web Access Control", contentControlEnabled)}
        <p>Manage internet access by user, application, and schedule while keeping the rules tied to Aetherix web protection.</p>
        <label className="policyInlineField"><span>Scheduler:</span><select aria-label="Assign scheduler"><option>Assign scheduler</option><option>Business hours</option><option>Always active</option></select></label>
        {renderSwitchTitle("Application Blacklisting", contentControlEnabled)}
        <p>Block or restrict access to applications that should not initiate internet sessions from protected endpoints.</p>
        <label className="policyCheckboxRow"><input type="checkbox" checked={contentControlEnabled} onChange={(event) => setModuleField("web_protection", "content_control_enabled", event.target.checked)} /> Enable Aetherix content control</label>
        {renderSwitchTitle("Data Protection", dlpEnabled)}
        <p>Prevent unauthorized disclosure of sensitive data using the existing Semantic DLP classifiers and upload actions.</p>
        <label className="policyInlineField"><span>Sensitive upload action:</span><select value={String(draft.modules.web_protection?.sensitive_upload_action ?? "block")} onChange={(event) => setModuleField("web_protection", "sensitive_upload_action", event.target.value)}><option value="allow">Allow</option><option value="review">Review</option><option value="block">Block</option></select></label>
        <button className="btnGhost" type="button" onClick={() => openPolicyModules(["web_protection", "semantic_dlp", "genai_guardrails"])}>Open Aetherix DLP modules</button>
      </section>
    );
  }

  function renderNetworkProtectionWeb() {
    const antiphishingAction = String(draft.modules.web_protection?.antiphishing_action ?? "block");
    const infectedWebsiteAction = String(draft.modules.web_protection?.infected_website_action ?? "block");
    const emailScanEnabled = draft.modules.web_protection?.email_scan_enabled === true;
    return (
      <section className="policyDetailSection policyAgentBlock wideAgent networkProtectionBlock">
        {renderSwitchTitle("Antiphishing", webProtectionEnabled)}
        <p>Block known phishing webpages and suspicious web destinations before users disclose private or confidential information.</p>
        <label className="policyInlineField"><span>Default action for suspicious webpages:</span><select value={antiphishingAction} onChange={(event) => setModuleField("web_protection", "antiphishing_action", event.target.value)}><option value="allow">Allow</option><option value="review">Review</option><option value="block">Block</option></select></label>
        <label className="policyCheckboxRow"><input type="checkbox" defaultChecked /> Protection against fraud</label>
        <label className="policyCheckboxRow"><input type="checkbox" defaultChecked /> Protection against phishing</label>
        {renderSwitchTitle("Web Traffic Scan", webProtectionEnabled)}
        <p>Analyze inbound HTTP traffic in real time and prevent malicious payloads from being downloaded.</p>
        <label className="policyInlineField"><span>Default action for infected websites:</span><select value={infectedWebsiteAction} onChange={(event) => setModuleField("web_protection", "infected_website_action", event.target.value)}><option value="allow">Allow</option><option value="review">Review</option><option value="block">Block</option></select></label>
        {renderSwitchTitle("Email Traffic Scan", emailScanEnabled)}
        <p>Inspect incoming and outgoing mail protocols where encrypted traffic interception is enabled.</p>
        <label className="policyCheckboxRow"><input type="checkbox" checked={emailScanEnabled} onChange={(event) => setModuleField("web_protection", "email_scan_enabled", event.target.checked)} /> Enable email traffic scanning</label>
        <label className="policyCheckboxRow"><input type="checkbox" disabled={!emailScanEnabled} /> Incoming emails (POP3)</label>
        <label className="policyCheckboxRow"><input type="checkbox" disabled={!emailScanEnabled} /> Incoming emails (IMAP)</label>
        <label className="policyCheckboxRow"><input type="checkbox" disabled={!emailScanEnabled} /> Outgoing emails (SMTP)</label>
        <label className="policyCheckboxRow"><input type="checkbox" disabled /> Incoming and outgoing (MAPI)</label>
        <div className="policyWarningCallout">To enable MAPI mail inspection, first activate encrypted MAPI interception in Network Protection General.</div>
      </section>
    );
  }

  function renderNetworkProtectionAttacks() {
    const networkAction = String(draft.modules.network_protection?.network_attack_signature_action ?? "review");
    const attackTechniques = ["All", "Initial Access", "Credential Access", "Discovery", "Lateral Movement", "Crimeware"];
    return (
      <section className="policyDetailSection policyAgentBlock wideAgent networkProtectionBlock">
        {renderSwitchTitle("Network Attack Defense", networkProtectionEnabled)}
        <p>Detect attack techniques used to gain unauthorized access to endpoints and decide whether to report or block them.</p>
        {renderSwitchTitle("Server traffic scan", false)}
        <p>Monitor incoming traffic on protected servers for potential threats.</p>
        <label className="policyCheckboxRow"><input type="checkbox" disabled /> Inspect encrypted domain controller traffic</label>
        {renderSwitchTitle("Inspect RDP traffic", false)}
        <div className="policyWarningCallout">To enable this option, first activate encrypted traffic interception in Network Protection General.</div>
        <h2>Attack techniques</h2>
        <p>Select the techniques you want to report or block based on your organization security requirements.</p>
        <div className="policyMatrixTable networkAttackTable">
          <div><span>Technique</span><span>Report only</span><span>Block</span></div>
          {attackTechniques.map((technique) => (
            <div key={technique}>
              <label><input type="checkbox" defaultChecked /> {technique}</label>
              <label><input type="radio" name={`attack-${technique}`} checked={networkAction !== "block"} onChange={() => setModuleField("network_protection", "network_attack_signature_action", "review")} /> Report only</label>
              <label><input type="radio" name={`attack-${technique}`} checked={networkAction === "block"} onChange={() => setModuleField("network_protection", "network_attack_signature_action", "block")} /> Block</label>
            </div>
          ))}
        </div>
        <button className="btnLink" type="button" onClick={() => setModuleField("network_protection", "network_attack_signature_action", "review")}>Reset to default</button>
      </section>
    );
  }

  function renderNetworkProtectionCustomPages() {
    return (
      <section className="policyDetailSection policyAgentBlock wideAgent networkProtectionBlock">
        {renderSwitchTitle("Custom Pages", customPagesEnabled)}
        <p>Enable Aetherix custom pages and assign the block or warning page users see when web protection or content control restricts a destination.</p>
        <label className="policyCheckboxRow"><input type="checkbox" checked={customPagesEnabled} onChange={(event) => setModuleField("web_protection", "custom_pages_enabled", event.target.checked)} /> Enable custom response pages</label>
        <label className="policyInlineField"><span>Custom page:</span><select aria-label="Assign custom page" disabled={!customPagesEnabled}><option>Assign custom page</option><option>Aetherix access denied</option><option>Compliance warning</option></select></label>
      </section>
    );
  }

  function renderPatchManagement() {
    const maintenanceWindow = String(draft.modules.patch_management?.maintenance_window ?? "none");
    return (
      <section className="policyDetailSection policyAgentBlock wideAgent">
        <h1>Patch Management</h1>
        <p>Provides automatic patch assessment and installation through dedicated Aetherix maintenance windows.</p>
        <label className="policyCheckboxRow"><input type="checkbox" checked={patchManagementEnabled} onChange={(event) => setModuleField("patch_management", "enabled", event.target.checked)} /> Enable automatic patch assessment and installation</label>
        <h2>Maintenance windows</h2>
        <label className="policyInlineField"><span>Maintenance window:</span><select value={maintenanceWindow} onChange={(event) => setModuleField("patch_management", "maintenance_window", event.target.value)}><option value="none">No maintenance window selected</option><option value="business_hours">Business hours</option><option value="after_hours">After hours</option><option value="weekend">Weekend</option></select></label>
        <p>Select a maintenance window for this policy. Maintenance windows are defined in Policies &gt; Configuration Profiles.</p>
        <button className="btnGhost" type="button" onClick={() => openPolicyModules(["patch_management"])}>Open Aetherix patch module</button>
      </section>
    );
  }

  function renderDeviceControl() {
    const rules = (draft.modules.device_control?.rules as any[]) || [];
    const exclusions = (draft.modules.device_control?.exclusions as any[]) || [];
    return (
      <DeviceControlSection
        enabled={deviceControlEnabled}
        rules={rules}
        exclusions={exclusions}
        canEdit={!isWorking}
        onUpdateEnabled={(enabled) => setModuleField("device_control", "enabled", enabled)}
        onUpdateRules={(updatedRules) => setModuleField("device_control", "rules", updatedRules)}
        onUpdateExclusions={(updatedExclusions) => setModuleField("device_control", "exclusions", updatedExclusions)}
        renderSwitchTitle={renderSwitchTitle}
      />
    );
  }

  function renderIntegrityMonitoring() {
    return (
      <section className="policyDetailSection policyAgentBlock wideAgent">
        {renderSwitchTitle("Integrity Monitoring", integrityMonitoringEnabled)}
        <p>Monitor critical files, registry keys, and service configurations for unexpected changes.</p>
        <label className="policyCheckboxRow"><input type="checkbox" checked={integrityMonitoringEnabled} onChange={(event) => setModuleField("integrity_monitoring", "enabled", event.target.checked)} /> Enable integrity monitoring</label>
        <label className="policyInlineField"><span>Monitoring mode:</span><select value={String(draft.modules.integrity_monitoring?.scan_mode ?? "monitor")} onChange={(event) => setModuleField("integrity_monitoring", "scan_mode", event.target.value)}><option value="monitor">Monitor only</option><option value="alert">Alert on changes</option><option value="isolate">Isolate on critical change</option></select></label>
        <div className="policyAssignmentTable updateTable"><div><span>Profile</span><span>Scope</span><span>Status</span></div><div><span>System baseline</span><span>Core OS paths</span><span>Enabled</span></div></div>
      </section>
    );
  }

  function renderExchangeProtection() {
    return (
      <section className="policyDetailSection policyAgentBlock wideAgent">
        <h1>General</h1>
        <p>Create and manage groups of email accounts, define quarantine retention, and configure email security filters.</p>
        <h2>User groups</h2>
        <p>Create user groups to apply customized scanning and filtering policies.</p>
        <div className="policyV2Actions"><button className="btnGhost" type="button">Add</button><button className="policyDangerButton" type="button">Delete</button></div>
        <div className="policyCommunicationBuilder"><select aria-label="Exchange group company"><option>Company</option></select><input aria-label="Exchange group name" placeholder="Group name" /></div>
        <div className="policyAssignmentTable updateTable"><div><span></span><span>Group name</span></div><p>No groups</p></div>
        <label className="policyInlineField"><span>Delete quarantined files older than (days):</span><input type="number" defaultValue="15" /></label>
        <label className="policySwitchRow"><span className="policySwitch" /> Connection blacklist</label>
        {renderSwitchTitle("Domain IP Check (Antispoofing)", exchangeProtectionEnabled)}
        <p>Use this filter to block spoofed emails by specifying trusted IP addresses for trusted domains.</p>
        <label className="policyCheckboxRow"><input type="checkbox" checked={exchangeProtectionEnabled} onChange={(event) => setModuleField("exchange_protection", "enabled", event.target.checked)} /> Enable Exchange protection</label>
      </section>
    );
  }

  function renderEncryption() {
    return (
      <section className="policyDetailSection policyAgentBlock wideAgent">
        {renderSwitchTitle("Encryption", encryptionEnabled)}
        <p>Require encryption for removable media and sensitive local storage workflows.</p>
        <label className="policyCheckboxRow"><input type="checkbox" checked={encryptionEnabled} onChange={(event) => setModuleField("encryption", "enabled", event.target.checked)} /> Enable encryption controls</label>
        <label className="policyInlineField"><span>Removable media action:</span><select value={String(draft.modules.encryption?.removable_media_action ?? "ask")} onChange={(event) => setModuleField("encryption", "removable_media_action", event.target.value)}><option value="allow">Allow</option><option value="ask">Ask user</option><option value="block">Block until encrypted</option></select></label>
      </section>
    );
  }

  function renderIncidentsSensor() {
    return (
      <section className="policyDetailSection policyAgentBlock wideAgent">
        {renderSwitchTitle("Incidents Sensor", incidentsSensorEnabled)}
        <p>Collect endpoint activity signals used by incident response, risk management, and PHASR analysis.</p>
        <label className="policyCheckboxRow"><input type="checkbox" checked={incidentsSensorEnabled} onChange={(event) => setModuleField("incidents_sensor", "enabled", event.target.checked)} /> Enable incidents sensor</label>
        <label className="policyInlineField"><span>Retain local telemetry for (days):</span><input type="number" value={Number(draft.modules.incidents_sensor?.retention_days ?? 30)} onChange={(event) => setModuleField("incidents_sensor", "retention_days", Number(event.target.value))} /></label>
      </section>
    );
  }

  function renderStorageProtection() {
    return (
      <section className="policyDetailSection policyAgentBlock wideAgent">
        {renderSwitchTitle("Storage Protection", storageProtectionEnabled)}
        <p>Protect local and network storage locations from suspicious write patterns and malicious file placement.</p>
        <label className="policyCheckboxRow"><input type="checkbox" checked={storageProtectionEnabled} onChange={(event) => setModuleField("storage_protection", "enabled", event.target.checked)} /> Enable storage protection</label>
        <label className="policyCheckboxRow"><input type="checkbox" checked={draft.modules.storage_protection?.scan_archives !== false} onChange={(event) => setModuleField("storage_protection", "scan_archives", event.target.checked)} /> Scan archives written to protected storage</label>
      </section>
    );
  }

  function renderRiskManagementGeneral() {
    return (
      <section className="policyDetailSection policyAgentBlock wideAgent">
        {renderSwitchTitle("Risk Management", riskManagementEnabled)}
        <p>Enables recurrent risk scanning on target endpoints. This means you can schedule scanning for security risks, such as automatic updates or user access control settings.</p>
        <h2>Scheduler</h2>
        <label className="policyInlineField"><span>Start date and time:</span><input type="date" defaultValue="2026-05-23" /><input type="number" defaultValue="17" /><input type="number" defaultValue="11" /></label>
        <label className="policyRadioRow"><input type="radio" name="riskRecurrence" defaultChecked /> Schedule task to run once every:</label>
        <label className="policyInlineField"><span>Repeat every:</span><input type="number" value={Number(draft.modules.risk_management?.recurrence_days ?? 1)} onChange={(event) => setModuleField("risk_management", "recurrence_days", Number(event.target.value))} /><select defaultValue="days"><option value="days">days</option><option value="weeks">weeks</option></select></label>
        <label className="policyRadioRow"><input type="radio" name="riskRecurrence" /> Run task every:</label>
        <div className="policyV2Actions"><button type="button" className="btnGhost">Sun</button><button type="button" className="btnGhost">Mon</button><button type="button" className="btnGhost">Tue</button><button type="button" className="btnGhost">Wed</button><button type="button" className="btnGhost">Thu</button><button type="button" className="btnGhost">Fri</button><button type="button" className="btnGhost">Sat</button></div>
        <label className="policyCheckboxRow"><input type="checkbox" checked={draft.modules.risk_management?.missed_runtime_action !== false} onChange={(event) => setModuleField("risk_management", "missed_runtime_action", event.target.checked)} /> If scheduled run time is missed, run task as soon as possible</label>
      </section>
    );
  }

  function renderRiskManagementPhasr() {
    const phasrAction = (key: string) => String(draft.modules.phasr?.[key] ?? "off");
    return (
      <section className="policyDetailSection policyAgentBlock wideAgent">
        {renderSwitchTitle("PHASR", phasrEnabled)}
        <p>When enabled, PHASR continuously monitors endpoints and analyzes user behavior patterns to identify potential attack vectors.</p>
        <p>PHASR relies on historical data collected by EDR through the Incidents Sensor. If the Incidents Sensor is disabled, PHASR will not function as expected.</p>
        <div className="policyWarningCallout">PHASR settings applied through assignment rules override device policies. Check your configurations to prevent unintended overrides.</div>
        <h2>Configure PHASR monitoring for the following activity types:</h2>
        {[["living_off_land_action", "Living off the land binaries"], ["remote_admin_action", "Remote admin tools"], ["tampering_action", "Tampering tools"], ["piracy_action", "Piracy tools"], ["crypto_miner_action", "Crypto miners"]].map(([key, label]) => (
          <label key={key} className="policyInlineField"><span>{label}:</span><select value={phasrAction(key)} onChange={(event) => setModuleField("phasr", key, event.target.value)}><option value="off">Off</option><option value="monitor">Monitor</option><option value="block">Block</option></select><span><input type="checkbox" /> Allow users to request access</span></label>
        ))}
        <div className="policyWarningCallout">Switching between monitoring modes will remove PHASR restrictions currently applied to behavioral profiles.</div>
      </section>
    );
  }

  function renderBlocklist() {
    return (
      <section className="policyDetailSection policyAgentBlock wideAgent">
        {renderSwitchTitle("Blocklist", blocklistEnabled)}
        <p>Customize blocklist settings to prevent specific files, applications, or network connections from running or accessing your system.</p>
        <label className="policyCheckboxRow"><input type="checkbox" checked={draft.modules.blocklist?.application_hash === true} onChange={(event) => setModuleField("blocklist", "application_hash", event.target.checked)} /> Application hash</label>
        <label className="policyCheckboxRow"><input type="checkbox" checked={draft.modules.blocklist?.dll_files === true} onChange={(event) => setModuleField("blocklist", "dll_files", event.target.checked)} /> DLL files</label>
        <label className="policyCheckboxRow"><input type="checkbox" checked={draft.modules.blocklist?.script_files === true} onChange={(event) => setModuleField("blocklist", "script_files", event.target.checked)} /> Script files</label>
        <p>Enabling script file blocking can disrupt applications that rely on script execution.</p>
        <label className="policyCheckboxRow"><input type="checkbox" checked={draft.modules.blocklist?.application_path === true} onChange={(event) => setModuleField("blocklist", "application_path", event.target.checked)} /> Application path</label>
        <p>Block applications from specified file paths.</p>
        <label className="policyCheckboxRow"><input type="checkbox" checked={draft.modules.blocklist?.network_connection === true} onChange={(event) => setModuleField("blocklist", "network_connection", event.target.checked)} /> Network connection</label>
        <p>Block connections to or from specific IPs, ports, or MAC addresses.</p>
      </section>
    );
  }

  function renderLiveSearch() {
    return (
      <section className="policyDetailSection policyAgentBlock wideAgent">
        {renderSwitchTitle("Live Search", liveSearchEnabled)}
        <p>Enables Live Search capabilities on target endpoints.</p>
        <p>With Live Search, you can retrieve information about events and system statistics directly from online endpoints using OSQuery, an SQL-compatible query system.</p>
        <label className="policyCheckboxRow"><input type="checkbox" checked={liveSearchEnabled} onChange={(event) => setModuleField("live_search", "enabled", event.target.checked)} /> Enable Live Search on endpoints</label>
      </section>
    );
  }

  function renderModuleEditorControls() {
    return (
      <section className="policyDetailSection policyEngineBlock" aria-label="Policy engine modules">
        <div className="policyEngineHeader">
          <div>
            <h2>Policy engine modules</h2>
            <p>Configure the Aetherix runtime modules, entitlement locks, simulations, promotions, and assignments for this policy.</p>
          </div>
          <div className="policyV2Actions">
            <button className="btnGhost" type="button" disabled={!selectedPolicyId || isWorking} onClick={() => void simulateSelectedPolicy()}>
              <FlaskConical size={14} /> Simulate selected
            </button>
            <button className="btnGhost" type="button" disabled={!selectedPolicyId || !simulation || isWorking} onClick={openPromotionGate}>
              <Check size={14} /> Promote selected
            </button>
            <button className="btnGhost" type="button" disabled={!selectedPolicyId || isWorking} onClick={() => setAssignmentOpen(true)}>
              <Link size={14} /> Assign selected
            </button>
          </div>
        </div>

        <div className="policyEditorGrid compact">
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

        <div className="policyAccordionList dark">
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
                    {locked ? <em className="lockBadge" style={{ background: "rgba(220, 20, 20, 0.1)", color: "var(--danger)", fontSize: "11px", fontWeight: "bold", padding: "1px 6px", borderRadius: "4px", textTransform: "uppercase" }}>Locked</em> : null}
                    {open ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
                  </span>
                </button>
                {open ? (
                  <div className="policyModuleBody">
                    {locked ? (
                      <div className="policyModuleLockedCallout" style={{ padding: "16px", background: "rgba(220, 38, 38, 0.05)", borderLeft: "4px solid var(--danger)", borderRadius: "6px", marginBottom: "16px" }}>
                        <div className="lockCalloutHeader" style={{ display: "flex", alignItems: "center", gap: "8px", color: "var(--danger)", fontWeight: 700, fontSize: "14px", marginBottom: "6px" }}>
                          <ShieldAlert size={18} />
                          <span>Module Locked: {reason}</span>
                        </div>
                        <p className="lockCalloutBody" style={{ fontSize: "13px", color: "var(--text-muted)", margin: "0 0 12px 0", lineHeight: "1.4" }}>
                          Continuous simulation, compliance logging, and automated threat mitigations are disabled for {module.title} on this tenant scope.
                        </p>
                        <div className="lockCalloutActions">
                          <button type="button" className="btnPurchaseUpgrade" onClick={() => alert(`Redirecting to upgrade page for ${module.addon || 'premium'} subscription add-on...`)} style={{ background: "var(--danger)", color: "white", border: "none", borderRadius: "6px", padding: "6px 12px", fontSize: "12px", fontWeight: "bold", cursor: "pointer", display: "inline-flex", alignItems: "center", gap: "4px" }}>
                            Upgrade Plan <ArrowUpRight size={14} />
                          </button>
                        </div>
                      </div>
                    ) : null}
                    
                    <div className="policyModuleFields" style={{ opacity: locked ? 0.5 : 1, pointerEvents: locked ? "none" : "auto" }}>
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

        <div className="policySimulationInline" style={{ marginTop: "24px", padding: "24px", background: "var(--bg-card)", borderRadius: "8px", border: "1px solid var(--line)" }}>
          <h3 style={{ fontSize: "16px", fontWeight: 700, margin: "0 0 16px 0", color: "var(--text-primary)", display: "flex", alignItems: "center", gap: "8px" }}>
            <FlaskConical size={18} style={{ color: "var(--primary)" }} />
            Simulation Center & Impact Analysis
          </h3>
          {!simulation ? (
            <p style={{ color: "var(--text-muted)", fontSize: "13px" }}>No active simulation has been run for this draft policy. Run a simulation to verify threat coverage and evaluate approval gates.</p>
          ) : (
            <div>
              {/* Risk Delta and Affected Endpoints Headers */}
              <div className="simGrid" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px", marginBottom: "20px" }}>
                <div className="simCard" style={{ padding: "12px", background: "rgba(16, 185, 129, 0.05)", border: "1px solid rgba(16, 185, 129, 0.15)", borderRadius: "6px" }}>
                  <span style={{ fontSize: "11px", color: "var(--text-muted)", textTransform: "uppercase", fontWeight: "bold" }}>Security Posture Impact</span>
                  <div style={{ display: "flex", alignItems: "baseline", gap: "8px", marginTop: "4px" }}>
                    <span style={{ fontSize: "22px", fontWeight: "bold", color: "var(--primary)" }}>-48% Risk Delta</span>
                    <span style={{ fontSize: "11px", color: "var(--primary)", fontWeight: "bold" }}>▼ Improved</span>
                  </div>
                  <p style={{ fontSize: "12px", color: "var(--text-muted)", margin: "4px 0 0 0" }}>Expected risk exposure reduction based on activated detection & isolation engines.</p>
                </div>
                <div className="simCard" style={{ padding: "12px", background: "var(--line)", borderRadius: "6px" }}>
                  <span style={{ fontSize: "11px", color: "var(--text-muted)", textTransform: "uppercase", fontWeight: "bold" }}>Target Surface Size</span>
                  <div style={{ display: "flex", alignItems: "baseline", gap: "8px", marginTop: "4px" }}>
                    <span style={{ fontSize: "22px", fontWeight: "bold", color: "var(--text-primary)" }}>14 Endpoints</span>
                    <span style={{ fontSize: "11px", color: "var(--text-muted)" }}>queued</span>
                  </div>
                  <p style={{ fontSize: "12px", color: "var(--text-muted)", margin: "4px 0 0 0" }}>Active devices currently assigned inside this company tenant hierarchy.</p>
                </div>
              </div>

              {/* Summary Stats */}
              <div className="policySimulationSummary" style={{ display: "flex", gap: "12px", flexWrap: "wrap", padding: "12px", background: "var(--line)", borderRadius: "6px", marginBottom: "16px", fontSize: "12px" }}>
                <span style={{ marginRight: "12px" }}><strong>Total Modules:</strong> {simulation.summary.modules_total}</span>
                <span style={{ marginRight: "12px", color: "var(--primary)" }}><strong>Enabled:</strong> {simulation.summary.modules_enabled}</span>
                <span style={{ marginRight: "12px", color: "var(--danger)" }}><strong>Block Actions:</strong> {simulation.summary.would_block}</span>
                <span style={{ marginRight: "12px", color: "var(--danger)" }}><strong>Network Isolations:</strong> {simulation.summary.would_isolate}</span>
                <span><strong>Rollbacks:</strong> {simulation.summary.would_rollback}</span>
              </div>

              {/* Destructive Action Alert / Gate state */}
              {destructiveCount > 0 ? (
                <div className="destructiveAlertBox" style={{ padding: "16px", background: "rgba(220, 38, 38, 0.05)", borderLeft: "4px solid var(--danger)", borderRadius: "6px", marginBottom: "16px" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "8px", color: "var(--danger)", fontWeight: 700, fontSize: "13px", marginBottom: "6px" }}>
                    <AlertTriangle size={16} />
                    <span>PROMOTION GATE ACTIVE</span>
                  </div>
                  <p style={{ fontSize: "12px", color: "var(--text-muted)", margin: "0 0 10px 0", lineHeight: "1.4" }}>
                    This policy configuration implements destructive threat defense protocols. Promoting this version requires manual operator sign-off and simulation logging evidence.
                  </p>
                  
                  {/* Scannable modules display */}
                  <div className="destructiveModulesList" style={{ background: "white", padding: "10px", borderRadius: "4px", border: "1px solid var(--line)" }}>
                    {simulation.outcomes.filter(o => o.destructive_actions && o.destructive_actions.length > 0).map(o => (
                      <div key={o.module} style={{ display: "flex", justifyContent: "space-between", fontSize: "12px", padding: "4px 0", borderBottom: "1px solid #f1f5f9" }}>
                        <span style={{ fontWeight: 600, color: "var(--text-primary)" }}>{o.module}</span>
                        <span style={{ color: "var(--danger)" }}>{o.destructive_actions.join(", ")}</span>
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <p className="policyGateHint" style={{ fontSize: "12px", color: "var(--primary)", padding: "12px", background: "rgba(16, 185, 129, 0.05)", borderRadius: "6px" }}>
                  ✓ Standard Configuration: No destructive actions or blocking commands are enabled. Policy can be promoted to active state instantly.
                </p>
              )}
            </div>
          )}
        </div>
      </section>
    );
  }

  // OLD DETAIL VIEW (being phased out for creation)
  // "Add Policy" now uses the dedicated PolicyEditorPage route for a clean experience.
  // This block is temporarily kept only for editing *existing* policies during the transition.
  if (viewMode === "detail" && detailMode === "existing") {
    return (
      <>
      <div className="policyDetailPage">
        <aside className="policyDetailSidebar" aria-label="Policy settings navigation">
          <div className="policyDetailSearch">
            <input placeholder="Search (min. 3 characters)" aria-label="Search policy settings" />
          </div>
          <nav>
            <section>
              <h2>
                <button
                  className="policySidebarGroupToggle"
                  type="button"
                  aria-expanded={expandedSections.general}
                  onClick={() => setExpandedSections((current) => ({ ...current, general: !current.general }))}
                >
                  <span>General</span>
                  {expandedSections.general ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                </button>
              </h2>
              {expandedSections.general ? (
                <>
                  <button className={policySection === "details" ? "active" : ""} type="button" onClick={() => setPolicySection("details")}>Policy</button>
                  <button className={policySection === "inheritance" ? "active" : ""} type="button" onClick={() => setPolicySection("inheritance")}>Inheritance rules</button>
                  
                  <div className={["agentNotifications", "agentSettings", "agentCommunication", "agentUpdate", "agentTelemetry"].includes(policySection) ? "policySidebarParent active" : "policySidebarParent"}>
                <button
                  className={["agentNotifications", "agentSettings", "agentCommunication", "agentUpdate", "agentTelemetry"].includes(policySection) ? "active" : ""}
                  type="button"
                  onClick={() => {
                    setPolicySection("agentNotifications");
                    setExpandedSections(prev => ({ ...prev, agent: true }));
                  }}
                >
                  Agent <span>2/3</span>
                </button>
                <button
                  aria-label="Toggle Agent Section"
                  className="policySidebarToggle"
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    setExpandedSections(prev => ({ ...prev, agent: !prev.agent }));
                  }}
                >
                  {expandedSections.agent ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                </button>
              </div>
              {expandedSections.agent && (
                <div className="policySidebarChildren">
                  <button className={policySection === "agentNotifications" ? "active" : ""} type="button" onClick={() => setPolicySection("agentNotifications")}>Notifications <span>On</span></button>
                  <button aria-label="Agent Settings" className={policySection === "agentSettings" ? "active" : ""} type="button" onClick={() => setPolicySection("agentSettings")}>Settings</button>
                  <button aria-label="Agent Communication" className={policySection === "agentCommunication" ? "active" : ""} type="button" onClick={() => setPolicySection("agentCommunication")}>Communication</button>
                  <button aria-label="Agent Update" className={policySection === "agentUpdate" ? "active" : ""} type="button" onClick={() => setPolicySection("agentUpdate")}>Update <span>On</span></button>
                  <button className={policySection === "agentTelemetry" ? "active" : ""} type="button" onClick={() => setPolicySection("agentTelemetry")}>Security Telemetry <span>Off</span></button>
                </div>
              )}

              <div className={["relayCommunication", "relayUpdate"].includes(policySection) ? "policySidebarParent active" : "policySidebarParent"}>
                <button
                  className={["relayCommunication", "relayUpdate"].includes(policySection) ? "active" : ""}
                  type="button"
                  onClick={() => {
                    setPolicySection("relayCommunication");
                    setExpandedSections(prev => ({ ...prev, relay: true }));
                  }}
                >
                  Relay
                </button>
                <button
                  aria-label="Toggle Relay Section"
                  className="policySidebarToggle"
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    setExpandedSections(prev => ({ ...prev, relay: !prev.relay }));
                  }}
                >
                  {expandedSections.relay ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                </button>
              </div>
              {expandedSections.relay && (
                <div className="policySidebarChildren">
                  <button aria-label="Relay Communication" className={policySection === "relayCommunication" ? "active" : ""} type="button" onClick={() => setPolicySection("relayCommunication")}>Communication</button>
                  <button aria-label="Relay Update" className={policySection === "relayUpdate" ? "active" : ""} type="button" onClick={() => setPolicySection("relayUpdate")}>Update</button>
                </div>
              )}

              <button className={policySection === "modules" ? "active" : ""} type="button" onClick={() => setPolicySection("modules")}>Aetherix modules</button>
                </>
              ) : null}
            </section>
            <section>
              <h2>
                <button
                  className="policySidebarGroupToggle"
                  type="button"
                  aria-expanded={expandedSections.protection}
                  onClick={() => setExpandedSections((current) => ({ ...current, protection: !current.protection }))}
                >
                  <span>Protection & Monitoring</span>
                  {expandedSections.protection ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                </button>
              </h2>
              {expandedSections.protection ? (
                <>
                  <div className={policySection.startsWith("antimalware") ? "policySidebarParent active" : "policySidebarParent"}>
                <button
                  className={policySection.startsWith("antimalware") ? "active" : ""}
                  type="button"
                  onClick={() => {
                    setPolicySection("antimalwareOnAccess");
                    setExpandedSections(prev => ({ ...prev, antimalware: true }));
                  }}
                >
                  Antimalware <span>4/6</span>
                </button>
                <button
                  aria-label="Toggle Antimalware Section"
                  className="policySidebarToggle"
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    setExpandedSections(prev => ({ ...prev, antimalware: !prev.antimalware }));
                  }}
                >
                  {expandedSections.antimalware ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                </button>
              </div>
              {expandedSections.antimalware && (
                <div className="policySidebarChildren">
                  <button aria-label="Antimalware On-Access" className={policySection === "antimalwareOnAccess" ? "active" : ""} type="button" onClick={() => setPolicySection("antimalwareOnAccess")}>On-Access <span>{antimalwareEnabled ? "On" : "Off"}</span></button>
                  <button aria-label="Antimalware On-Execute" className={policySection === "antimalwareOnExecute" ? "active" : ""} type="button" onClick={() => setPolicySection("antimalwareOnExecute")}>On-Execute <span>3/4</span></button>
                  <button aria-label="Antimalware On-Demand" className={policySection === "antimalwareOnDemand" ? "active" : ""} type="button" onClick={() => setPolicySection("antimalwareOnDemand")}>On-Demand <span>Off</span></button>
                  <button aria-label="Antimalware Anti-Tampering" className={policySection === "antimalwareIntegrity" ? "active" : ""} type="button" onClick={() => setPolicySection("antimalwareIntegrity")}>Anti-Tampering <span>{antiExploitEnabled ? "On" : "Off"}</span></button>
                  <button aria-label="Antimalware Hyper Detect" className={policySection === "antimalwareHyperDetect" ? "active" : ""} type="button" onClick={() => setPolicySection("antimalwareHyperDetect")}>Hyper Detect <span>{behaviorEnabled ? "On" : "Off"}</span></button>
                  <button aria-label="Antimalware Advanced Anti-Exploit" className={policySection === "antimalwareAdvancedExploit" ? "active" : ""} type="button" onClick={() => setPolicySection("antimalwareAdvancedExploit")}>Advanced Anti-Exploit <span>{antiExploitEnabled ? "On" : "Off"}</span></button>
                  <button aria-label="Antimalware Security Servers" className={policySection === "antimalwareSecurityServers" ? "active" : ""} type="button" onClick={() => setPolicySection("antimalwareSecurityServers")}>Security Servers</button>
                  <button aria-label="Antimalware Settings" className={policySection === "antimalwareSettings" ? "active" : ""} type="button" onClick={() => setPolicySection("antimalwareSettings")}>Settings</button>
                  <button aria-label="Antimalware Exclusions" className={policySection === "antimalwareExclusions" ? "active" : ""} type="button" onClick={() => setPolicySection("antimalwareExclusions")}>Exclusions</button>
                </div>
              )}

              <div className={policySection === "sandboxAnalyzerEndpoint" ? "policySidebarParent active" : "policySidebarParent"}>
                <button
                  className={policySection === "sandboxAnalyzerEndpoint" ? "active" : ""}
                  type="button"
                  onClick={() => {
                    setPolicySection("sandboxAnalyzerEndpoint");
                    setExpandedSections(prev => ({ ...prev, sandbox: true }));
                  }}
                >
                  Sandbox Analyzer <span>{sandboxEnabled ? "On" : "Off"}</span>
                </button>
                <button
                  aria-label="Toggle Sandbox Section"
                  className="policySidebarToggle"
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    setExpandedSections(prev => ({ ...prev, sandbox: !prev.sandbox }));
                  }}
                >
                  {expandedSections.sandbox ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                </button>
              </div>
              {expandedSections.sandbox && (
                <div className="policySidebarChildren">
                  <button aria-label="Sandbox Endpoint Sensor" className={policySection === "sandboxAnalyzerEndpoint" ? "active" : ""} type="button" onClick={() => setPolicySection("sandboxAnalyzerEndpoint")}>Endpoint Sensor <span>{sandboxEnabled ? "On" : "Off"}</span></button>
                </div>
              )}

              <div className={policySection.startsWith("firewall") ? "policySidebarParent active" : "policySidebarParent"}>
                <button
                  className={policySection.startsWith("firewall") ? "active" : ""}
                  type="button"
                  onClick={() => {
                    setPolicySection("firewallGeneral");
                    setExpandedSections(prev => ({ ...prev, firewall: true }));
                  }}
                >
                  Firewall <span>{firewallEnabled ? "On" : "Off"}</span>
                </button>
                <button
                  aria-label="Toggle Firewall Section"
                  className="policySidebarToggle"
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    setExpandedSections(prev => ({ ...prev, firewall: !prev.firewall }));
                  }}
                >
                  {expandedSections.firewall ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                </button>
              </div>
              {expandedSections.firewall && (
                <div className="policySidebarChildren">
                  <button aria-label="Firewall General" className={policySection === "firewallGeneral" ? "active" : ""} type="button" onClick={() => setPolicySection("firewallGeneral")}>General <span>1/2</span></button>
                  <button aria-label="Firewall Settings" className={policySection === "firewallSettings" ? "active" : ""} type="button" onClick={() => setPolicySection("firewallSettings")}>Settings</button>
                  <button aria-label="Firewall Rules" className={policySection === "firewallRules" ? "active" : ""} type="button" onClick={() => setPolicySection("firewallRules")}>Rules</button>
                </div>
              )}

              <div className={policySection.startsWith("networkProtection") ? "policySidebarParent active" : "policySidebarParent"}>
                <button
                  className={policySection.startsWith("networkProtection") ? "active" : ""}
                  type="button"
                  onClick={() => {
                    setPolicySection("networkProtectionGeneral");
                    setExpandedSections(prev => ({ ...prev, network: true }));
                  }}
                >
                  Network Protection <span>{networkProtectionEnabled ? "2/5" : "Off"}</span>
                </button>
                <button
                  aria-label="Toggle Network Section"
                  className="policySidebarToggle"
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    setExpandedSections(prev => ({ ...prev, network: !prev.network }));
                  }}
                >
                  {expandedSections.network ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                </button>
              </div>
              {expandedSections.network && (
                <div className="policySidebarChildren">
                  <button aria-label="Network Protection General" className={policySection === "networkProtectionGeneral" ? "active" : ""} type="button" onClick={() => setPolicySection("networkProtectionGeneral")}>General <span>{networkProtectionEnabled ? "On" : "Off"}</span></button>
                  <button aria-label="Network Protection Content Control" className={policySection === "networkProtectionContent" ? "active" : ""} type="button" onClick={() => setPolicySection("networkProtectionContent")}>Content Control <span>{contentControlEnabled ? "On" : "Off"}</span></button>
                  <button aria-label="Network Protection Web Protection" className={policySection === "networkProtectionWeb" ? "active" : ""} type="button" onClick={() => setPolicySection("networkProtectionWeb")}>Web Protection <span>{webProtectionEnabled ? "2/3" : "Off"}</span></button>
                  <button aria-label="Network Protection Network Attacks" className={policySection === "networkProtectionAttacks" ? "active" : ""} type="button" onClick={() => setPolicySection("networkProtectionAttacks")}>Network Attacks <span>{networkProtectionEnabled ? "On" : "Off"}</span></button>
                  <button aria-label="Network Protection Custom Pages" className={policySection === "networkProtectionCustomPages" ? "active" : ""} type="button" onClick={() => setPolicySection("networkProtectionCustomPages")}>Custom Pages <span>{customPagesEnabled ? "On" : "Off"}</span></button>
                </div>
              )}

              <button className={policySection === "patchManagement" ? "active" : ""} type="button" onClick={() => setPolicySection("patchManagement")}>Patch Management <span>{patchManagementEnabled ? "On" : "Off"}</span></button>
              <button className={policySection === "deviceControl" ? "active" : ""} type="button" onClick={() => setPolicySection("deviceControl")}>Device Control <span>{deviceControlEnabled ? "On" : "Off"}</span></button>
              <button className={policySection === "integrityMonitoring" ? "active" : ""} type="button" onClick={() => setPolicySection("integrityMonitoring")}>Integrity Monitoring <span>{integrityMonitoringEnabled ? "On" : "Off"}</span></button>
              <button className={policySection === "exchangeProtection" ? "active" : ""} type="button" onClick={() => setPolicySection("exchangeProtection")}>Exchange Protection <span>{exchangeProtectionEnabled ? "2/4" : "Off"}</span></button>
              <button className={policySection === "encryption" ? "active" : ""} type="button" onClick={() => setPolicySection("encryption")}>Encryption <span>{encryptionEnabled ? "On" : "Off"}</span></button>
              <button className={policySection === "incidentsSensor" ? "active" : ""} type="button" onClick={() => setPolicySection("incidentsSensor")}>Incidents Sensor <span>{incidentsSensorEnabled ? "On" : "Off"}</span></button>
              <button className={policySection === "storageProtection" ? "active" : ""} type="button" onClick={() => setPolicySection("storageProtection")}>Storage Protection <span>{storageProtectionEnabled ? "On" : "Off"}</span></button>
              <div className={policySection.startsWith("riskManagement") ? "policySidebarParent active" : "policySidebarParent"}>
                <button
                  className={policySection.startsWith("riskManagement") ? "active" : ""}
                  type="button"
                  onClick={() => {
                    setPolicySection("riskManagementGeneral");
                    setExpandedSections(prev => ({ ...prev, risk: true }));
                  }}
                >
                  Risk Management <span>{riskManagementEnabled ? "On" : "Off"}</span>
                </button>
                <button
                  aria-label="Toggle Risk Management Section"
                  className="policySidebarToggle"
                  type="button"
                  onClick={(event) => {
                    event.stopPropagation();
                    setExpandedSections(prev => ({ ...prev, risk: !prev.risk }));
                  }}
                >
                  {expandedSections.risk ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                </button>
              </div>
              {expandedSections.risk && (
                <div className="policySidebarChildren">
                  <button aria-label="Risk Management General" className={policySection === "riskManagementGeneral" ? "active" : ""} type="button" onClick={() => setPolicySection("riskManagementGeneral")}>General <span>{riskManagementEnabled ? "On" : "Off"}</span></button>
                  <button aria-label="Risk Management PHASR" className={policySection === "riskManagementPhasr" ? "active" : ""} type="button" onClick={() => setPolicySection("riskManagementPhasr")}>PHASR <span>{phasrEnabled ? "On" : "Off"}</span></button>
                </div>
              )}
              <button className={policySection === "blocklist" ? "active" : ""} type="button" onClick={() => setPolicySection("blocklist")}>Blocklist <span>{blocklistEnabled ? "On" : "Off"}</span></button>
              <button className={policySection === "liveSearch" ? "active" : ""} type="button" onClick={() => setPolicySection("liveSearch")}>Live Search <span>{liveSearchEnabled ? "On" : "Off"}</span></button>
              {POLICY_MODULE_GROUPS.map((group) => (
                <button
                  key={group.label}
                  type="button"
                  className={policySection === "modules" && group.modules.some((moduleKey) => openModules.has(moduleKey)) ? "active" : ""}
                  onClick={() => openPolicyModules(group.modules)}
                >
                  {group.label}<span>{group.meta}</span>
                </button>
              ))}
                </>
              ) : null}
            </section>
          </nav>
        </aside>

        <form className="policyDetailWorkspace" onSubmit={createDraft}>
          <header className="policyDetailHeader">
            <div className="policyDetailTitleGroup">
              <div className="policyDetailCrumbs">
                <button type="button" onClick={closeDetail}>Policies</button>
                <span>/</span>
                <strong>{detailTitle}</strong>
                <span>/</span>
                <span>{sectionParent(policySection)}</span>
                <span>/</span>
                <strong>{sectionTitle[policySection]}</strong>
              </div>
              <h1>{detailTitle}</h1>
              <p>{detailMode === "new" ? "Create a draft policy and configure its tenant scope, inheritance, and protection modules." : currentPolicyName}</p>
            </div>
            <a href="https://support.aetherix.local" target="_blank" rel="noreferrer">Get help from Support Center</a>
          </header>

          {error ? <ErrorBanner message={error} /> : null}
          {success ? <SuccessBanner message={success} /> : null}

          <main className={`policyDetailContent ${policySection !== "details" ? "wide" : ""}`}>
            {policySection === "details" ? (
              <>
                <section className="policyDetailSection">
                  <h1>Policy details</h1>
                  <label className="policyDetailField policyNameField">
                    <span>Name*:</span>
                    <input value={draft.name} onChange={(event) => setDraft((current) => ({ ...current, name: event.target.value }))} />
                  </label>
                  <label className="policyDetailToggle">
                    <input type="checkbox" />
                    Allow other users to change this policy
                  </label>
                </section>

                <section className="policyDetailSection policyHistoryBlock">
                  <h2>History</h2>
                  <dl>
                    <div>
                      <dt>Created by:</dt>
                      <dd>{selectedPolicy?.policy.created_by ?? "Georges Haddad"}</dd>
                    </div>
                    <div>
                      <dt>Created on:</dt>
                      <dd>{selectedPolicy ? formatDate(selectedPolicy.policy.created_at) : formatDate(new Date().toISOString())}</dd>
                    </div>
                    <div>
                      <dt>Modified on:</dt>
                      <dd>{selectedPolicy?.policy.updated_at ? formatDate(selectedPolicy.policy.updated_at) : "N/A"}</dd>
                    </div>
                  </dl>
                </section>

                <section className="policyDetailSection policySupportBlock">
                  <h2>Technical Support information</h2>
                  <p>The Technical Support information is displayed in the agent's About window.</p>
                  <label className="policyDetailField">
                    <span>Website*:</span>
                    <input defaultValue="https://www.aetherix.local" />
                  </label>
                  <label className="policyDetailField">
                    <span>Email*:</span>
                    <input defaultValue="https://support.aetherix.local" />
                  </label>
                  <label className="policyDetailField">
                    <span>Phone*:</span>
                    <input defaultValue="(+1) 954 414 9621" />
                  </label>
                </section>
              </>
            ) : null}

            {policySection === "inheritance" ? (
              <section className="policyDetailSection policyInheritanceBlock">
                <h1>Inheritance rules</h1>
                <p>Reuse settings from existing policies to build your policy. Select the module, section, and policy from the drop-down menus.</p>
                <strong>Add inheritance rules</strong>
                <div className="policyInheritanceActions">
                  <button type="button">Delete</button>
                </div>
                <div className="policyInheritanceBuilder">
                  <select aria-label="Inheritance module"><option>Module</option>{MODULES.map((module) => <option key={module.key}>{module.title}</option>)}</select>
                  <select aria-label="Inheritance section" disabled><option>This module has no sections</option></select>
                  <select aria-label="Inheritance policy"><option>Policy</option>{policies.map((policy) => <option key={policy.id}>{policy.name}</option>)}</select>
                  <button type="button" aria-label="Add inheritance rule">+</button>
                </div>
                <div className="policyInheritanceTable">
                  <div className="policyInheritanceHead">
                    <label><input type="checkbox" /> Module</label>
                    <span>Section</span>
                    <span>Inherit from</span>
                    <span>Actions</span>
                  </div>
                  <button type="button">Add item</button>
                </div>
              </section>
            ) : null}

            {policySection === "agentNotifications" ? renderAgentNotifications() : null}
            {policySection === "agentSettings" ? renderAgentSettings() : null}
            {policySection === "agentCommunication" ? renderAgentCommunication() : null}
            {policySection === "agentUpdate" ? renderAgentUpdate() : null}
            {policySection === "agentTelemetry" ? renderAgentTelemetry() : null}
            {policySection === "relayCommunication" ? renderRelayCommunication() : null}
            {policySection === "relayUpdate" ? renderRelayUpdate() : null}
            {policySection === "antimalwareOnAccess" ? renderAntimalwareOnAccess() : null}
            {policySection === "antimalwareOnExecute" ? renderAntimalwareOnExecute() : null}
            {policySection === "antimalwareOnDemand" ? renderAntimalwareOnDemand() : null}
            {policySection === "antimalwareIntegrity" ? renderAntimalwareIntegrity() : null}
            {policySection === "antimalwareHyperDetect" ? renderAntimalwareHyperDetect() : null}
            {policySection === "antimalwareAdvancedExploit" ? renderAntimalwareAdvancedExploit() : null}
            {policySection === "antimalwareSecurityServers" ? renderAntimalwareSecurityServers() : null}
            {policySection === "antimalwareSettings" ? renderAntimalwareSettings() : null}
            {policySection === "antimalwareExclusions" ? renderAntimalwareExclusions() : null}
            {policySection === "sandboxAnalyzerEndpoint" ? renderSandboxAnalyzerEndpoint() : null}
            {policySection === "firewallGeneral" ? renderFirewallGeneral() : null}
            {policySection === "firewallSettings" ? renderFirewallSettings() : null}
            {policySection === "firewallRules" ? renderFirewallRules() : null}
            {policySection === "networkProtectionGeneral" ? renderNetworkProtectionGeneral() : null}
            {policySection === "networkProtectionContent" ? renderNetworkProtectionContent() : null}
            {policySection === "networkProtectionWeb" ? renderNetworkProtectionWeb() : null}
            {policySection === "networkProtectionAttacks" ? renderNetworkProtectionAttacks() : null}
            {policySection === "networkProtectionCustomPages" ? renderNetworkProtectionCustomPages() : null}
            {policySection === "patchManagement" ? renderPatchManagement() : null}
            {policySection === "deviceControl" ? renderDeviceControl() : null}
            {policySection === "integrityMonitoring" ? renderIntegrityMonitoring() : null}
            {policySection === "exchangeProtection" ? renderExchangeProtection() : null}
            {policySection === "encryption" ? renderEncryption() : null}
            {policySection === "incidentsSensor" ? renderIncidentsSensor() : null}
            {policySection === "storageProtection" ? renderStorageProtection() : null}
            {policySection === "riskManagementGeneral" ? renderRiskManagementGeneral() : null}
            {policySection === "riskManagementPhasr" ? renderRiskManagementPhasr() : null}
            {policySection === "blocklist" ? renderBlocklist() : null}
            {policySection === "liveSearch" ? renderLiveSearch() : null}
            {policySection === "modules" ? renderModuleEditorControls() : null}
          </main>

          <footer className="policyDetailFooter">
            <button className="policySaveButton" type="submit" disabled={isWorking}>Save</button>
            <button className="policyCancelButton" type="button" onClick={closeDetail}>Cancel</button>
          </footer>
        </form>
      </div>
        <SideSheet
          open={assignmentOpen}
          onClose={() => setAssignmentOpen(false)}
          title="Assign policy"
          subtitle="Choose a target scope and preview effective inheritance"
        >
          <div className="policyAssignBody">
            {/* ...existing assignment sheet content... */}
            {/** Copied from builder branch, content unchanged **/}
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

            <div className="policyAssignPreview" style={{ marginTop: "24px", paddingTop: "16px", borderTop: "1px solid var(--line)" }}>
              <h3 style={{ fontSize: "14px", fontWeight: "bold", marginBottom: "12px", color: "var(--text-primary)" }}>Cascaded Inheritance Topology</h3>
              {!effectivePreview ? (
                <p className="muted" style={{ fontSize: "12px", color: "var(--text-muted)" }}>Select an assignment target above to render the graphical inheritance hierarchy cascade.</p>
              ) : (
                <>
                  <div className="inheritanceFlowGraph" style={{ background: "var(--line)", padding: "16px", borderRadius: "8px", marginBottom: "16px" }}>
                    <div className="flowLevelMSP" style={{ background: "white", padding: "10px", borderRadius: "6px", borderLeft: "4px solid var(--primary)", fontSize: "12px", boxShadow: "0 1px 2px var(--shadow)" }}>
                      <div style={{ display: "flex", justifyContent: "space-between", fontWeight: 600 }}>
                        <span>🌐 Level 1: Global Partner Template</span>
                        <span style={{ color: "var(--primary)" }}>Root baseline</span>
                      </div>
                      <p style={{ margin: "2px 0 0 0", fontSize: "11px", color: "var(--text-muted)" }}>Establishes default EDR, GenAI rulesets and security exclusions.</p>
                    </div>
                    <div className="flowConnector" style={{ height: "16px", width: "2px", background: "var(--text-muted)", margin: "0 auto", opacity: 0.3 }} />
                    <div className="flowLevelCustomer" style={{ background: "white", padding: "10px", borderRadius: "6px", borderLeft: "4px solid #6366f1", fontSize: "12px", boxShadow: "0 1px 2px var(--shadow)" }}>
                      <div style={{ display: "flex", justifyContent: "space-between", fontWeight: 600 }}>
                        <span>🏢 Level 2: Customer / Tenant Level</span>
                        <span style={{ color: "#6366f1" }}>Tenant overrides</span>
                      </div>
                      <p style={{ margin: "2px 0 0 0", fontSize: "11px", color: "var(--text-muted)" }}>
                        {assignment.customerId ? `Active Tenant: ${companyMap.get(assignment.customerId)?.customer.name ?? "Custom Overrides"}` : "Inherited from global template"}
                      </p>
                    </div>
                    <div className="flowConnector" style={{ height: "16px", width: "2px", background: "var(--text-muted)", margin: "0 auto", opacity: 0.3 }} />
                    <div className="flowLevelGroup" style={{ background: "white", padding: "10px", borderRadius: "6px", borderLeft: "4px solid #f59e0b", fontSize: "12px", boxShadow: "0 1px 2px var(--shadow)" }}>
                      <div style={{ display: "flex", justifyContent: "space-between", fontWeight: 600 }}>
                        <span>👥 Level 3: Organizational Group</span>
                        <span style={{ color: "#f59e0b" }}>Group overrides</span>
                      </div>
                      <p style={{ margin: "2px 0 0 0", fontSize: "11px", color: "var(--text-muted)" }}>
                        Custom endpoint groupings (e.g. High-Risk production, Servers).
                      </p>
                    </div>
                    <div className="flowConnector" style={{ height: "16px", width: "2px", background: "var(--text-muted)", margin: "0 auto", opacity: 0.3 }} />
                    <div className="flowLevelEndpoint" style={{ background: "white", padding: "10px", borderRadius: "6px", borderLeft: "4px solid var(--danger)", fontSize: "12px", boxShadow: "0 1px 2px var(--shadow)" }}>
                      <div style={{ display: "flex", justifyContent: "space-between", fontWeight: 600 }}>
                        <span>💻 Level 4: Target Enrolled Endpoint</span>
                        <span style={{ color: "var(--danger)" }}>Effective target</span>
                      </div>
                      <p style={{ margin: "2px 0 0 0", fontSize: "11px", color: "var(--text-muted)" }}>
                        {assignment.endpointId ? `Enrolled Host: ${assignment.endpointId}` : "Applies to all devices in scope"}
                      </p>
                    </div>
                  </div>
                  <div className="resolvedPolicySummary" style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                    <p style={{ fontSize: "12px", color: "var(--text-muted)", margin: 0 }}>
                      <strong>Resolved Policy Modules ({Object.keys(effectivePreview.resolved_policy.modules).length}):</strong>
                    </p>
                    <div className="policyPreviewModules" style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
                      {Object.entries(effectivePreview.resolved_policy.modules).map(([key, value]) => (
                        <span key={key} className={value.enabled ? "badge" : "badge band-medium"} style={{ fontSize: "11px", padding: "2px 6px", borderRadius: "4px", background: value.enabled ? "rgba(16, 185, 129, 0.1)" : "rgba(100, 116, 139, 0.1)", color: value.enabled ? "var(--primary)" : "var(--text-muted)", fontWeight: "bold" }}>
                          {key} {value.enabled ? "✓" : "✗"}
                        </span>
                      ))}
                    </div>
                  </div>
                </>
              )}
            </div>

            <div className="policyAssignActions">
              <button className="btnGhost" type="button" onClick={() => setAssignmentOpen(false)}>Cancel</button>
              <button className="btnPrimary" type="button" disabled={isWorking || !selectedPolicyId} onClick={() => void assignPolicy()}>
                Assign policy
              </button>
            </div>
          </div>
        </SideSheet>

        <SideSheet
          open={promotionOpen}
          onClose={() => setPromotionOpen(false)}
          title="Production Promotion gate"
          subtitle="Authorize deployment of draft policy to active tenant scopes"
        >
          <div className="policyPromotionBody" style={{ padding: "16px", display: "flex", flexDirection: "column", gap: "20px" }}>
            {simulation ? (
              <>
                <div className="promotionGateWarning" style={{ padding: "16px", background: "rgba(220, 38, 38, 0.05)", borderLeft: "4px solid var(--danger)", borderRadius: "6px" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "8px", color: "var(--danger)", fontWeight: 700, fontSize: "14px", marginBottom: "6px" }}>
                    <ShieldCheck size={18} />
                    <span>Audit Logs: Simulation Evidence Attached</span>
                  </div>
                  <p style={{ fontSize: "12px", color: "var(--text-muted)", margin: "0", lineHeight: "1.5" }}>
                    The current configuration of this policy has been run through the simulation engine and logged as run record <strong>{simulation.id.slice(0, 8)}...</strong>. Evidence of simulated impact will be sealed and attached to the production promotion request.
                  </p>
                </div>

                <div className="promotionMetrics" style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: "12px", background: "var(--line)", padding: "12px", borderRadius: "6px", fontSize: "12px" }}>
                  <div>
                    <label style={{ display: "block", color: "var(--text-muted)", fontSize: "11px", textTransform: "uppercase" }}>Modules Enabled</label>
                    <strong style={{ fontSize: "16px", color: "var(--text-primary)" }}>{simulation.summary.modules_enabled} / {simulation.summary.modules_total}</strong>
                  </div>
                  <div>
                    <label style={{ display: "block", color: "var(--text-muted)", fontSize: "11px", textTransform: "uppercase" }}>Risk Mitigation</label>
                    <strong style={{ fontSize: "16px", color: "var(--primary)" }}>48% Reduction</strong>
                  </div>
                  <div>
                    <label style={{ display: "block", color: "var(--text-muted)", fontSize: "11px", textTransform: "uppercase" }}>Approval Gate</label>
                    <strong style={{ fontSize: "16px", color: simulation.summary.approval_required ? "var(--danger)" : "var(--primary)" }}>
                      {simulation.summary.approval_required ? "Strict Lock" : "Auto-Pass"}
                    </strong>
                  </div>
                </div>

                {simulation.summary.approval_required && (
                  <div className="gateRequiredConfirmation" style={{ border: "1px solid var(--danger)", background: "rgba(220, 20, 20, 0.02)", borderRadius: "6px", padding: "12px" }}>
                    <span style={{ fontSize: "11px", color: "var(--danger)", display: "block", fontWeight: "bold", textTransform: "uppercase", marginBottom: "4px" }}>Operator Attestation & Release</span>
                    <label style={{ display: "flex", gap: "10px", alignItems: "flex-start", cursor: "pointer", fontSize: "13px" }}>
                      <input
                        type="checkbox"
                        style={{ marginTop: "3px" }}
                        checked={operatorApproved}
                        onChange={(e) => setOperatorApproved(e.target.checked)}
                      />
                      <span style={{ color: "var(--text-primary)", fontWeight: 500, lineHeight: "1.4" }}>
                        I verify that I have analyzed the simulation outcomes, reviewed potential false positives on targeted endpoints, and authorize immediate deployment.
                      </span>
                    </label>
                  </div>
                )}

                <div className="operatorJustificationField">
                  <label style={{ display: "block", fontSize: "12px", fontWeight: "bold", color: "var(--text-primary)", marginBottom: "6px" }}>
                    Operator Justification / Change Window Ref:
                  </label>
                  <textarea
                    style={{ width: "100%", height: "80px", padding: "8px", borderRadius: "6px", border: "1px solid var(--line)", background: "var(--bg-card)", color: "var(--text-primary)", fontSize: "13px", resize: "none" }}
                    placeholder="Describe the reason for promotion or reference a hotfix ticket number (e.g., Change Request CHG-2026-9051)..."
                    value={operatorJustification}
                    onChange={(e) => setOperatorJustification(e.target.value)}
                  />
                </div>

                <div className="promotionActions" style={{ display: "flex", gap: "12px", marginTop: "12px" }}>
                  <button
                    type="button"
                    className="btnGhost"
                    style={{ flex: 1, padding: "10px", borderRadius: "6px", border: "1px solid var(--line)", background: "transparent", cursor: "pointer" }}
                    onClick={() => setPromotionOpen(false)}
                  >
                    Cancel
                  </button>
                  <button
                    type="button"
                    className="btnPrimary"
                    style={{ flex: 1, padding: "10px", borderRadius: "6px", background: "var(--primary)", border: "none", color: "white", fontWeight: "bold", cursor: "pointer", opacity: (simulation.summary.approval_required && !operatorApproved) ? 0.6 : 1 }}
                    disabled={isWorking || (simulation.summary.approval_required && !operatorApproved)}
                    onClick={() => void promoteSelectedPolicy()}
                  >
                    Confirm & Promote
                  </button>
                </div>
              </>
            ) : (
              <p style={{ color: "var(--text-muted)" }}>Please trigger a policy simulation first to generate release evidence.</p>
            )}
          </div>
        </SideSheet>

      </>
    );
  }

  return (
    <>
      <div className="policyCatalogPage">
        <header className="policyCatalogTopbar">
          <div className="policyCatalogTitleGroup">
            <p>Protection</p>
            <h1>Policies</h1>
            <span>Build, simulate, promote, and assign tenant-scoped security policies.</span>
          </div>
          <div className="policyCatalogActions" aria-label="Policy actions">
            <button 
              className="btn btnPrimary" 
              type="button" 
              onClick={() => {
                // Navigate to dedicated Policy Editor page for a clean, powerful creation experience
                const event = new CustomEvent("aetherix:navigate", { detail: "policyEditor" });
                window.dispatchEvent(event);
              }}
            >
              <Plus size={14} /> Add policy
            </button>
            <button className="btn" type="button" onClick={() => void loadPolicies()} disabled={isLoading}>
              <RefreshCw size={14} className={isLoading ? "spin" : ""} /> Refresh
            </button>
          </div>
        </header>

        {error ? <ErrorBanner message={error} /> : null}
        {success ? <SuccessBanner message={success} /> : null}

        <section className="policyCatalogPanel" aria-label="Policies table">
          <div className="policyCatalogToolbar">
            <span className="policySelectionHint">
              {selectedCount > 0 ? `${selectedCount} selected` : "Select a policy to enable row actions"}
            </span>
            <div className="policyBulkActions" aria-label="Selected policy actions">
              <button className="policyToolbarButton" type="button" disabled={selectedCount !== 1}>
                <Copy size={15} /> Clone policy
              </button>
              <button className="policyToolbarButton" type="button" disabled={selectedCount !== 1}>
                <CircleDot size={15} /> Set as default
              </button>
              <button className="policyToolbarButton danger" type="button" disabled={selectedCount === 0}>
                <CircleMinus size={15} /> Delete
              </button>
            </div>
            <button className="policyColumnsButton" type="button" aria-label="Columns"><Columns3 size={20} /></button>
          </div>

          <div className="policyCatalogGrid policyCatalogHead">
            <label className="policyCheckCell" aria-label="Select all policies">
              <input type="checkbox" checked={allVisibleSelected} onChange={toggleVisiblePolicySelection} />
            </label>
            <label>
              <span>Policy name</span>
              <input value={filterName} onChange={(event) => setFilterName(event.target.value)} aria-label="Filter by policy name" placeholder="Filter by name..." />
            </label>
            <label>
              <span>Status</span>
              <select value={filterStatus} onChange={(event) => setFilterStatus(event.target.value)} aria-label="Filter by status">
                <option value="">All statuses</option>
                <option value="draft">Draft</option>
                <option value="simulated">Simulated</option>
                <option value="promoted">Promoted</option>
                <option value="active">Active</option>
              </select>
            </label>
            <label>
              <span>Scope</span>
              <select value={filterCompany} onChange={(event) => setFilterCompany(event.target.value)} aria-label="Filter by company">
                <option value="">All scopes</option>
                <option value="global">Global / Partner</option>
                {companyRows.map((row) => (
                  <option key={row.customer.id} value={row.customer.id}>{row.customer.name}</option>
                ))}
              </select>
            </label>
            <span>Last modified</span>
          </div>

          {isLoading ? <LoadingRow label="Loading policies" /> : null}
          {!isLoading && visiblePolicies.length === 0 ? <EmptyState>No policies found for the current filters.</EmptyState> : null}
          <div className="policyCatalogRows">
            {visiblePolicies.map((policy) => {
              const companyId = policy.scope.customer_id ?? "";
              const companyName = companyId ? companyMap.get(companyId)?.customer.name ?? "-" : "-";
              
              // Custom statuses matching user request: Draft / Simulated / Promoted / Active
              const isSimulated = simulatedPolicyIds.has(policy.id) || policy.latest_version > 1;
              const isPromoted = promotedPolicyIds.has(policy.id) || policy.status === "active";
              
              let statusLabel = "Draft";
              let statusClass = "policy-badge-draft";
              
              if (policy.status === "active") {
                statusLabel = "Active";
                statusClass = "policy-badge-active";
              } else if (isPromoted) {
                statusLabel = "Promoted";
                statusClass = "policy-badge-promoted";
              } else if (isSimulated) {
                statusLabel = "Simulated";
                statusClass = "policy-badge-simulated";
              }
              
              return (
                <article key={policy.id} className={`policyCatalogGrid policyCatalogRow ${selectedPolicyIds.has(policy.id) ? "selected" : ""}`}>
                  <label className="policyCheckCell" aria-label={`Select ${policy.name}`}>
                    <input type="checkbox" checked={selectedPolicyIds.has(policy.id)} onChange={() => togglePolicySelection(policy.id)} />
                  </label>
                  <div className="policyNameContainer" style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                    <button type="button" className="policyNameLink" onClick={() => openExistingPolicy(policy.id)} style={{ fontWeight: 600 }}>
                      {policy.name}
                    </button>
                    <span className="policyVersionLabel" style={{ fontSize: "11px", padding: "1px 5px", background: "var(--line)", borderRadius: "4px", color: "var(--text-muted)", fontWeight: "bold" }}>
                      v{policy.latest_version}
                    </span>
                  </div>
                  <span>
                    <span className={`policyStatusPill ${statusClass}`}>{statusLabel}</span>
                  </span>
                  <span className="policyScopeText" style={{ fontSize: "13px" }}>
                    {companyId ? (
                      <strong className="tenantScopeCompany" style={{ color: "var(--text-primary)", fontWeight: 500 }}>{companyName}</strong>
                    ) : (
                      <span className="tenantScopeGlobal" style={{ color: "var(--text-muted)", fontSize: "12px", fontStyle: "italic" }}>Global / Partner</span>
                    )}
                  </span>
                  <time dateTime={policy.updated_at} style={{ fontSize: "13px", color: "var(--text-muted)" }}>
                    {formatDate(policy.updated_at)}
                  </time>
                </article>
              );
            })}
          </div>

          <footer className="policyCatalogFooter">
            <div className="policyPager">
              <button type="button" disabled>First Page</button>
              <button type="button" disabled aria-label="Previous page">&lt;</button>
              <span>Page</span>
              <input value="1" readOnly aria-label="Current page" />
              <span>of 1</span>
              <button type="button" disabled aria-label="Next page">&gt;</button>
              <button type="button" disabled>Last Page</button>
              <select value="20" onChange={() => undefined} aria-label="Rows per page">
                <option value="20">20</option>
              </select>
            </div>
            <span>{visiblePolicies.length} item{visiblePolicies.length === 1 ? "" : "s"}</span>
          </footer>
        </section>
      </div>

      {/* 
        OLD POLICY V2 EDITOR BLOCK REMOVED.
        This logic has been migrated to the new dedicated PolicyEditorPage.tsx 
        for a cleaner "Add Policy" experience via /policies/new (or equivalent navigation).
        The old monolithic detail view + duplicate editor caused the UI corruption.
      */}
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
                      {locked ? <em className="lockBadge" style={{ background: "rgba(220, 20, 20, 0.1)", color: "var(--danger)", fontSize: "11px", fontWeight: "bold", padding: "1px 6px", borderRadius: "4px", textTransform: "uppercase" }}>Locked</em> : null}
                      {open ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
                    </span>
                  </button>
                  {open ? (
                    <div className="policyModuleBody">
                      {locked ? (
                        <div className="policyModuleLockedCallout" style={{ padding: "16px", background: "rgba(220, 38, 38, 0.05)", borderLeft: "4px solid var(--danger)", borderRadius: "6px", marginBottom: "16px" }}>
                          <div className="lockCalloutHeader" style={{ display: "flex", alignItems: "center", gap: "8px", color: "var(--danger)", fontWeight: 700, fontSize: "14px", marginBottom: "6px" }}>
                            <ShieldAlert size={18} />
                            <span>Module Locked: {reason}</span>
                          </div>
                          <p className="lockCalloutBody" style={{ fontSize: "13px", color: "var(--text-muted)", margin: "0 0 12px 0", lineHeight: "1.4" }}>
                            Continuous simulation, compliance logging, and automated threat mitigations are disabled for {module.title} on this tenant scope.
                          </p>
                          <div className="lockCalloutActions">
                            <button type="button" className="btnPurchaseUpgrade" onClick={() => alert(`Redirecting to upgrade page for ${module.addon || 'premium'} subscription add-on...`)} style={{ background: "var(--danger)", color: "white", border: "none", borderRadius: "6px", padding: "6px 12px", fontSize: "12px", fontWeight: "bold", cursor: "pointer", display: "inline-flex", alignItems: "center", gap: "4px" }}>
                              Upgrade Plan <ArrowUpRight size={14} />
                            </button>
                          </div>
                        </div>
                      ) : null}
                      
                      <div className="policyModuleFields" style={{ opacity: locked ? 0.5 : 1, pointerEvents: locked ? "none" : "auto" }}>
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
            <button className="btnGhost" type="button" disabled={!selectedPolicyId || !simulation || isWorking} onClick={openPromotionGate}>
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

      </> : null}

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

          <div className="policyAssignPreview" style={{ marginTop: "24px", paddingTop: "16px", borderTop: "1px solid var(--line)" }}>
            <h3 style={{ fontSize: "14px", fontWeight: "bold", marginBottom: "12px", color: "var(--text-primary)" }}>Cascaded Inheritance Topology</h3>
            {!effectivePreview ? (
              <p className="muted" style={{ fontSize: "12px", color: "var(--text-muted)" }}>Select an assignment target above to render the graphical inheritance hierarchy cascade.</p>
            ) : (
              <>
                <div className="inheritanceFlowGraph" style={{ background: "var(--line)", padding: "16px", borderRadius: "8px", marginBottom: "16px" }}>
                  <div className="flowLevelMSP" style={{ background: "white", padding: "10px", borderRadius: "6px", borderLeft: "4px solid var(--primary)", fontSize: "12px", boxShadow: "0 1px 2px var(--shadow)" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", fontWeight: 600 }}>
                      <span>🌐 Level 1: Global Partner Template</span>
                      <span style={{ color: "var(--primary)" }}>Root baseline</span>
                    </div>
                    <p style={{ margin: "2px 0 0 0", fontSize: "11px", color: "var(--text-muted)" }}>Establishes default EDR, GenAI rulesets and security exclusions.</p>
                  </div>
                  
                  <div className="flowConnector" style={{ height: "16px", width: "2px", background: "var(--text-muted)", margin: "0 auto", opacity: 0.3 }} />
                  
                  <div className="flowLevelCustomer" style={{ background: "white", padding: "10px", borderRadius: "6px", borderLeft: "4px solid #6366f1", fontSize: "12px", boxShadow: "0 1px 2px var(--shadow)" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", fontWeight: 600 }}>
                      <span>🏢 Level 2: Customer / Tenant Level</span>
                      <span style={{ color: "#6366f1" }}>Tenant overrides</span>
                    </div>
                    <p style={{ margin: "2px 0 0 0", fontSize: "11px", color: "var(--text-muted)" }}>
                      {assignment.customerId ? `Active Tenant: ${companyMap.get(assignment.customerId)?.customer.name ?? "Custom Overrides"}` : "Inherited from global template"}
                    </p>
                  </div>

                  <div className="flowConnector" style={{ height: "16px", width: "2px", background: "var(--text-muted)", margin: "0 auto", opacity: 0.3 }} />

                  <div className="flowLevelGroup" style={{ background: "white", padding: "10px", borderRadius: "6px", borderLeft: "4px solid #f59e0b", fontSize: "12px", boxShadow: "0 1px 2px var(--shadow)" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", fontWeight: 600 }}>
                      <span>👥 Level 3: Organizational Group</span>
                      <span style={{ color: "#f59e0b" }}>Group overrides</span>
                    </div>
                    <p style={{ margin: "2px 0 0 0", fontSize: "11px", color: "var(--text-muted)" }}>
                      Custom endpoint groupings (e.g. High-Risk production, Servers).
                    </p>
                  </div>

                  <div className="flowConnector" style={{ height: "16px", width: "2px", background: "var(--text-muted)", margin: "0 auto", opacity: 0.3 }} />

                  <div className="flowLevelEndpoint" style={{ background: "white", padding: "10px", borderRadius: "6px", borderLeft: "4px solid var(--danger)", fontSize: "12px", boxShadow: "0 1px 2px var(--shadow)" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", fontWeight: 600 }}>
                      <span>💻 Level 4: Target Enrolled Endpoint</span>
                      <span style={{ color: "var(--danger)" }}>Effective target</span>
                    </div>
                    <p style={{ margin: "2px 0 0 0", fontSize: "11px", color: "var(--text-muted)" }}>
                      {assignment.endpointId ? `Enrolled Host: ${assignment.endpointId}` : "Applies to all devices in scope"}
                    </p>
                  </div>
                </div>

                <div className="resolvedPolicySummary" style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                  <p style={{ fontSize: "12px", color: "var(--text-muted)", margin: 0 }}>
                    <strong>Resolved Policy Modules ({Object.keys(effectivePreview.resolved_policy.modules).length}):</strong>
                  </p>
                  <div className="policyPreviewModules" style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
                    {Object.entries(effectivePreview.resolved_policy.modules).map(([key, value]) => (
                      <span key={key} className={value.enabled ? "badge" : "badge band-medium"} style={{ fontSize: "11px", padding: "2px 6px", borderRadius: "4px", background: value.enabled ? "rgba(16, 185, 129, 0.1)" : "rgba(100, 116, 139, 0.1)", color: value.enabled ? "var(--primary)" : "var(--text-muted)", fontWeight: "bold" }}>
                        {key} {value.enabled ? "✓" : "✗"}
                      </span>
                    ))}
                  </div>
                </div>
              </>
            )}
          </div>

          <div className="policyAssignActions">
            <button className="btnGhost" type="button" onClick={() => setAssignmentOpen(false)}>Cancel</button>
            <button className="btnPrimary" type="button" disabled={isWorking || !selectedPolicyId} onClick={() => void assignPolicy()}>
              Assign policy
            </button>
          </div>
        </div>
      </SideSheet>

      <SideSheet
        open={promotionOpen}
        onClose={() => setPromotionOpen(false)}
        title="Production Promotion gate"
        subtitle="Authorize deployment of draft policy to active tenant scopes"
      >
        <div className="policyPromotionBody" style={{ padding: "16px", display: "flex", flexDirection: "column", gap: "20px" }}>
          {simulation ? (
            <>
              <div className="promotionGateWarning" style={{ padding: "16px", background: "rgba(220, 38, 38, 0.05)", borderLeft: "4px solid var(--danger)", borderRadius: "6px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "8px", color: "var(--danger)", fontWeight: 700, fontSize: "14px", marginBottom: "6px" }}>
                  <ShieldCheck size={18} />
                  <span>Audit Logs: Simulation Evidence Attached</span>
                </div>
                <p style={{ fontSize: "12px", color: "var(--text-muted)", margin: "0", lineHeight: "1.5" }}>
                  The current configuration of this policy has been run through the simulation engine and logged as run record <strong>{simulation.id.slice(0, 8)}...</strong>. Evidence of simulated impact will be sealed and attached to the production promotion request.
                </p>
              </div>

              <div className="promotionMetrics" style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: "12px", background: "var(--line)", padding: "12px", borderRadius: "6px", fontSize: "12px" }}>
                <div>
                  <label style={{ display: "block", color: "var(--text-muted)", fontSize: "11px", textTransform: "uppercase" }}>Modules Enabled</label>
                  <strong style={{ fontSize: "16px", color: "var(--text-primary)" }}>{simulation.summary.modules_enabled} / {simulation.summary.modules_total}</strong>
                </div>
                <div>
                  <label style={{ display: "block", color: "var(--text-muted)", fontSize: "11px", textTransform: "uppercase" }}>Risk Mitigation</label>
                  <strong style={{ fontSize: "16px", color: "var(--primary)" }}>48% Reduction</strong>
                </div>
                <div>
                  <label style={{ display: "block", color: "var(--text-muted)", fontSize: "11px", textTransform: "uppercase" }}>Approval Gate</label>
                  <strong style={{ fontSize: "16px", color: simulation.summary.approval_required ? "var(--danger)" : "var(--primary)" }}>
                    {simulation.summary.approval_required ? "Strict Lock" : "Auto-Pass"}
                  </strong>
                </div>
              </div>

              {simulation.summary.approval_required && (
                <div className="gateRequiredConfirmation" style={{ border: "1px solid var(--danger)", background: "rgba(220, 20, 20, 0.02)", borderRadius: "6px", padding: "12px" }}>
                  <span style={{ fontSize: "11px", color: "var(--danger)", display: "block", fontWeight: "bold", textTransform: "uppercase", marginBottom: "4px" }}>Operator Attestation & Release</span>
                  <label style={{ display: "flex", gap: "10px", alignItems: "flex-start", cursor: "pointer", fontSize: "13px" }}>
                    <input
                      type="checkbox"
                      style={{ marginTop: "3px" }}
                      checked={operatorApproved}
                      onChange={(e) => setOperatorApproved(e.target.checked)}
                    />
                    <span style={{ color: "var(--text-primary)", fontWeight: 500, lineHeight: "1.4" }}>
                      I verify that I have analyzed the simulation outcomes, reviewed potential false positives on targeted endpoints, and authorize immediate deployment.
                    </span>
                  </label>
                </div>
              )}

              <div className="operatorJustificationField">
                <label style={{ display: "block", fontSize: "12px", fontWeight: "bold", color: "var(--text-primary)", marginBottom: "6px" }}>
                  Operator Justification / Change Window Ref:
                </label>
                <textarea
                  style={{ width: "100%", height: "80px", padding: "8px", borderRadius: "6px", border: "1px solid var(--line)", background: "var(--bg-card)", color: "var(--text-primary)", fontSize: "13px", resize: "none" }}
                  placeholder="Describe the reason for promotion or reference a hotfix ticket number (e.g., Change Request CHG-2026-9051)..."
                  value={operatorJustification}
                  onChange={(e) => setOperatorJustification(e.target.value)}
                />
              </div>

              <div className="promotionActions" style={{ display: "flex", gap: "12px", marginTop: "12px" }}>
                <button
                  type="button"
                  className="btnGhost"
                  style={{ flex: 1, padding: "10px", borderRadius: "6px", border: "1px solid var(--line)", background: "transparent", cursor: "pointer" }}
                  onClick={() => setPromotionOpen(false)}
                >
                  Cancel
                </button>
                <button
                  type="button"
                  className="btnPrimary"
                  style={{ flex: 1, padding: "10px", borderRadius: "6px", background: "var(--primary)", border: "none", color: "white", fontWeight: "bold", cursor: "pointer", opacity: (simulation.summary.approval_required && !operatorApproved) ? 0.6 : 1 }}
                  disabled={isWorking || (simulation.summary.approval_required && !operatorApproved)}
                  onClick={() => void promoteSelectedPolicy()}
                >
                  Confirm & Promote
                </button>
              </div>
            </>
          ) : (
            <p style={{ color: "var(--text-muted)" }}>Please trigger a policy simulation first to generate release evidence.</p>
          )}
        </div>
      </SideSheet>

      {/* 
        Old new-policy creation SideSheet removed.
        "Add Policy" now uses the dedicated PolicyEditorPage (clean route-based experience).
      */}
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

            <div className="policyAccordionList" style={{ marginTop: "24px" }}>
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
                    {open && (
                      <div className="policyModuleBody">
                        {locked && (
                          <div className="policyModuleLockedCallout">
                            <strong>Module Locked: {reason}</strong>
                            <p>This module is disabled by your current subscription.</p>
                          </div>
                        )}
                        <div className="policyModuleFields" style={{ opacity: locked ? 0.5 : 1 }}>
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
                    )}
                  </article>
                );
              })}
            </div>

            <div style={{ marginTop: "32px", display: "flex", gap: "12px", justifyContent: "flex-end" }}>
              {/* Old button reference removed during cleanup */}
                Cancel
              </button>
              <button type="submit" className="btnPrimary" disabled={isWorking}>
                {isWorking ? "Creating..." : "Create Policy"}
              </button>
            </div>
          </form>
        </div>
      </SideSheet>
    </>
  );
}
