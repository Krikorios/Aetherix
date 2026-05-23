import { type ReactNode, useCallback, useEffect, useState } from "react";
import {
  AlertTriangle,
  Archive,
  Ban,
  BarChart,
  BarChart3,
  Bell,
  Brain,
  Bug,
  Building2,
  FileText,
  FileCheck,
  FlaskConical,
  Globe,
  Globe2,
  LayoutDashboard,
  LogOut,
  Mail,
  Package,
  Plug,
  Search,
  Settings,
  Shield,
  ShieldCheck,
  Smartphone,
  Target,
  Usb,
  Users,
  Eye,
  ListChecks,
} from "lucide-react";
import { DashboardPage } from "./pages/Dashboard";
import { AlertsPage } from "./pages/AlertsPage";
import { DlpScanPage } from "./pages/DlpScanPage";
import { PolicyPage } from "./pages/PolicyPage";
import { AntimalwareBehaviorPage } from "./pages/AntimalwareBehavior";
import { CustomDetectionRulesPage } from "./pages/CustomDetectionRules";
import { EnrollmentPage } from "./pages/EnrollmentPage";
import { AccountsPage } from "./pages/AccountsPage";
import { CompaniesPage } from "./pages/CompaniesPage";
import { LoginPage } from "./pages/LoginPage";
import { SetupAccountPage } from "./pages/SetupAccountPage";
import {
  apiGet,
  getAccountId,
  logout as apiLogout,
  type Branding,
  type MeResponse,
  type PermissionLevel,
} from "./api";

const DEFAULT_BRANDING: Branding = {
  product_name: "Aetherix",
  tagline: "MSP Console",
  primary_color: "#0b6b57",
  accent_color: "#0b6b57",
  logo_url: null,
  support_email: null,
  support_url: null,
  footer_note: null,
  source: "platform",
};

type Page =
  | "dashboard"
  | "executiveSummary"
  | "healthAttackSurface"
  | "alerts"
  | "search"
  | "blocklist"
  | "customRules"
  | "agenticAi"
  | "threatsXplorer"
  | "policies"
  | "antimalware"
  | "webProtection"
  | "deviceControl"
  | "riskManagement"
  | "digitalRisk"
  | "easm"
  | "reports"
  | "quarantine"
  | "companies"
  | "accounts"
  | "installers"
  | "policyAssignments"
  | "sandbox"
  | "emailSecurity"
  | "mobileSecurity"
  | "dataInsights"
  | "integrations"
  | "configuration";

type NavItem = {
  id: Page;
  label: string;
  icon: ReactNode;
  // Permission required to see this item. ``null`` means always available
  // for any signed-in account.
  requires?: { resource: string; level: PermissionLevel } | null;
};

const NAV: { group: string; items: NavItem[] }[] = [
  {
    group: "OVERVIEW",
    items: [
      { id: "dashboard", label: "Dashboard", icon: <LayoutDashboard size={18} /> },
      { id: "executiveSummary", label: "Executive Summary", icon: <BarChart3 size={18} />, requires: { resource: "incidents", level: "view" } },
      { id: "healthAttackSurface", label: "Health & Attack Surface", icon: <Shield size={18} />, requires: { resource: "incidents", level: "view" } },
    ],
  },
  {
    group: "INCIDENTS & RESPONSE",
    items: [
      { id: "alerts", label: "Alerts", icon: <Bell size={18} />, requires: { resource: "incidents", level: "view" } },
      { id: "search", label: "Search", icon: <Search size={18} />, requires: { resource: "incidents", level: "view" } },
      { id: "blocklist", label: "Blocklist", icon: <Ban size={18} />, requires: { resource: "policies", level: "view" } },
      { id: "customRules", label: "Custom Rules", icon: <ListChecks size={18} />, requires: { resource: "policies", level: "edit" } },
      { id: "agenticAi", label: "Agentic AI Investigation", icon: <Brain size={18} />, requires: { resource: "incidents", level: "edit" } },
      { id: "threatsXplorer", label: "Threats Xplorer", icon: <Target size={18} />, requires: { resource: "policies", level: "view" } },
    ],
  },
  {
    group: "PROTECTION",
    items: [
      { id: "policies", label: "Policies", icon: <ShieldCheck size={18} />, requires: { resource: "policies", level: "view" } },
      { id: "antimalware", label: "Antimalware & Behavior", icon: <Bug size={18} />, requires: { resource: "policies", level: "view" } },
      { id: "webProtection", label: "Web & Email Protection", icon: <Globe size={18} />, requires: { resource: "policies", level: "view" } },
      { id: "deviceControl", label: "Device Control", icon: <Usb size={18} />, requires: { resource: "policies", level: "view" } },
      { id: "quarantine", label: "Quarantine", icon: <Archive size={18} />, requires: { resource: "incidents", level: "edit" } },
    ],
  },
  {
    group: "RISK & EXTERNAL",
    items: [
      { id: "riskManagement", label: "Risk Management", icon: <AlertTriangle size={18} />, requires: { resource: "incidents", level: "view" } },
      { id: "digitalRisk", label: "Digital Risk (DRP)", icon: <Eye size={18} />, requires: { resource: "incidents", level: "view" } },
      { id: "easm", label: "External Attack Surface (EASM)", icon: <Globe2 size={18} />, requires: { resource: "incidents", level: "view" } },
      { id: "reports", label: "Reports", icon: <FileText size={18} />, requires: { resource: "incidents", level: "view" } },
    ],
  },
  {
    group: "MSP CONTROL",
    items: [
      { id: "companies", label: "Companies", icon: <Building2 size={18} />, requires: { resource: "companies", level: "view" } },
      { id: "accounts", label: "Accounts", icon: <Users size={18} />, requires: { resource: "accounts", level: "view" } },
      { id: "installers", label: "Installers", icon: <Package size={18} />, requires: { resource: "companies", level: "edit" } },
      { id: "policyAssignments", label: "Policy Assignments", icon: <FileCheck size={18} />, requires: { resource: "policies", level: "edit" } },
    ],
  },
  {
    group: "ADD-ONS & INTEGRATIONS",
    items: [
      { id: "sandbox", label: "Sandbox Analyzer", icon: <FlaskConical size={18} />, requires: { resource: "incidents", level: "view" } },
      { id: "emailSecurity", label: "Email Security", icon: <Mail size={18} />, requires: { resource: "incidents", level: "view" } },
      { id: "mobileSecurity", label: "Mobile Security", icon: <Smartphone size={18} />, requires: { resource: "incidents", level: "view" } },
      { id: "dataInsights", label: "Data Insights", icon: <BarChart size={18} />, requires: { resource: "licensing", level: "view" } },
      { id: "integrations", label: "Integrations", icon: <Plug size={18} />, requires: { resource: "companies", level: "edit" } },
      { id: "configuration", label: "Configuration", icon: <Settings size={18} />, requires: { resource: "companies", level: "manage" } },
    ],
  },
];

const LEVEL_RANK: Record<PermissionLevel, number> = {
  none: 0,
  view: 1,
  edit: 2,
  manage: 3,
};

function hasPermission(
  me: MeResponse | null,
  req: { resource: string; level: PermissionLevel } | null | undefined,
): boolean {
  if (!req) return true;
  if (!me) return false;
  const have = me.permissions[req.resource] ?? "none";
  return LEVEL_RANK[have] >= LEVEL_RANK[req.level];
}

function pickInitialPage(me: MeResponse | null): Page {
  for (const group of NAV) {
    for (const item of group.items) {
      if (hasPermission(me, item.requires)) return item.id;
    }
  }
  return "dashboard";
}

function parseInviteToken(hash: string): string | null {
  // Invite links use ``#/invite/<token>`` so the token survives copy/paste
  // and works even when the console is served as a static SPA.
  const match = /^#\/invite\/([A-Za-z0-9_-]+)$/.exec(hash || "");
  return match ? match[1] : null;
}

const INITIAL_INVITE_TOKEN =
  typeof window !== "undefined" ? parseInviteToken(window.location.hash) : null;

export function App() {
  const [me, setMe] = useState<MeResponse | null>(null);
  const [page, setPage] = useState<Page>("dashboard");
  const [branding, setBranding] = useState<Branding>(DEFAULT_BRANDING);
  const [authStatus, setAuthStatus] = useState<"loading" | "signedIn" | "signedOut">("loading");
  const [inviteToken, setInviteToken] = useState<string | null>(INITIAL_INVITE_TOKEN);

  useEffect(() => {
    const onHashChange = () => setInviteToken(parseInviteToken(window.location.hash));
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

  useEffect(() => {
    function onNavigate(event: Event) {
      const custom = event as CustomEvent<{ page?: Page }>;
      const target = custom.detail?.page;
      if (!target) return;
      if (!navItemFor(target)) return;
      setPage(target);
    }
    window.addEventListener("aetherix:navigate", onNavigate as EventListener);
    return () => window.removeEventListener("aetherix:navigate", onNavigate as EventListener);
  }, []);

  const loadMe = useCallback(async () => {
    if (!getAccountId()) {
      setMe(null);
      setBranding(DEFAULT_BRANDING);
      setAuthStatus("signedOut");
      return;
    }
    try {
      const next = await apiGet<MeResponse>("/me");
      setMe(next);
      setBranding(next.branding ?? DEFAULT_BRANDING);
      setAuthStatus("signedIn");
      setPage((current) => (hasPermission(next, navItemFor(current)?.requires) ? current : pickInitialPage(next)));
    } catch {
      // Stored account id is stale/invalid — drop it and force re-login.
      apiLogout();
      setMe(null);
      setBranding(DEFAULT_BRANDING);
      setAuthStatus("signedOut");
    }
  }, []);

  useEffect(() => {
    queueMicrotask(() => void loadMe());
    const onAccountChange = () => {
      void loadMe();
    };
    window.addEventListener("aetherix:account-changed", onAccountChange);
    window.addEventListener("storage", onAccountChange);
    return () => {
      window.removeEventListener("aetherix:account-changed", onAccountChange);
      window.removeEventListener("storage", onAccountChange);
    };
  }, [loadMe]);

  useEffect(() => {
    const root = document.documentElement;
    root.style.setProperty("--accent", branding.accent_color || branding.primary_color);
    root.style.setProperty("--brand-primary", branding.primary_color);
    document.title = `${branding.product_name} — ${branding.tagline}`;
  }, [branding.accent_color, branding.primary_color, branding.product_name, branding.tagline]);

  if (inviteToken) {
    return <SetupAccountPage token={inviteToken} />;
  }

  if (authStatus === "loading") {
    return (
      <main className="loginShell">
        <p className="muted">Loading…</p>
      </main>
    );
  }

  if (authStatus === "signedOut" || !me) {
    return (
      <LoginPage
        onAuthenticated={(next) => {
          setMe(next);
          setBranding(next.branding ?? DEFAULT_BRANDING);
          setAuthStatus("signedIn");
          setPage(pickInitialPage(next));
        }}
      />
    );
  }

  const handleSignOut = () => {
    apiLogout();
    setMe(null);
    setBranding(DEFAULT_BRANDING);
    setAuthStatus("signedOut");
    setPage("dashboard");
  };

  const visibleNav = NAV
    .map((section) => ({
      ...section,
      items: section.items.filter((item) => hasPermission(me, item.requires)),
    }))
    .filter((section) => section.items.length > 0);

  const currentNavItem = navItemFor(page);
  const pageAllowed = hasPermission(me, currentNavItem?.requires);
  const primaryRole = me.account.roles[0]?.role_code ?? null;

  return (
    <main className="shell">
      <aside className="rail" aria-label="Primary navigation">
        <div className="brandMark">
          {branding.logo_url ? (
            <img className="railLogo" src={branding.logo_url} alt="" aria-hidden="true" />
          ) : (
            <ShieldCheck className="railLogo" aria-hidden="true" />
          )}
          <div>
            <strong>{branding.product_name}</strong>
            <span>{branding.tagline}</span>
          </div>
        </div>
        {visibleNav.map((section) => (
          <nav className="navGroup" key={section.group} aria-label={section.group}>
            <span>{section.group}</span>
            {section.items.map(({ id, label, icon }) => (
              <button
                key={id}
                className={page === id ? "active" : ""}
                title={label}
                aria-label={label}
                aria-current={page === id ? "page" : undefined}
                onClick={() => setPage(id)}
              >
                {icon}
                <span>{label}</span>
              </button>
            ))}
          </nav>
        ))}
        <div className="railAuthPanel">
          <span>Signed in as</span>
          <strong>{me.account.full_name || me.account.email}</strong>
          <code>{me.account.email}</code>
          {primaryRole ? <em>{ROLE_LABEL[primaryRole] ?? primaryRole}</em> : null}
          <div className="railAuthActions">
            <button type="button" onClick={handleSignOut}>
              <LogOut size={14} style={{ marginRight: 6, verticalAlign: "-2px" }} />
              Sign out
            </button>
          </div>
        </div>
      </aside>

      <section className="workspace">
        {!pageAllowed ? (
          <ForbiddenPage />
        ) : (
          <>
            {page === "dashboard" && <DashboardPage />}
            {page === "alerts" && <AlertsPage />}
            {page === "search" && <AlertsPage />}
            {page === "threatsXplorer" && <DlpScanPage />}
            {page === "policies" && <PolicyPage />}
            {page === "antimalware" && <AntimalwareBehaviorPage me={me} />}
            {page === "customRules" && <CustomDetectionRulesPage me={me} />}
            {page === "installers" && <EnrollmentPage />}
            {page === "companies" && <CompaniesPage />}
            {page === "accounts" && <AccountsPage />}
            {!["dashboard", "alerts", "search", "threatsXplorer", "policies", "antimalware", "customRules", "installers", "companies", "accounts"].includes(page) ? (
              <PlaceholderPage page={page} />
            ) : null}
          </>
        )}
      </section>
    </main>
  );
}

function navItemFor(page: Page): NavItem | null {
  for (const group of NAV) {
    for (const item of group.items) {
      if (item.id === page) return item;
    }
  }
  return null;
}

const ROLE_LABEL: Record<string, string> = {
  platform_owner: "Platform Owner",
  msp_partner: "MSP Partner",
  company_admin: "Company Administrator",
  company_tech: "Company Technician",
  company_viewer: "Company Viewer",
};

function ForbiddenPage() {
  return (
    <section className="panel">
      <div className="panelHeader">
        <div>
          <h2>Not available for your role</h2>
          <span>You don't have permission to view this section. Contact your administrator if you need access.</span>
        </div>
        <ShieldCheck size={18} />
      </div>
    </section>
  );
}

type PlaceholderStatus = "designing" | "planned" | "add-on";

const STATUS_LABEL: Record<PlaceholderStatus, string> = {
  designing: "Designing",
  planned: "Planned",
  "add-on": "Add-on entitlement",
};

type PlaceholderMeta = {
  title: string;
  eyebrow: string;
  status: PlaceholderStatus;
  summary: string;
  depends: string[];
};

const PLACEHOLDERS: Record<Exclude<Page, "dashboard" | "alerts" | "search" | "threatsXplorer" | "policies" | "installers" | "companies" | "accounts">, PlaceholderMeta> = {
  executiveSummary: {
    title: "Executive Summary",
    eyebrow: "Partner reporting",
    status: "planned",
    summary:
      "AI-generated portfolio summary for MSP partners: customer risk, license utilisation, top incidents, and weekly delta. Builds on /companies, /alerts, and the upcoming ai_reports table.",
    depends: ["ai_reports table", "/companies tenant scope", "LLM gateway contract"],
  },
  healthAttackSurface: {
    title: "Endpoint Health",
    eyebrow: "Company operations",
    status: "planned",
    summary:
      "Per-company endpoint health view with policy drift, agent version skew, and action queues. Aggregates the existing /endpoints heartbeat data once company-scoped queries land.",
    depends: ["tenant-scoped /endpoints", "policy drift signal", "action queue API"],
  },
  easm: {
    title: "External Attack Surface Management",
    eyebrow: "External exposure",
    status: "planned",
    summary:
      "External attack surface discovery (DNS, CT logs, passive DNS, safe scanners) feeding easm_assets and easm_findings. Tracks domains, subdomains, certificates, exposed services, and risky DNS.",
    depends: ["easm_assets table", "asset-based licensing", "EASM collector workers"],
  },
  blocklist: {
    title: "Blocklist",
    eyebrow: "Response controls",
    status: "planned",
    summary:
      "Tenant-scoped blocklists for hashes, domains, URLs, users, and processes. Pulled into agent policy on heartbeat alongside the existing signed policy document.",
    depends: ["block list table", "policy document merge", "agent policy fetch"],
  },
  customRules: {
    title: "Custom Detection Rules",
    eyebrow: "Detection engineering",
    status: "planned",
    summary:
      "Customer-authored detection rules layered on top of platform rules. Same partner/company isolation as policy documents, with simulation before promotion.",
    depends: ["rules table", "rule simulator", "policy promotion flow"],
  },
  agenticAi: {
    title: "Agentic AI Investigation",
    eyebrow: "Autonomous response",
    status: "designing",
    summary:
      "Investigation agents correlate endpoint telemetry, DLP events, asset criticality, and threat intel into auditable timelines with confidence-scored response recommendations and approval gates.",
    depends: ["incident_cases correlation", "LLM gateway", "response_actions table"],
  },
  antimalware: {
    title: "Antimalware & Behavior",
    eyebrow: "Endpoint protection",
    status: "planned",
    summary:
      "Next-stage antimalware and behavior workflows with high-confidence triage, suspicious process context, and response action staging before destructive enforcement.",
    depends: ["detector integration", "behavior pipeline", "response action queue"],
  },
  webProtection: {
    title: "Web & Email Protection",
    eyebrow: "Content and communication",
    status: "planned",
    summary:
      "Unified controls for web destinations and email protection with policy-driven guardrails and tenant-scoped enforcement aligned to add-on licensing.",
    depends: ["web classifier", "mail connector", "policy integration"],
  },
  deviceControl: {
    title: "Device Control",
    eyebrow: "Data movement controls",
    status: "planned",
    summary:
      "USB and peripheral policy controls for sensitive environments with approval-gated block actions and audit-backed evidence emission.",
    depends: ["device telemetry", "control policy schema", "audit evidence hooks"],
  },
  riskManagement: {
    title: "Risk Management",
    eyebrow: "Asset hardening",
    status: "planned",
    summary:
      "Patch inventory, installation packages, tasks, and tags scoped to a company. Reuses the customer hierarchy already enforced on /companies and installer builds.",
    depends: ["patch inventory ingestion", "task runner", "tag schema"],
  },
  digitalRisk: {
    title: "Digital Risk (DRP)",
    eyebrow: "Continuous threat exposure",
    status: "planned",
    summary:
      "External digital risk detection for brand abuse, impersonation, leaks, and dark web mentions with AI validation and takedown-ready context.",
    depends: ["DRP asset model", "OSINT collectors", "finding-to-incident mapping"],
  },
  reports: {
    title: "Reports",
    eyebrow: "Executive deliverables",
    status: "planned",
    summary:
      "Templated AI executive reports, ransomware readiness, and integrity reports backed by ai_reports with structured confidence, source references, and deterministic fallbacks.",
    depends: ["ai_reports table", "report templates", "object storage for evidence"],
  },
  quarantine: {
    title: "Quarantine",
    eyebrow: "Containment",
    status: "planned",
    summary:
      "Scoped restore and release workflows for quarantined files, email items, and processes. Audit-trail mirrors the existing signed policy and enrollment audit events.",
    depends: ["quarantine store", "restore workflow", "audit hash chain"],
  },
  sandbox: {
    title: "Sandbox Analyzer",
    eyebrow: "Add-on entitlement",
    status: "add-on",
    summary:
      "Detonation and behavioural analysis of suspicious artefacts. Surfaces only when the subscription_entitlements row grants sandbox access for the customer.",
    depends: ["subscription_entitlements", "sandbox worker", "verdict pipeline"],
  },
  policyAssignments: {
    title: "Policy Assignments",
    eyebrow: "MSP governance",
    status: "planned",
    summary:
      "Centralized view of partner/company/group/endpoint assignment scope with inheritance preview and operational diff history.",
    depends: ["assignment history view", "scope filters", "effective diff renderer"],
  },
  emailSecurity: {
    title: "Email Security",
    eyebrow: "Add-on entitlement",
    status: "add-on",
    summary:
      "Inline and journaling protection for mailboxes. Gated on subscription_entitlements and integrated with quarantine, blocklist, and incident correlation.",
    depends: ["mail connector", "subscription_entitlements", "quarantine integration"],
  },
  mobileSecurity: {
    title: "Mobile Security",
    eyebrow: "Add-on entitlement",
    status: "add-on",
    summary:
      "iOS and Android protection with MDM bridge. Gated on subscription_entitlements; reuses the policy engine and enrollment token flow already shipping for desktop agents.",
    depends: ["MDM bridge", "subscription_entitlements", "mobile agent profile"],
  },
  dataInsights: {
    title: "Data Insights",
    eyebrow: "Usage and billing",
    status: "planned",
    summary:
      "Usage, AI efficiency, and billing signals across partners and customers. Feeds the AI Efficiency Score already shown on the Companies hub.",
    depends: ["usage metering", "billing export", "AI efficiency model"],
  },
  integrations: {
    title: "Integrations",
    eyebrow: "Ecosystem connectors",
    status: "planned",
    summary:
      "PSA, RMM, SIEM, identity, and billing connectors. Wraps the existing FastAPI control plane behind a connector contract with per-tenant credentials.",
    depends: ["connector framework", "credential vault", "SIEM event export"],
  },
  configuration: {
    title: "Configuration",
    eyebrow: "Platform settings",
    status: "designing",
    summary:
      "MSP white-label branding, support contacts, and global defaults. Builds on the live /me branding resolver that already drives accent colour and product name in this console.",
    depends: ["branding write API", "support contact schema", "global defaults"],
  },
};

function PlaceholderPage({ page }: { page: Page }) {
  const meta = PLACEHOLDERS[page as keyof typeof PLACEHOLDERS];
  if (!meta) return null;
  return (
    <section className="panel placeholderPanel">
      <div className="panelHeader">
        <div>
          <p className="placeholderEyebrow">{meta.eyebrow}</p>
          <h2>{meta.title}</h2>
          <span>{meta.summary}</span>
        </div>
        <span className={`badge placeholderStatus status-${meta.status}`}>{STATUS_LABEL[meta.status]}</span>
      </div>
      <div className="placeholderDepends">
        <span>Backend dependencies</span>
        <ul>
          {meta.depends.map((d) => (
            <li key={d}>{d}</li>
          ))}
        </ul>
      </div>
    </section>
  );
}


