import { type ReactNode, useCallback, useEffect, useState } from "react";
import {
  AlertTriangle,
  Archive,
  Ban,
  BarChart,
  ClipboardList,
  BarChart3,
  Bell,
  Brain,
  Bug,
  Building2,
  ChevronLeft,
  ChevronDown,
  ChevronRight,
  FileText,
  FileCheck,
  FlaskConical,
  Globe,
  LayoutDashboard,
  LogOut,
  Mail,
  Network,
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
import { PolicyEditorPage } from "./pages/PolicyEditorPage";
import { AntimalwareBehaviorPage } from "./pages/AntimalwareBehavior";
import { CustomDetectionRulesPage } from "./pages/CustomDetectionRules";
import { EnrollmentPage } from "./pages/EnrollmentPage";
import { AccountsPage } from "./pages/AccountsPage";
import { CompaniesPage } from "./pages/CompaniesPage";
import { LoginPage } from "./pages/LoginPage";
import { ImpersonationBanner } from "./components/ImpersonationBanner";
import { SetupAccountPage } from "./pages/SetupAccountPage";
import { CompliancePage } from "./pages/CompliancePage";
import { DigitalRiskPage } from "./pages/DigitalRiskPage";
import {
  apiGet,
  getAccessToken,
  logout as apiLogout,
  type Branding,
  type MeResponse,
  type PermissionLevel,
  type RoleCode,
} from "./api";
import { hasPermission as sharedHasPermission } from "./permissions";
import { ExecutiveSummaryPage } from "./pages/ExecutiveSummaryPage";
import { HealthAttackSurfacePage } from "./pages/HealthAttackSurfacePage";
import { BlocklistPage } from "./pages/BlocklistPage";
import { RiskManagementPage } from "./pages/RiskManagementPage";
import { QuarantinePage } from "./pages/QuarantinePage";
import { WebProtectionPage } from "./pages/WebProtectionPage";
import { DeviceControlPage } from "./pages/DeviceControlPage";
import { ReportsPage } from "./pages/ReportsPage";
import { PolicyAssignmentsPage } from "./pages/PolicyAssignmentsPage";
import { ConfigurationPage } from "./pages/ConfigurationPage";
import { AgenticAiPage } from "./pages/AgenticAiPage";
import { SearchPage } from "./pages/SearchPage";
import { DataInsightsPage } from "./pages/DataInsightsPage";
import { IntegrationsPage } from "./pages/IntegrationsPage";
import { SandboxPage } from "./pages/SandboxPage";
import { EmailSecurityPage } from "./pages/EmailSecurityPage";
import { MobileSecurityPage } from "./pages/MobileSecurityPage";
import { NetworkPage } from "./pages/NetworkPage";
import { ActionQueuePage } from "./pages/ActionQueuePage";

const DEFAULT_BRANDING: Branding = {
  product_name: "Aetherix",
  tagline: "MSP Console",
  primary_color: "#1d4ed8",
  accent_color: "#1d4ed8",
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
  | "reports"
  | "quarantine"
  | "network"
  | "companies"
  | "accounts"
  | "compliance"
  | "installers"
  | "policyAssignments"
  | "sandbox"
  | "emailSecurity"
  | "mobileSecurity"
  | "dataInsights"
  | "integrations"
  | "configuration"
  | "policyEditor"
  | "actionQueue";

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
      { id: "policyAssignments", label: "Policy Assignments", icon: <FileCheck size={18} />, requires: { resource: "policies", level: "edit" } },
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
      { id: "reports", label: "Reports", icon: <FileText size={18} />, requires: { resource: "incidents", level: "view" } },
      { id: "compliance", label: "Compliance Center", icon: <FileCheck size={18} />, requires: { resource: "companies", level: "view" } },
    ],
  },
  {
    group: "MSP CONTROL",
    items: [
      { id: "network", label: "Network", icon: <Network size={18} />, requires: { resource: "companies", level: "view" } },
      { id: "companies", label: "Companies", icon: <Building2 size={18} />, requires: { resource: "companies", level: "view" } },
      { id: "accounts", label: "Accounts", icon: <Users size={18} />, requires: { resource: "accounts", level: "view" } },
      { id: "installers", label: "Installers", icon: <Package size={18} />, requires: { resource: "companies", level: "edit" } },
      { id: "actionQueue", label: "Queue", icon: <ClipboardList size={18} />, requires: { resource: "incidents", level: "view" } },
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

function hasPermission(
  me: MeResponse | null,
  req: { resource: string; level: PermissionLevel } | null | undefined,
): boolean {
  // Delegate to the shared helper so individual page components and the
  // sidebar always evaluate permissions the same way.
  return sharedHasPermission(me, req ?? null);
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

const params = typeof window !== "undefined" ? new URLSearchParams(window.location.search) : null;
const isHarness = import.meta.env.DEV && params?.get("harness") === "true";
const harnessRole = params?.get("role") || "msp_partner";
const harnessPage = (params?.get("page") || "policies") as Page;

function mockedMe(role: string): MeResponse {
  const isAdmin = role === "company_admin";
  return {
    account: {
      id: "account-1",
      email: isAdmin ? "admin@acme.test" : "msp@partner.test",
      full_name: isAdmin ? "Company Admin" : "MSP Partner",
      status: "active",
      two_factor: "enabled",
      password_expires_at: null,
      locked_until: null,
      last_login_at: null,
      created_at: "2026-05-23T00:00:00Z",
      roles: [{ id: "role-1", role_code: role as RoleCode, partner_id: null, customer_id: null, granted_by: "system", granted_at: "2026-05-23T00:00:00Z" }],
    },
    permissions: {
      policies: "manage",
      companies: isAdmin ? "view" : "manage",
      incidents: "view",
      accounts: isAdmin ? "none" : "manage",
      licensing: "view",
    },
    scope: {
      is_platform: false,
      partner_ids: ["partner-1"],
      customer_ids: ["customer-1"],
    },
    branding: {
      product_name: "Aetherix",
      tagline: "MSP Console",
      primary_color: "#0b6b57",
      accent_color: "#0b6b57",
      logo_url: null,
      support_email: null,
      support_url: null,
      footer_note: null,
      source: "platform",
    },
  };
}

export function App() {
  const [me, setMe] = useState<MeResponse | null>(() => {
    if (isHarness) {
      return mockedMe(harnessRole);
    }
    return null;
  });
  const [page, setPage] = useState<Page>(() => {
    if (isHarness) {
      return harnessPage;
    }
    return "dashboard";
  });
  const [editorPolicyId, setEditorPolicyId] = useState<string | null>(null);
  const [branding, setBranding] = useState<Branding>(() => {
    if (isHarness) {
      return mockedMe(harnessRole).branding;
    }
    return DEFAULT_BRANDING;
  });
  const [authStatus, setAuthStatus] = useState<"loading" | "signedIn" | "signedOut">(() => {
    if (isHarness) {
      return "signedIn";
    }
    return "loading";
  });
  const [inviteToken, setInviteToken] = useState<string | null>(INITIAL_INVITE_TOKEN);
  const [railCollapsed, setRailCollapsed] = useState(false);
  const [expandedNavGroups, setExpandedNavGroups] = useState<Record<string, boolean>>(() =>
    Object.fromEntries(NAV.map((section) => [section.group, true])),
  );

  useEffect(() => {
    const onHashChange = () => setInviteToken(parseInviteToken(window.location.hash));
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

  useEffect(() => {
    function onNavigate(event: Event) {
      const custom = event as CustomEvent<{ page?: Page; policyId?: string | null }>;
      const detail = custom.detail;
      if (!detail?.page) return;
      if (detail.page !== "policyEditor" && !navItemFor(detail.page)) return;

      setPage(detail.page);
      if (detail.page === "policyEditor") {
        setEditorPolicyId(detail.policyId ?? null);
      } else {
        setEditorPolicyId(null);
      }
    }
    window.addEventListener("aetherix:navigate", onNavigate as EventListener);
    return () => window.removeEventListener("aetherix:navigate", onNavigate as EventListener);
  }, []);

  const loadMe = useCallback(async () => {
    if (isHarness) {
      return;
    }
    if (!getAccessToken()) {
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
      // Stored token is stale/invalid — drop it and force re-login.
      apiLogout();
      setMe(null);
      setBranding(DEFAULT_BRANDING);
      setAuthStatus("signedOut");
    }
  }, []);

  useEffect(() => {
    queueMicrotask(() => void loadMe());
    const onAuthChange = () => {
      void loadMe();
    };
    window.addEventListener("aetherix:auth-changed", onAuthChange);
    window.addEventListener("storage", onAuthChange);
    return () => {
      window.removeEventListener("aetherix:auth-changed", onAuthChange);
      window.removeEventListener("storage", onAuthChange);
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
    <main className={railCollapsed ? "shell railCollapsed" : "shell"}>
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
          <button
            className="railCollapseButton"
            type="button"
            aria-label={railCollapsed ? "Expand navigation" : "Collapse navigation"}
            title={railCollapsed ? "Expand navigation" : "Collapse navigation"}
            onClick={() => setRailCollapsed((current) => !current)}
          >
            {railCollapsed ? <ChevronRight size={16} /> : <ChevronLeft size={16} />}
          </button>
        </div>
        {visibleNav.map((section) => (
          <nav className="navGroup" key={section.group} aria-label={section.group}>
            <button
              className="navGroupToggle"
              type="button"
              aria-expanded={expandedNavGroups[section.group] ?? true}
              onClick={() => setExpandedNavGroups((current) => ({
                ...current,
                [section.group]: !(current[section.group] ?? true),
              }))}
            >
              <span>{section.group}</span>
              {(expandedNavGroups[section.group] ?? true) ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
            </button>
            {railCollapsed || (expandedNavGroups[section.group] ?? true) ? (
              <div className="navGroupItems">
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
              </div>
            ) : null}
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

      <section className={`workspace ${page === "policies" || page === "installers" ? "policyWorkspace" : ""}`}>
     <ImpersonationBanner />
     {!pageAllowed ? (
       <ForbiddenPage />
     ) : (
       <>
         {page === "dashboard" && <DashboardPage />}
         {page === "alerts" && <AlertsPage />}
          {page === "search" && <SearchPage me={me} />}
         {page === "threatsXplorer" && <DlpScanPage />}
         {page === "policies" && <PolicyPage />}
         {page === "antimalware" && <AntimalwareBehaviorPage me={me} />}
         {page === "customRules" && <CustomDetectionRulesPage me={me} />}
         {page === "installers" && <EnrollmentPage />}
         {page === "companies" && <CompaniesPage />}
         {page === "accounts" && <AccountsPage />}
         {page === "compliance" && <CompliancePage />}
         {page === "digitalRisk" && <DigitalRiskPage me={me} />}
          {page === "executiveSummary" && <ExecutiveSummaryPage me={me} />}
          {page === "healthAttackSurface" && <HealthAttackSurfacePage me={me} />}
         {page === "blocklist" && <BlocklistPage me={me} />}
         {page === "riskManagement" && <RiskManagementPage me={me} />}
         {page === "quarantine" && <QuarantinePage me={me} />}
         {page === "webProtection" && <WebProtectionPage me={me} />}
         {page === "deviceControl" && <DeviceControlPage me={me} />}
         {page === "reports" && <ReportsPage me={me} />}
         {page === "policyAssignments" && <PolicyAssignmentsPage me={me} />}
         {page === "policyEditor" && (
           <PolicyEditorPage 
             me={me} 
             mode={editorPolicyId ? "edit" : "new"}
             policyId={editorPolicyId} 
             onBack={() => setPage("policies")} 
           />
         )}
         {page === "network" && <NetworkPage me={me} />}
         {page === "actionQueue" && <ActionQueuePage me={me} />}
         {page === "configuration" && <ConfigurationPage me={me} />}
         {page === "agenticAi" && <AgenticAiPage me={me} />}
         {page === "dataInsights" && <DataInsightsPage me={me} />}
         {page === "integrations" && <IntegrationsPage me={me} />}
         {page === "sandbox" && <SandboxPage me={me} />}
         {page === "emailSecurity" && <EmailSecurityPage me={me} />}
         {page === "mobileSecurity" && <MobileSecurityPage me={me} />}
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
