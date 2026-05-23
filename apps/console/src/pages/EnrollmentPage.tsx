import { FormEvent, useEffect, useMemo, useRef, useState } from "react";
import { Check, ChevronDown, ChevronRight, CirclePlus, Copy, Download, Link as LinkIcon, RefreshCw, Search } from "lucide-react";
import { apiGet, apiPost, apiPut } from "../api";
import type { Customer, CustomerQuickCreateResult, CustomerUpdatePayload, InstallerBuild, InstallerPlatform, PolicyPackage, QuickDeployLink } from "../api";
import { EmptyState, ErrorBanner, LoadingRow, SuccessBanner } from "../components";
import { formatDate } from "../utils";

const PLATFORM_OPTIONS: { value: InstallerPlatform; label: string; suffix: string }[] = [
  { value: "windows_msi", label: "Windows MSI", suffix: "MSI" },
  { value: "windows_exe", label: "Windows EXE", suffix: "EXE" },
  { value: "macos_pkg", label: "macOS PKG", suffix: "PKG" },
  { value: "linux_deb", label: "Linux DEB", suffix: "DEB" },
  { value: "linux_rpm", label: "Linux RPM", suffix: "RPM" },
];

const COMPANY_SIZES = ["1-10", "11-50", "51-250", "251-1000", "1000+"] as const;
type CompanySize = (typeof COMPANY_SIZES)[number];

type DeploymentSection =
  | "details"
  | "policy"
  | "agentGeneral"
  | "agentCommunication"
  | "agentUpdate"
  | "agentNotifications"
  | "platforms";

const SECTION_TITLE: Record<DeploymentSection, string> = {
  details: "Company Details",
  policy: "Policy Package",
  agentGeneral: "General",
  agentCommunication: "Communication",
  agentUpdate: "Update",
  agentNotifications: "Notifications",
  platforms: "Installer Platforms",
};

const AGENT_SECTIONS: DeploymentSection[] = ["agentGeneral", "agentCommunication", "agentUpdate", "agentNotifications"];
const WIDE_SECTIONS: DeploymentSection[] = ["agentCommunication", "agentUpdate", "platforms"];

type DeploymentDraft = {
  name: string;
  industry: string;
  country: string;
  company_size: CompanySize;
  policy_package_id: string;
  platforms: InstallerPlatform[];
  update_channel: "stable" | "slow" | "fast";
  update_interval_hours: number;
  proxy_enabled: boolean;
  proxy_server: string;
  proxy_port: string;
  silent_mode: boolean;
  show_alerts: boolean;
  telemetry_enabled: boolean;
};

type DeploymentResult = {
  customer: Customer;
  policyName: string;
  installers: InstallerBuild[];
  quick_deploy_links: QuickDeployLink[];
};

function defaultDraft(): DeploymentDraft {
  return {
    name: "",
    industry: "Professional Services",
    country: "US",
    company_size: "11-50",
    policy_package_id: "",
    platforms: ["windows_msi", "macos_pkg"],
    update_channel: "stable",
    update_interval_hours: 1,
    proxy_enabled: false,
    proxy_server: "",
    proxy_port: "8080",
    silent_mode: false,
    show_alerts: true,
    telemetry_enabled: false,
  };
}

function platformLabel(platform: InstallerPlatform | null): string {
  return PLATFORM_OPTIONS.find((p) => p.value === platform)?.label ?? "Installer";
}

function CopyButton({ value, label = "Copy" }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  function copy() {
    void navigator.clipboard.writeText(value).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1600);
    });
  }
  return (
    <button type="button" className="btnSecondary" onClick={copy} aria-label={label}>
      {copied ? <Check size={16} /> : <Copy size={16} />}
      {copied ? "Copied" : label}
    </button>
  );
}

export function EnrollmentPage() {
  const [viewMode, setViewMode] = useState<"catalog" | "detail">("catalog");
  const [detailMode, setDetailMode] = useState<"new" | "existing">("new");
  const [section, setSection] = useState<DeploymentSection>("details");
  const [agentExpanded, setAgentExpanded] = useState(true);
  const [customers, setCustomers] = useState<Customer[]>([]);
  const [policyPackages, setPolicyPackages] = useState<PolicyPackage[]>([]);
  const [selectedCustomer, setSelectedCustomer] = useState<Customer | null>(null);
  const [draft, setDraft] = useState<DeploymentDraft>(defaultDraft());
  const [isLoading, setIsLoading] = useState(true);
  const [isWorking, setIsWorking] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [result, setResult] = useState<DeploymentResult | null>(null);
  const [filterQuery, setFilterQuery] = useState("");
  const mountedRef = useRef(true);

  async function load() {
    try {
      const [nextCustomers, nextPackages] = await Promise.all([
        apiGet<Customer[]>("/customers"),
        apiGet<PolicyPackage[]>("/policy-packages"),
      ]);
      if (!mountedRef.current) return;
      setCustomers(nextCustomers);
      setPolicyPackages(nextPackages);
      setDraft((prev) => ({ ...prev, policy_package_id: prev.policy_package_id || nextPackages[0]?.id || "" }));
      setError(null);
    } catch (err) {
      if (mountedRef.current) setError(err instanceof Error ? err.message : "Failed to load deployment data");
    } finally {
      if (mountedRef.current) setIsLoading(false);
    }
  }

  useEffect(() => {
    mountedRef.current = true;
    void load();
    return () => { mountedRef.current = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function openNew() {
    const next = defaultDraft();
    next.policy_package_id = policyPackages[0]?.id ?? "";
    setDraft(next);
    setSelectedCustomer(null);
    setDetailMode("new");
    setSection("details");
    setError(null);
    setSuccess(null);
    setViewMode("detail");
  }

  function openExisting(customer: Customer) {
    setDraft({
      name: customer.name,
      industry: customer.industry ?? "Professional Services",
      country: customer.country ?? "US",
      company_size: (customer.company_size as CompanySize) ?? "11-50",
      policy_package_id: customer.assigned_policy_package_id ?? policyPackages[0]?.id ?? "",
      platforms: ["windows_msi", "macos_pkg"],
      update_channel: "stable",
      update_interval_hours: 1,
      proxy_enabled: false,
      proxy_server: "",
      proxy_port: "8080",
      silent_mode: false,
      show_alerts: true,
      telemetry_enabled: false,
    });
    setSelectedCustomer(customer);
    setDetailMode("existing");
    setSection("details");
    setError(null);
    setSuccess(null);
    setViewMode("detail");
  }

  function closeDetail() {
    setViewMode("catalog");
    setError(null);
    setSuccess(null);
  }

  function setDraftField<K extends keyof DeploymentDraft>(key: K, value: DeploymentDraft[K]) {
    setDraft((prev) => ({ ...prev, [key]: value }));
  }

  function togglePlatform(platform: InstallerPlatform) {
    setDraft((prev) => ({
      ...prev,
      platforms: prev.platforms.includes(platform)
        ? prev.platforms.length === 1
          ? prev.platforms
          : prev.platforms.filter((p) => p !== platform)
        : [...prev.platforms, platform],
    }));
  }

  async function handleSave(event: FormEvent) {
    event.preventDefault();
    if (!draft.name.trim()) { setError("Company name is required"); return; }
    setError(null); setSuccess(null); setIsWorking(true);
    try {
      if (detailMode === "new") {
        const created = await apiPost<CustomerQuickCreateResult>("/customers/quick-create", {
          name: draft.name.trim(),
          industry: draft.industry.trim() || null,
          country: draft.country.trim() || null,
          company_size: draft.company_size,
          policy_package_id: draft.policy_package_id || null,
          platforms: draft.platforms,
          installer_ttl_seconds: 86_400,
          created_by: "msp-admin",
        });
        setResult({
          customer: created.customer,
          policyName: created.assignment.policy_name,
          installers: created.installers,
          quick_deploy_links: created.quick_deploy_links,
        });
        await load();
        closeDetail();
        setSuccess(`${created.customer.name} is ready for deployment.`);
      } else if (selectedCustomer) {
        const payload: CustomerUpdatePayload = {
          name: draft.name.trim(),
          industry: draft.industry.trim() || null,
          country: draft.country.trim() || null,
          company_size: draft.company_size,
          policy_package_id: draft.policy_package_id || null,
          updated_by: "msp-admin",
        };
        const updated = await apiPut<Customer>(`/customers/${selectedCustomer.id}`, payload);
        setSelectedCustomer(updated);
        setCustomers((prev) => prev.map((c) => (c.id === updated.id ? updated : c)));
        setSuccess(`${updated.name} updated.`);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Operation failed");
    } finally {
      setIsWorking(false);
    }
  }

  async function handleGenerate() {
    if (!selectedCustomer) return;
    setError(null); setSuccess(null); setIsWorking(true);
    try {
      const payload: CustomerUpdatePayload = {
        name: draft.name.trim(),
        industry: draft.industry.trim() || null,
        country: draft.country.trim() || null,
        company_size: draft.company_size,
        policy_package_id: draft.policy_package_id || null,
        updated_by: "msp-admin",
      };
      const updated = await apiPut<Customer>(`/customers/${selectedCustomer.id}`, payload);
      const body = { platforms: draft.platforms, ttl_seconds: 86_400, created_by: "msp-admin" };
      const [installers, links] = await Promise.all([
        apiPost<InstallerBuild[]>(`/customers/${updated.id}/installers`, body),
        apiPost<QuickDeployLink[]>(`/customers/${updated.id}/quick-deploy`, body),
      ]);
      setResult({
        customer: updated,
        policyName: updated.assigned_policy_name ?? "No policy",
        installers,
        quick_deploy_links: links,
      });
      await load();
      closeDetail();
      setSuccess(`${updated.name} installers generated.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Generate failed");
    } finally {
      setIsWorking(false);
    }
  }

  const filteredCustomers = useMemo(() => {
    const q = filterQuery.trim().toLowerCase();
    if (!q) return customers;
    return customers.filter((c) =>
      `${c.name} ${c.customer_number} ${c.industry ?? ""} ${c.company_size ?? ""}`.toLowerCase().includes(q),
    );
  }, [customers, filterQuery]);

  const selectedPackage = useMemo(
    () => policyPackages.find((p) => p.id === draft.policy_package_id) ?? policyPackages[0] ?? null,
    [policyPackages, draft.policy_package_id],
  );

  const currentTitle = detailMode === "new" ? "New Deployment" : (selectedCustomer?.name ?? "Deployment");
  const sectionParent = AGENT_SECTIONS.includes(section) ? "Agent" : "General";
  const isWideSection = WIDE_SECTIONS.includes(section);

  // ─── DETAIL VIEW ─────────────────────────────────────────────────────────
  if (viewMode === "detail") {
    return (
      <div className="policyDetailPage">
        <aside className="policyDetailSidebar" aria-label="Deployment settings">
          <div className="policyDetailSearch">
            <input placeholder="Search settings" aria-label="Search" />
          </div>
          <nav>
            <section>
              <h2>General</h2>
              <button
                type="button"
                className={section === "details" ? "active" : ""}
                onClick={() => setSection("details")}
              >
                Company
              </button>
              <button
                type="button"
                className={section === "policy" ? "active" : ""}
                onClick={() => setSection("policy")}
              >
                Policy package
              </button>
              <button
                type="button"
                className={section === "platforms" ? "active" : ""}
                onClick={() => setSection("platforms")}
              >
                Installer platforms
                <span>{draft.platforms.length}/{PLATFORM_OPTIONS.length}</span>
              </button>
            </section>
            <section>
              <h2>Agent</h2>
              <button
                type="button"
                className={AGENT_SECTIONS.includes(section) ? "active" : ""}
                aria-expanded={agentExpanded}
                onClick={() => {
                  if (!agentExpanded) setSection("agentGeneral");
                  setAgentExpanded((v) => !v);
                }}
              >
                Agent configuration
                <span style={{ display: "flex", alignItems: "center" }}>
                  {agentExpanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                </span>
              </button>
              {agentExpanded ? (
                <div className="policySidebarChildren">
                  <button
                    type="button"
                    className={section === "agentGeneral" ? "active" : ""}
                    onClick={() => setSection("agentGeneral")}
                  >
                    General
                  </button>
                  <button
                    type="button"
                    className={section === "agentCommunication" ? "active" : ""}
                    onClick={() => setSection("agentCommunication")}
                  >
                    Communication
                  </button>
                  <button
                    type="button"
                    className={section === "agentUpdate" ? "active" : ""}
                    onClick={() => setSection("agentUpdate")}
                  >
                    Update
                  </button>
                  <button
                    type="button"
                    className={section === "agentNotifications" ? "active" : ""}
                    onClick={() => setSection("agentNotifications")}
                  >
                    Notifications
                  </button>
                </div>
              ) : null}
            </section>
          </nav>
        </aside>

        <form className="policyDetailWorkspace" onSubmit={handleSave}>
          <header className="policyDetailHeader">
            <div className="policyDetailCrumbs">
              <button type="button" onClick={closeDetail}>Installers</button>
              <span>/</span>
              <button type="button" onClick={closeDetail}>{currentTitle}</button>
              <span>/</span>
              <strong>{SECTION_TITLE[section]}</strong>
            </div>
            <a href="https://support.aetherix.local" target="_blank" rel="noreferrer">
              Get help from Support Center
            </a>
          </header>

          {error ? <ErrorBanner message={error} /> : null}
          {success ? <SuccessBanner message={success} /> : null}

          <main className={`policyDetailContent ${isWideSection ? "wide" : ""}`}>

            {/* ── Company Details ── */}
            {section === "details" ? (
              <section className="policyDetailSection policyAgentBlock">
                <h1>Company Details</h1>
                <p>Configure the company information for this managed deployment.</p>
                <label className="policyDetailField">
                  <span>Company name*:</span>
                  <input
                    required
                    value={draft.name}
                    onChange={(e) => setDraftField("name", e.target.value)}
                    placeholder="Northwind Dental"
                    maxLength={160}
                    autoFocus
                  />
                </label>
                <label className="policyDetailField">
                  <span>Industry:</span>
                  <input
                    value={draft.industry}
                    onChange={(e) => setDraftField("industry", e.target.value)}
                    maxLength={80}
                  />
                </label>
                <label className="policyDetailField">
                  <span>Country:</span>
                  <input
                    value={draft.country}
                    onChange={(e) => setDraftField("country", e.target.value)}
                    maxLength={80}
                  />
                </label>
                <label className="policyDetailField">
                  <span>Company size:</span>
                  <select
                    value={draft.company_size}
                    onChange={(e) => setDraftField("company_size", e.target.value as CompanySize)}
                  >
                    {COMPANY_SIZES.map((s) => (
                      <option key={s} value={s}>{s} endpoints</option>
                    ))}
                  </select>
                </label>
                {detailMode === "existing" && selectedCustomer ? (
                  <div className="policyHistoryBlock" style={{ marginTop: 28 }}>
                    <h2>Deployment info</h2>
                    <dl>
                      <div><dt>Customer #:</dt><dd>{selectedCustomer.customer_number}</dd></div>
                      <div><dt>Status:</dt><dd>{selectedCustomer.status ?? "Active"}</dd></div>
                      <div><dt>Assigned policy:</dt><dd>{selectedCustomer.assigned_policy_name ?? "No policy"}</dd></div>
                    </dl>
                  </div>
                ) : null}
              </section>
            ) : null}

            {/* ── Policy Package ── */}
            {section === "policy" ? (
              <section className="policyDetailSection policyAgentBlock">
                <h1>Policy Package</h1>
                <p>Assign a policy package to pre-configure protection modules for this deployment.</p>
                <label className="policyDetailField">
                  <span>Policy package:</span>
                  <select
                    value={draft.policy_package_id}
                    onChange={(e) => setDraftField("policy_package_id", e.target.value)}
                    disabled={policyPackages.length === 0}
                  >
                    {policyPackages.map((pkg) => (
                      <option key={pkg.id} value={pkg.id}>{pkg.name}</option>
                    ))}
                  </select>
                </label>
                {selectedPackage ? (
                  <div className="policyAgentSubsection" style={{ marginTop: 16 }}>
                    <label className="policyInlineField">
                      <span>Version:</span>
                      <input readOnly value={`v${selectedPackage.version}`} />
                    </label>
                    <label className="policyInlineField">
                      <span>DLP rules:</span>
                      <input
                        readOnly
                        value={String(
                          Array.isArray(selectedPackage.payload.dlp_rules)
                            ? selectedPackage.payload.dlp_rules.length
                            : 0,
                        )}
                      />
                    </label>
                    <label className="policyInlineField">
                      <span>Hardening:</span>
                      <input readOnly value={selectedPackage.payload.hardening_rules ? "Enabled" : "Custom"} />
                    </label>
                  </div>
                ) : null}
              </section>
            ) : null}

            {/* ── Installer Platforms ── */}
            {section === "platforms" ? (
              <section className="policyDetailSection policyAgentBlock wideAgent">
                <h1>Installer Platforms</h1>
                <p>Select the operating system platforms for which installers will be generated.</p>
                <div className="policyAccordionList dark" style={{ marginTop: 16 }}>
                  {PLATFORM_OPTIONS.map((platform) => (
                    <article key={platform.value} className="policyModuleCard">
                      <button
                        type="button"
                        className="policyModuleHead"
                        onClick={() => togglePlatform(platform.value)}
                      >
                        <span>
                          <strong>{platform.label}</strong>
                          <small>.{platform.suffix.toLowerCase()} installer package</small>
                        </span>
                        <span className="policyModuleHeadRight">
                          <label className="toggleRow" onClick={(e) => e.stopPropagation()}>
                            <input
                              type="checkbox"
                              checked={draft.platforms.includes(platform.value)}
                              onChange={() => togglePlatform(platform.value)}
                            />
                            {draft.platforms.includes(platform.value) ? "Included" : "Excluded"}
                          </label>
                        </span>
                      </button>
                    </article>
                  ))}
                </div>
              </section>
            ) : null}

            {/* ── Agent General ── */}
            {section === "agentGeneral" ? (
              <section className="policyDetailSection policyAgentBlock">
                <h1>General</h1>
                <p>Configure general agent settings including the update ring and telemetry.</p>
                <div className="policyAgentStack">
                  <label className="policyInlineField">
                    <span>Update channel:</span>
                    <select
                      value={draft.update_channel}
                      onChange={(e) =>
                        setDraftField("update_channel", e.target.value as DeploymentDraft["update_channel"])
                      }
                    >
                      <option value="stable">Stable</option>
                      <option value="slow">Slow ring</option>
                      <option value="fast">Fast ring</option>
                    </select>
                  </label>
                  <label
                    className="policySwitchRow"
                    onClick={() => setDraftField("telemetry_enabled", !draft.telemetry_enabled)}
                  >
                    <span className={`policySwitch ${draft.telemetry_enabled ? "on" : ""}`} aria-hidden="true" />
                    Security Telemetry
                  </label>
                  <p>Export security event raw data to SIEM solutions for advanced analysis and correlation.</p>
                </div>
              </section>
            ) : null}

            {/* ── Agent Communication ── */}
            {section === "agentCommunication" ? (
              <section className="policyDetailSection policyAgentBlock wideAgent">
                <h1>Communication</h1>
                <p>Configure proxy and relay communication settings for managed endpoints.</p>
                <div className="policyAgentStack">
                  <h2>Proxy configuration</h2>
                  <label
                    className="policySwitchRow"
                    onClick={() => setDraftField("proxy_enabled", !draft.proxy_enabled)}
                  >
                    <span className={`policySwitch ${draft.proxy_enabled ? "on" : ""}`} aria-hidden="true" />
                    Enable proxy
                  </label>
                  <label className="policyInlineField">
                    <span>Server:</span>
                    <input
                      value={draft.proxy_server}
                      onChange={(e) => setDraftField("proxy_server", e.target.value)}
                      placeholder="http://proxy"
                      disabled={!draft.proxy_enabled}
                    />
                  </label>
                  <label className="policyInlineField">
                    <span>Port:</span>
                    <input
                      type="number"
                      value={draft.proxy_port}
                      onChange={(e) => setDraftField("proxy_port", e.target.value)}
                      disabled={!draft.proxy_enabled}
                    />
                  </label>
                </div>
                <div className="policyAgentSubsection">
                  <h2>Communication between endpoints and Cloud Services</h2>
                  <label className="policyRadioRow">
                    <input type="radio" name="cloudProxy" defaultChecked /> Use previous settings
                  </label>
                  <label className="policyRadioRow">
                    <input type="radio" name="cloudProxy" /> Autodetect proxy settings
                  </label>
                  <label className="policyRadioRow">
                    <input type="radio" name="cloudProxy" /> Do not use proxy
                  </label>
                </div>
              </section>
            ) : null}

            {/* ── Agent Update ── */}
            {section === "agentUpdate" ? (
              <section className="policyDetailSection policyAgentBlock wideAgent">
                <h1>Update</h1>
                <p>Configure how the security agent downloads and installs updates.</p>
                <h2>Scheduler</h2>
                <label className="policyInlineField">
                  <span>Check for updates every (hours):</span>
                  <input
                    type="number"
                    value={draft.update_interval_hours}
                    onChange={(e) => setDraftField("update_interval_hours", Number(e.target.value))}
                    min={1}
                    max={72}
                  />
                </label>
                <label className="policyInlineField">
                  <span>Update ring:</span>
                  <select
                    value={draft.update_channel}
                    onChange={(e) =>
                      setDraftField("update_channel", e.target.value as DeploymentDraft["update_channel"])
                    }
                  >
                    <option value="slow">Slow ring</option>
                    <option value="stable">Stable</option>
                    <option value="fast">Fast ring</option>
                  </select>
                </label>
                <h2>Update locations</h2>
                <div className="policyUpdateLocation">
                  <input placeholder="Add location" />
                  <label><input type="checkbox" /> Use proxy</label>
                  <button type="button">+</button>
                </div>
                <div className="policyAssignmentTable updateTable">
                  <div>
                    <span>Priority</span>
                    <span>Server</span>
                    <span>Proxy</span>
                    <span>Actions</span>
                  </div>
                  <div>
                    <span>1</span>
                    <span>Aetherix Relay Pool</span>
                    <span><input type="checkbox" /></span>
                    <span>Edit</span>
                  </div>
                </div>
                <label className="policyCheckboxRow">
                  <input type="checkbox" defaultChecked /> Use Aetherix managed update service as fallback
                </label>
              </section>
            ) : null}

            {/* ── Agent Notifications ── */}
            {section === "agentNotifications" ? (
              <section className="policyDetailSection policyAgentBlock">
                <h1>Notifications</h1>
                <p>Customize how the security agent displays notifications on the endpoint.</p>
                <div className="policyAgentStack">
                  <label
                    className="policySwitchRow"
                    onClick={() => setDraftField("silent_mode", !draft.silent_mode)}
                  >
                    <span className={`policySwitch ${!draft.silent_mode ? "on" : ""}`} aria-hidden="true" />
                    Show icon in notification area
                  </label>
                  <p>A system reboot may be required to apply this setting.</p>
                  <label
                    className="policySwitchRow"
                    onClick={() => setDraftField("show_alerts", !draft.show_alerts)}
                  >
                    <span className={`policySwitch ${draft.show_alerts ? "on" : ""}`} aria-hidden="true" />
                    Display alert pop-ups
                  </label>
                  <p>Alert pop-ups require user action. Disabling this option applies the recommended action on the endpoint.</p>
                  <label className="policySwitchRow">
                    <span className="policySwitch" aria-hidden="true" />
                    Display notification pop-ups
                  </label>
                  <p>Notifications provide endpoint users with critical security information without requiring user interaction.</p>
                </div>
              </section>
            ) : null}

          </main>

          <footer className="policyDetailFooter">
            <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
              {detailMode === "existing" ? (
                <button
                  type="button"
                  className="policySaveButton"
                  disabled={isWorking || !draft.name.trim() || draft.platforms.length === 0}
                  onClick={() => void handleGenerate()}
                >
                  {isWorking
                    ? <RefreshCw size={14} style={{ marginRight: 6 }} />
                    : <Download size={14} style={{ marginRight: 6 }} />}
                  Save & Generate
                </button>
              ) : null}
              <button
                className="policySaveButton"
                type="submit"
                disabled={isWorking || !draft.name.trim()}
              >
                {isWorking ? <RefreshCw size={14} style={{ marginRight: 6 }} /> : null}
                {detailMode === "new" ? "Create & Deploy" : "Save changes"}
              </button>
            </div>
            <button className="policyCancelButton" type="button" onClick={closeDetail}>
              Cancel
            </button>
          </footer>
        </form>
      </div>
    );
  }

  // ─── CATALOG VIEW ─────────────────────────────────────────────────────────
  return (
    <div className="policyCatalogPage">
      <header className="policyCatalogTopbar">
        <h1>Installers</h1>
      </header>

      {error ? <ErrorBanner message={error} /> : null}
      {success ? <SuccessBanner message={success} /> : null}

      {result ? (
        <section className="panel deployResult">
          <div className="panelHeader">
            <div>
              <h2>{result.customer.name}</h2>
              <span>{result.customer.customer_number} · {result.policyName}</span>
            </div>
            <div className="panelActions">
              <span className="badge">Ready</span>
              <button type="button" className="btnGhost" onClick={() => setResult(null)} aria-label="Dismiss">
                Dismiss
              </button>
            </div>
          </div>
          <div className="artifactGrid">
            {result.quick_deploy_links.map((link) => (
              <article className="artifactCard" key={link.id}>
                <header>
                  <LinkIcon size={18} />
                  <strong>{platformLabel(link.platform)}</strong>
                </header>
                <code className="tokenValue">{link.url}</code>
                <div className="artifactActions">
                  <CopyButton value={link.url} label="Copy link" />
                  <span>Expires {formatDate(link.expires_at)}</span>
                </div>
              </article>
            ))}
          </div>
          <div className="artifactGrid directInstallers">
            {result.installers.map((installer) => (
              <article className="artifactCard" key={installer.id}>
                <header>
                  <Download size={18} />
                  <strong>{platformLabel(installer.platform)}</strong>
                </header>
                <div className="policyMeta compactMeta">
                  <div className="metaItem">
                    <span>Signing</span>
                    <strong>{installer.signing_status}</strong>
                  </div>
                  <div className="metaItem">
                    <span>SHA-256</span>
                    <code>{installer.artifact_sha256?.slice(0, 16)}...</code>
                  </div>
                </div>
                {installer.enrollment_token ? (
                  <CopyButton value={installer.enrollment_token} label="Copy token" />
                ) : null}
              </article>
            ))}
          </div>
        </section>
      ) : null}

      <section className="policyCatalogPanel" aria-label="Deployments table">
        <div className="policyCatalogToolbar">
          <button className="policyToolbarButton primary" type="button" onClick={openNew}>
            <CirclePlus size={16} /> Add
          </button>
          <button className="policyToolbarButton primary" type="button" onClick={() => void load()}>
            <RefreshCw size={16} /> Refresh
          </button>
          <div className="searchField" style={{ marginLeft: "auto" }}>
            <Search size={14} />
            <input
              placeholder="Search deployments"
              value={filterQuery}
              onChange={(e) => setFilterQuery(e.target.value)}
            />
          </div>
        </div>

        <div className="policyCatalogGrid enrollmentGrid policyCatalogHead">
          <span>Company name</span>
          <span>Customer #</span>
          <span>Industry</span>
          <span>Size</span>
          <span>Assigned policy</span>
        </div>

        {isLoading ? <LoadingRow label="Loading deployments" /> : null}
        {!isLoading && filteredCustomers.length === 0 ? (
          <EmptyState>No deployments match the current filters.</EmptyState>
        ) : null}

        <div className="policyCatalogRows">
          {filteredCustomers.map((customer) => (
            <article
              key={customer.id}
              className="policyCatalogGrid enrollmentGrid policyCatalogRow"
            >
              <button
                type="button"
                className="policyNameLink"
                onClick={() => openExisting(customer)}
              >
                {customer.name}
              </button>
              <span>{customer.customer_number}</span>
              <span>{customer.industry ?? "—"}</span>
              <span>{customer.company_size ?? "—"}</span>
              <span>{customer.assigned_policy_name ?? "No policy"}</span>
            </article>
          ))}
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
              <option value="50">50</option>
            </select>
            <span>rows per page</span>
          </div>
          <span>{filteredCustomers.length} deployment{filteredCustomers.length !== 1 ? "s" : ""}</span>
        </footer>
      </section>
    </div>
  );
}

