import { FormEvent, useEffect, useMemo, useRef, useState } from "react";
import {
  Apple,
  Bell,
  Check,
  ChevronDown,
  Copy,
  Download,
  Filter,
  Gift,
  Link as LinkIcon,
  Monitor,
  Package,
  Search,
  SlidersHorizontal,
  Trash2,
  UserCircle,
  X,
} from "lucide-react";
import { apiGet, apiPost } from "../api";
import type { Customer, CustomerQuickCreateResult, InstallerPlatform, PolicyPackage, QuickDeployLink } from "../api";
import { ErrorBanner, LoadingRow, SuccessBanner } from "../components";

const PLATFORM_OPTIONS: { value: InstallerPlatform; label: string; os: "windows" | "linux" | "macos"; arch: string }[] = [
  { value: "windows_exe", label: "Downloader", os: "windows", arch: "Universal" },
  { value: "windows_msi", label: "Kit", os: "windows", arch: "Intel/AMD x86 64-bit" },
  { value: "linux_deb", label: "Downloader", os: "linux", arch: "Debian/Ubuntu" },
  { value: "linux_rpm", label: "Kit", os: "linux", arch: "RHEL/Fedora" },
  { value: "macos_pkg", label: "Downloader", os: "macos", arch: "Apple M series / Intel" },
];

const MODULES = [
  { id: "antimalware", label: "Antimalware", os: ["windows", "macos", "linux"] },
  { id: "advanced-threat", label: "Advanced Threat Control", os: ["windows", "macos", "linux"] },
  { id: "anti-exploit", label: "Advanced Anti-Exploit", os: ["windows", "linux"] },
  { id: "firewall", label: "Firewall", os: ["windows", "macos"] },
  { id: "network", label: "Network Protection", os: ["windows", "macos"] },
  { id: "content", label: "Content Control", os: ["windows", "macos"] },
  { id: "antiphishing", label: "Antiphishing", os: ["windows", "macos"] },
  { id: "web-scan", label: "Web Traffic Scan", os: ["windows", "macos"] },
  { id: "network-defense", label: "Network Attack Defense", os: ["windows", "macos", "linux"] },
  { id: "device", label: "Device Control", os: ["windows", "macos"] },
  { id: "power-user", label: "Power User", os: ["windows"] },
  { id: "encryption", label: "Encryption", os: ["windows", "macos"] },
  { id: "patch", label: "Patch Management", os: ["windows", "macos", "linux"] },
  { id: "integrity", label: "Integrity Monitoring", os: ["windows", "linux"] },
  { id: "sensor", label: "Endpoint Detection Sensor", os: ["windows", "macos", "linux"] },
  { id: "dlp", label: "Data Loss Prevention", os: ["windows", "macos"] },
];

const DEFAULT_MODULES = new Set(["antimalware", "advanced-threat", "anti-exploit", "firewall", "network", "content", "antiphishing", "web-scan", "network-defense"]);

type PackageRow = {
  id: string;
  name: string;
  type: string;
  language: string;
  description: string;
  company: string;
  customer: Customer;
};

type Draft = {
  name: string;
  description: string;
  language: string;
  customerId: string;
  companyName: string;
  operationMode: "detect_prevent" | "detect_only" | "monitor";
  modules: string[];
  roles: string[];
};

function defaultDraft(customers: Customer[]): Draft {
  const first = customers[0];
  return {
    name: "",
    description: "",
    language: "English",
    customerId: first?.id ?? "new",
    companyName: first?.name ?? "",
    operationMode: "detect_prevent",
    modules: Array.from(DEFAULT_MODULES),
    roles: ["workstations", "servers"],
  };
}

function osIcon(os: "windows" | "linux" | "macos") {
  if (os === "macos") return <Apple size={17} />;
  if (os === "linux") return <Package size={16} />;
  return <Monitor size={16} />;
}

function packageType(pkg: PolicyPackage | undefined): string {
  if (!pkg) return "BEST";
  if (pkg.package_type === "custom") return "CUSTOM";
  if (pkg.package_type === "industry") return "INDUSTRY";
  return "BEST";
}

function CopyButton({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      className="installIconButton"
      onClick={() => {
        void navigator.clipboard.writeText(value).then(() => {
          setCopied(true);
          window.setTimeout(() => setCopied(false), 1400);
        });
      }}
      aria-label="Copy download link"
    >
      {copied ? <Check size={14} /> : <Copy size={14} />}
    </button>
  );
}

export function EnrollmentPage() {
  const [customers, setCustomers] = useState<Customer[]>([]);
  const [policyPackages, setPolicyPackages] = useState<PolicyPackage[]>([]);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [companyFilter, setCompanyFilter] = useState("all");
  const [nameFilter, setNameFilter] = useState("");
  const [descriptionFilter, setDescriptionFilter] = useState("");
  const [typeFilter, setTypeFilter] = useState("all");
  const [downloadOpen, setDownloadOpen] = useState(false);
  const [createOpen, setCreateOpen] = useState(false);
  const [draft, setDraft] = useState<Draft>(() => defaultDraft([]));
  const [quickLinks, setQuickLinks] = useState<QuickDeployLink[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isWorking, setIsWorking] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
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
      setError(null);
    } catch (err) {
      if (mountedRef.current) setError(err instanceof Error ? err.message : "Failed to load installation packages");
    } finally {
      if (mountedRef.current) setIsLoading(false);
    }
  }

  useEffect(() => {
    mountedRef.current = true;
    void load();
    return () => { mountedRef.current = false; };
  }, []);

  const rows = useMemo<PackageRow[]>(() => {
    return customers.map((customer) => {
      const pkg = policyPackages.find((item) => item.id === customer.assigned_policy_package_id);
      return {
        id: customer.id,
        name: customer.assigned_policy_name ? `${customer.assigned_policy_name} Package` : `${customer.name} Installation Package`,
        type: packageType(pkg),
        language: "English",
        description: pkg?.description || customer.industry || "N/A",
        company: customer.name,
        customer,
      };
    });
  }, [customers, policyPackages]);

  const filteredRows = useMemo(() => {
    return rows.filter((row) => {
      const matchesCompany = companyFilter === "all" || row.customer.id === companyFilter;
      const matchesName = row.name.toLowerCase().includes(nameFilter.trim().toLowerCase());
      const matchesDescription = row.description.toLowerCase().includes(descriptionFilter.trim().toLowerCase());
      const matchesType = typeFilter === "all" || row.type === typeFilter;
      return matchesCompany && matchesName && matchesDescription && matchesType;
    });
  }, [companyFilter, descriptionFilter, nameFilter, rows, typeFilter]);

  const selectedRows = rows.filter((row) => selectedIds.has(row.id));
  const activeRow = selectedRows[0] ?? filteredRows[0] ?? null;
  const allVisibleSelected = filteredRows.length > 0 && filteredRows.every((row) => selectedIds.has(row.id));

  function toggleSelection(id: string) {
    setSelectedIds((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function resetFilters() {
    setCompanyFilter("all");
    setNameFilter("");
    setDescriptionFilter("");
    setTypeFilter("all");
  }

  function openCreate() {
    setDraft(defaultDraft(customers));
    setQuickLinks([]);
    setError(null);
    setSuccess(null);
    setCreateOpen(true);
  }

  function setDraftField<K extends keyof Draft>(key: K, value: Draft[K]) {
    setDraft((current) => ({ ...current, [key]: value }));
  }

  function toggleModule(id: string) {
    setDraft((current) => ({
      ...current,
      modules: current.modules.includes(id)
        ? current.modules.filter((item) => item !== id)
        : [...current.modules, id],
    }));
  }

  async function createPackage(event: FormEvent) {
    event.preventDefault();
    if (!draft.name.trim()) {
      setError("Package name is required.");
      return;
    }
    if (draft.customerId === "new" && !draft.companyName.trim()) {
      setError("Company name is required for a new company package.");
      return;
    }

    setIsWorking(true);
    setError(null);
    setSuccess(null);
    try {
      const selectedCustomer = customers.find((customer) => customer.id === draft.customerId);
      const created = await apiPost<CustomerQuickCreateResult>("/customers/quick-create", {
        name: selectedCustomer?.name ?? draft.companyName.trim(),
        industry: draft.description.trim() || selectedCustomer?.industry || null,
        country: selectedCustomer?.country || "US",
        company_size: selectedCustomer?.company_size || "11-50",
        policy_package_id: policyPackages[0]?.id ?? null,
        platforms: PLATFORM_OPTIONS.map((platform) => platform.value),
        installer_ttl_seconds: 86_400,
        created_by: "msp-admin",
        install_profile: {
          display_name: draft.name.trim(),
          description: draft.description.trim() || null,
          language: draft.language,
          operation_mode: draft.operationMode,
          modules: draft.modules,
          roles: draft.roles,
        },
      });
      setQuickLinks(created.quick_deploy_links);
      setSelectedIds(new Set([created.customer.id]));
      await load();
      setSuccess(`${draft.name.trim()} was created and installers are ready.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create installation package");
    } finally {
      setIsWorking(false);
    }
  }

  async function sendLinks() {
    if (!activeRow) return;
    setIsWorking(true);
    setError(null);
    setSuccess(null);
    try {
      const links = await apiPost<QuickDeployLink[]>(`/customers/${activeRow.customer.id}/quick-deploy`, {
        platforms: PLATFORM_OPTIONS.map((platform) => platform.value),
        ttl_seconds: 86_400,
        created_by: "msp-admin",
      });
      setQuickLinks(links);
      setSuccess(`Download links prepared for ${activeRow.company}.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to prepare download links");
    } finally {
      setIsWorking(false);
    }
  }

  function deleteSelected() {
    if (selectedIds.size === 0) return;
    setCustomers((current) => current.filter((customer) => !selectedIds.has(customer.id)));
    setSelectedIds(new Set());
    setSuccess("Selected packages removed from this view. Backend deletion is not wired for installer packages yet.");
  }

  return (
    <main className="installPackagesPage">
      <div className="installUtilityBar" aria-label="Console utilities">
        <button type="button" aria-label="User"><UserCircle size={15} /></button>
        <button type="button" aria-label="Promotions"><Gift size={15} /></button>
        <button type="button" aria-label="Notifications"><Bell size={15} /></button>
      </div>

      <header className="installHeader">
        <h1>Installation packages</h1>
        <div>
          <button type="button" className="installTinyButton" onClick={resetFilters}>Reset view</button>
          <button type="button" className="installIconButton active" aria-label="Filters"><Filter size={15} /></button>
          <button type="button" className="installIconButton" aria-label="View settings"><SlidersHorizontal size={15} /></button>
        </div>
      </header>

      {error ? <ErrorBanner message={error} /> : null}
      {success ? <SuccessBanner message={success} /> : null}

      <section className="installToolbar" aria-label="Installation package actions">
        <button type="button" className="installPrimary" onClick={openCreate}>Create</button>
        <div className="installDownloadWrap">
          <button type="button" className="installTextButton" onClick={() => setDownloadOpen((open) => !open)} disabled={!activeRow}>
            Download <ChevronDown size={14} />
          </button>
          {downloadOpen && activeRow ? (
            <div className="installDownloadMenu">
              <label className="installFlyoutSearch">
                <input aria-label="Search installer downloads" />
                <Search size={15} />
              </label>
              {(["windows", "linux", "macos"] as const).map((os) => (
                <div className="installDownloadColumn" key={os}>
                  <h2>{osIcon(os)} {os === "macos" ? "macOS" : os[0].toUpperCase() + os.slice(1)} installers</h2>
                  {PLATFORM_OPTIONS.filter((platform) => platform.os === os).map((platform) => (
                    <a key={platform.value} href="#" onClick={(event) => event.preventDefault()}>
                      <span>{platform.label}</span>
                      <small>{platform.arch}</small>
                      <Check size={13} />
                    </a>
                  ))}
                </div>
              ))}
            </div>
          ) : null}
        </div>
        <button type="button" className="installTextButton" onClick={sendLinks} disabled={!activeRow || isWorking}>
          Send download links
        </button>
        <button type="button" className="installDanger" onClick={deleteSelected} disabled={selectedIds.size === 0}>
          <Trash2 size={13} /> Delete
        </button>
      </section>

      <section className="installFilters" aria-label="Filters">
        <label>
          <span>Company</span>
          <select value={companyFilter} onChange={(event) => setCompanyFilter(event.target.value)}>
            <option value="all">All</option>
            {customers.map((customer) => <option key={customer.id} value={customer.id}>{customer.name}</option>)}
          </select>
        </label>
        <label>
          <span>Name</span>
          <input value={nameFilter} onChange={(event) => setNameFilter(event.target.value)} />
          <Search size={14} />
        </label>
        <label>
          <span>Description</span>
          <input value={descriptionFilter} onChange={(event) => setDescriptionFilter(event.target.value)} />
          <Search size={14} />
        </label>
        <label>
          <span>Type</span>
          <select value={typeFilter} onChange={(event) => setTypeFilter(event.target.value)}>
            <option value="all">All</option>
            <option value="BEST">BEST</option>
            <option value="CUSTOM">CUSTOM</option>
            <option value="INDUSTRY">INDUSTRY</option>
          </select>
        </label>
        <button type="button" onClick={resetFilters}>Reset filters</button>
      </section>

      <section className="installTable" aria-label="Installation packages table">
        <div className="installTableHead">
          <label>
            <input
              type="checkbox"
              checked={allVisibleSelected}
              onChange={() => {
                setSelectedIds((current) => {
                  if (allVisibleSelected) return new Set([...current].filter((id) => !filteredRows.some((row) => row.id === id)));
                  return new Set([...current, ...filteredRows.map((row) => row.id)]);
                });
              }}
            />
            <span>Name</span>
          </label>
          <span>Type</span>
          <span>Language</span>
          <span>Description</span>
          <span>Company</span>
        </div>
        {isLoading ? <LoadingRow label="Loading installation packages" /> : null}
        {!isLoading && filteredRows.length === 0 ? (
          <div className="installEmpty">No installation packages match the current filters.</div>
        ) : null}
        {filteredRows.map((row) => {
          const selected = selectedIds.has(row.id);
          return (
            <button
              type="button"
              key={row.id}
              className={selected ? "installTableRow selected" : "installTableRow"}
              onClick={() => toggleSelection(row.id)}
            >
              <span>
                <input type="checkbox" checked={selected} onChange={() => toggleSelection(row.id)} onClick={(event) => event.stopPropagation()} />
                <strong>{row.name}</strong>
              </span>
              <span>{row.type}</span>
              <span>{row.language}</span>
              <span>{row.description}</span>
              <span>{row.company}</span>
            </button>
          );
        })}
      </section>

      {quickLinks.length > 0 ? (
        <section className="installLinkTray" aria-label="Prepared download links">
          <div>
            <strong>Prepared download links</strong>
            <span>{quickLinks.length} link{quickLinks.length === 1 ? "" : "s"} ready to send</span>
          </div>
          {quickLinks.slice(0, 5).map((link) => (
            <code key={link.id}>{link.platform ?? "any"}: {link.url}<CopyButton value={link.url} /></code>
          ))}
        </section>
      ) : null}

      {createOpen ? (
        <div className="installCreateOverlay" role="dialog" aria-modal="true" aria-label="Create Installation Package">
          <form className="installCreatePanel" onSubmit={createPackage}>
            <header>
              <h2>Create Installation Package</h2>
              <button type="button" className="installIconButton" onClick={() => setCreateOpen(false)} aria-label="Close"><X size={18} /></button>
            </header>
            <div className="installCreateContent">
              <section className="installCreateGeneral">
                <h3>General</h3>
                <label>
                  <span>Name*:</span>
                  <input required value={draft.name} onChange={(event) => setDraftField("name", event.target.value)} placeholder="Type here" autoFocus />
                </label>
                <label>
                  <span>Description:</span>
                  <input value={draft.description} onChange={(event) => setDraftField("description", event.target.value)} placeholder="Type here" />
                </label>
                <label>
                  <span>Language:</span>
                  <select value={draft.language} onChange={(event) => setDraftField("language", event.target.value)}>
                    <option>English</option>
                    <option>Spanish</option>
                    <option>French</option>
                    <option>German</option>
                  </select>
                </label>
                <label>
                  <span>Company*:</span>
                  <select
                    value={draft.customerId}
                    onChange={(event) => {
                      const customer = customers.find((item) => item.id === event.target.value);
                      setDraft((current) => ({ ...current, customerId: event.target.value, companyName: customer?.name ?? "" }));
                    }}
                  >
                    <option value="new">Create new company</option>
                    {customers.map((customer) => <option key={customer.id} value={customer.id}>{customer.name}</option>)}
                  </select>
                </label>
                {draft.customerId === "new" ? (
                  <label>
                    <span>New company:</span>
                    <input value={draft.companyName} onChange={(event) => setDraftField("companyName", event.target.value)} placeholder="Company name" />
                  </label>
                ) : null}

                <h4>Security modules and roles</h4>
                <label>
                  <span>Operation mode:</span>
                  <select value={draft.operationMode} onChange={(event) => setDraftField("operationMode", event.target.value as Draft["operationMode"])}>
                    <option value="detect_prevent">Detection and prevention</option>
                    <option value="detect_only">Detection only</option>
                    <option value="monitor">Monitor</option>
                  </select>
                </label>
              </section>

              <section className="installModuleMatrix" aria-label="Security modules and OS compatibility">
                <div className="installMatrixHead">
                  <span>Modules</span>
                  <span>OS compatibility</span>
                </div>
                {MODULES.map((module) => (
                  <label key={module.id} className={draft.modules.includes(module.id) ? "enabled" : ""}>
                    <span>
                      <input type="checkbox" checked={draft.modules.includes(module.id)} onChange={() => toggleModule(module.id)} />
                      {module.label}
                    </span>
                    <span className="installOsList">
                      {(["windows", "macos", "linux"] as const).map((os) => (
                        <i key={os} className={module.os.includes(os) ? "supported" : ""}>{osIcon(os)}</i>
                      ))}
                    </span>
                  </label>
                ))}
              </section>

              <section className="installRolesPanel">
                <h3>Roles</h3>
                <div className="installRolesGrid">
                {["workstations", "servers", "relay", "gold-image", "test-ring"].map((role) => (
                  <label key={role}>
                    <input
                      type="checkbox"
                      checked={draft.roles.includes(role)}
                      onChange={() => setDraft((current) => ({
                        ...current,
                        roles: current.roles.includes(role)
                          ? current.roles.filter((item) => item !== role)
                          : [...current.roles, role],
                      }))}
                    />
                    {role.replace(/-/g, " ")}
                  </label>
                ))}
                </div>
                <p>Additional package sections can be added here without changing the table layout.</p>
              </section>
            </div>
            <footer>
              <button type="submit" className="installSave" disabled={isWorking || !draft.name.trim()}>{isWorking ? "Saving..." : "Save"}</button>
              <button type="button" className="installCancel" onClick={() => setCreateOpen(false)}>Cancel</button>
            </footer>
          </form>
        </div>
      ) : null}
    </main>
  );
}
