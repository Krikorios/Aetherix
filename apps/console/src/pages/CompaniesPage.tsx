import { FormEvent, useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import {
  AlertCircle,
  Building2,
  Check,
  Clock,
  Copy,
  Download,
  Hash,
  Key,
  Layers,
  Link2,
  MoreHorizontal,
  Package,
  Plus,
  RefreshCw,
  ShieldCheck,
} from "lucide-react";
import {
  apiGet,
  apiPost,
  apiPut,
  getAccountId,
  setAccountId,
  type CompanyLicense,
  type CompanyLicenseAssign,
  type Customer,
  type CustomerQuickCreateResult,
  type InstallerBuild,
  type InstallerPlatform,
  type MeResponse,
  type PolicyPackage,
  type QuickDeployLink,
  type Subscription,
} from "../api";
import {
  EmptyState,
  ErrorBanner,
  LoadingRow,
  PageHeader,
  SideSheet,
  SuccessBanner,
} from "../components";

const COMPANY_SIZES = ["1-10", "11-50", "51-250", "251-1000", "1000+"] as const;
const PLATFORMS: { value: InstallerPlatform; label: string }[] = [
  { value: "windows_msi", label: "Windows MSI" },
  { value: "macos_pkg", label: "macOS PKG" },
  { value: "linux_deb", label: "Linux DEB" },
];

const ADDON_LABELS: Record<string, string> = {
  semantic_dlp: "Semantic DLP",
  agentic_ir: "Agentic IR",
  xdr: "XDR",
  patch_management: "Patch Management",
  sandbox_analyzer: "Sandbox Analyzer",
  email_security: "Email Security",
  mobile_security: "Mobile Security",
  full_disk_encryption: "Full Disk Encryption",
};

type CompanyRow = {
  customer: Customer;
  license: CompanyLicense | null;
};

export function CompaniesPage() {
  const [me, setMe] = useState<MeResponse | null>(null);
  const [authError, setAuthError] = useState<string | null>(null);
  const [accountInput, setAccountInput] = useState(getAccountId() ?? "");

  const [rows, setRows] = useState<CompanyRow[]>([]);
  const [subscriptions, setSubscriptions] = useState<Subscription[]>([]);
  const [policyPackages, setPolicyPackages] = useState<PolicyPackage[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [selected, setSelected] = useState<CompanyRow | null>(null);
  const mountedRef = useRef(true);

  const canManageCompanies = (me?.permissions.companies ?? "none") === "manage";
  const canViewLicensing = ["view", "edit", "manage"].includes(me?.permissions.licensing ?? "none");

  const load = useCallback(async () => {
    setIsLoading(true);
    try {
      const [companies, subs, packages] = await Promise.all([
        apiGet<Customer[]>("/companies"),
        apiGet<Subscription[]>("/subscriptions"),
        apiGet<PolicyPackage[]>("/policy-packages"),
      ]);
      const licenses = await Promise.all(
        companies.map(async (c) => {
          try {
            return await apiGet<CompanyLicense>(`/companies/${c.id}/license`);
          } catch {
            return null;
          }
        }),
      );
      if (!mountedRef.current) return;
      setRows(companies.map((customer, idx) => ({ customer, license: licenses[idx] })));
      setSubscriptions(subs);
      setPolicyPackages(packages);
      setError(null);
    } catch (err) {
      if (mountedRef.current) setError(err instanceof Error ? err.message : "Failed to load companies");
    } finally {
      if (mountedRef.current) setIsLoading(false);
    }
  }, []);

  const loadMe = useCallback(async () => {
    if (!getAccountId()) {
      setMe(null);
      setAuthError("Sign in by pasting an account ID — temporary dev auth until SSO lands.");
      setIsLoading(false);
      return;
    }
    try {
      const next = await apiGet<MeResponse>("/me");
      if (!mountedRef.current) return;
      setMe(next);
      setAuthError(null);
      await load();
    } catch (err) {
      if (!mountedRef.current) return;
      setMe(null);
      setAuthError(err instanceof Error ? err.message : "Auth failed");
      setIsLoading(false);
    }
  }, [load]);

  useEffect(() => {
    mountedRef.current = true;
    void loadMe();
    return () => {
      mountedRef.current = false;
    };
  }, [loadMe]);

  function handleSignIn(event: FormEvent) {
    event.preventDefault();
    const trimmed = accountInput.trim();
    if (!trimmed) return;
    setAccountId(trimmed);
    void loadMe();
  }

  function handleSignOut() {
    setAccountId(null);
    setAccountInput("");
    setMe(null);
    setRows([]);
    setAuthError("Signed out.");
  }

  if (!me) {
    return (
      <>
        <PageHeader
          eyebrow="MSP tenant foundation"
          title="Companies + Licensing"
          subtitle="Sign in with an account ID to load tenant-scoped data."
        />
        {authError ? <ErrorBanner message={authError} /> : null}
        <section className="panel" style={{ maxWidth: 520 }}>
          <div className="panelHeader">
            <div>
              <h2>Dev sign-in</h2>
              <span>Paste a platform owner / partner / company account UUID.</span>
            </div>
            <Key size={18} />
          </div>
          <form className="formStack" onSubmit={handleSignIn}>
            <div className="formRow">
              <label htmlFor="accountId">Account ID</label>
              <input
                id="accountId"
                placeholder="00000000-0000-0000-0000-000000000000"
                value={accountInput}
                onChange={(event) => setAccountInput(event.target.value)}
              />
            </div>
            <div className="formActions">
              <button type="submit" className="btnPrimary" disabled={!accountInput.trim()}>
                Sign in
              </button>
            </div>
          </form>
        </section>
      </>
    );
  }

  return (
    <>
      <PageHeader
        eyebrow={me.scope.is_platform ? "Platform owner" : me.scope.partner_ids.length ? "MSP partner" : "Company user"}
        title="Companies + Licensing"
        subtitle={`Signed in as ${me.account.email}. ${rows.length} ${rows.length === 1 ? "company" : "companies"} in scope.`}
      />
      {error ? <ErrorBanner message={error} /> : null}
      {success ? <SuccessBanner message={success} /> : null}

      <section className="panel companyTablePanel">
        <div className="panelHeader">
          <div>
            <h2>Company Hub</h2>
            <span>Licensing posture, seat usage, and per-company configuration in one place.</span>
          </div>
          <div className="panelActions">
            <button type="button" className="btnGhost" onClick={() => void load()} aria-label="Refresh">
              <RefreshCw size={16} /> Refresh
            </button>
            {canManageCompanies ? (
              <button type="button" className="btnPrimary" onClick={() => setShowCreate(true)}>
                <Plus size={16} /> Add company
              </button>
            ) : null}
            <button type="button" className="btnGhost" onClick={handleSignOut}>
              Sign out
            </button>
          </div>
        </div>

        <div className="companyGrid">
          <div className="companyGridHead">
            <span>Company</span>
            <span>Type</span>
            <span>Status</span>
            <span>License key</span>
            <span>Expires</span>
            <span>Seats (used / reserved / total)</span>
            <span>Renewal</span>
            <span />
          </div>
          {isLoading ? <LoadingRow label="Loading companies" /> : null}
          {!isLoading && rows.length === 0 ? (
            <EmptyState>No companies in scope yet. Add one to begin.</EmptyState>
          ) : null}
          {rows.map((row) => (
            <button
              type="button"
              className="companyGridRow"
              key={row.customer.id}
              onClick={() => setSelected(row)}
            >
              <span className="cellCompany">
                <Building2 size={16} />
                <strong>{row.customer.name}</strong>
                <em>{row.customer.customer_number}</em>
              </span>
              <span>{row.customer.industry ?? "—"}</span>
              <span className={`statusPill status-${row.customer.status}`}>{row.customer.status}</span>
              <span className="mono">
                {row.license ? row.license.license_key : <em className="muted">Unlicensed</em>}
              </span>
              <span>{row.license?.expires_at ? formatDate(row.license.expires_at) : "—"}</span>
              <span>
                {row.license
                  ? `${row.license.products.reduce((a, p) => a + p.used_seats, 0)} / ${row.license.reserved_seats} / ${row.license.total_seats}`
                  : "—"}
              </span>
              <span>
                {row.license ? (
                  row.license.auto_renewal ? (
                    <span className="pillSubtle"><Check size={12} /> Auto</span>
                  ) : (
                    <span className="pillSubtle"><AlertCircle size={12} /> Manual</span>
                  )
                ) : (
                  "—"
                )}
              </span>
              <span className="cellActions">
                <MoreHorizontal size={16} />
              </span>
            </button>
          ))}
        </div>
      </section>

      <CreateCompanySheet
        open={showCreate}
        onClose={() => setShowCreate(false)}
        policyPackages={policyPackages}
        onCreated={(message) => {
          setShowCreate(false);
          setSuccess(message);
          void load();
        }}
        onError={(message) => setError(message)}
      />

      <CompanyEditSheet
        row={selected}
        onClose={() => setSelected(null)}
        subscriptions={subscriptions}
        canManageLicensing={(me.permissions.licensing ?? "none") === "manage"}
        canViewLicensing={canViewLicensing}
        onLicenseAssigned={(updated) => {
          setSuccess(`License updated for ${updated.customer.name}.`);
          setSelected(updated);
          setRows((current) =>
            current.map((r) => (r.customer.id === updated.customer.id ? updated : r)),
          );
        }}
        onError={(message) => setError(message)}
      />
    </>
  );
}

// ---------------------------------------------------------------------------
// Create Company side-sheet (wraps existing /customers/quick-create)
// ---------------------------------------------------------------------------

function CreateCompanySheet({
  open,
  onClose,
  policyPackages,
  onCreated,
  onError,
}: {
  open: boolean;
  onClose: () => void;
  policyPackages: PolicyPackage[];
  onCreated: (message: string) => void;
  onError: (message: string) => void;
}) {
  const [name, setName] = useState("");
  const [industry, setIndustry] = useState("Healthcare");
  const [companySize, setCompanySize] =
    useState<(typeof COMPANY_SIZES)[number]>("11-50");
  const [policyPackageId, setPolicyPackageId] = useState("");
  const [platforms, setPlatforms] = useState<InstallerPlatform[]>([
    "windows_msi",
    "macos_pkg",
  ]);
  const [isSaving, setIsSaving] = useState(false);

  useEffect(() => {
    if (open && policyPackages[0] && !policyPackageId) {
      setPolicyPackageId(policyPackages[0].id);
    }
  }, [open, policyPackages, policyPackageId]);

  function togglePlatform(platform: InstallerPlatform) {
    setPlatforms((current) =>
      current.includes(platform)
        ? current.filter((item) => item !== platform)
        : [...current, platform],
    );
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    setIsSaving(true);
    try {
      const created = await apiPost<CustomerQuickCreateResult>("/customers/quick-create", {
        name: name.trim(),
        industry,
        country: "US",
        company_size: companySize,
        policy_package_id: policyPackageId || null,
        platforms,
        installer_ttl_seconds: 86_400,
        created_by: "console",
      });
      setName("");
      onCreated(
        `${created.customer.name} is created, policy assigned, and installers queued.`,
      );
    } catch (err) {
      onError(err instanceof Error ? err.message : "Company creation failed");
    } finally {
      setIsSaving(false);
    }
  }

  return (
    <SideSheet open={open} onClose={onClose} title="Add company" subtitle="Quick create with policy and installers" width={560}>
      <form className="formStack" onSubmit={submit}>
        <div className="formRow">
          <label htmlFor="newCompanyName">Company name</label>
          <input
            id="newCompanyName"
            required
            value={name}
            onChange={(event) => setName(event.target.value)}
            placeholder="Northwind Dental"
          />
        </div>
        <div className="formGrid2">
          <div className="formRow">
            <label htmlFor="newIndustry">Industry</label>
            <input id="newIndustry" value={industry} onChange={(event) => setIndustry(event.target.value)} />
          </div>
          <div className="formRow">
            <label htmlFor="newSize">Company size</label>
            <select id="newSize" value={companySize} onChange={(event) => setCompanySize(event.target.value as typeof companySize)}>
              {COMPANY_SIZES.map((size) => (
                <option key={size}>{size}</option>
              ))}
            </select>
          </div>
        </div>
        <div className="formRow">
          <label htmlFor="newPolicy">Configuration profile</label>
          <select id="newPolicy" value={policyPackageId} onChange={(event) => setPolicyPackageId(event.target.value)}>
            <option value="">— None —</option>
            {policyPackages.map((item) => (
              <option key={item.id} value={item.id}>
                {item.name}
              </option>
            ))}
          </select>
        </div>
        <div className="formRow">
          <label>Platforms</label>
          <div className="platformCheckGrid">
            {PLATFORMS.map((platform) => (
              <label
                key={platform.value}
                className={platforms.includes(platform.value) ? "platformCheck active" : "platformCheck"}
              >
                <input
                  type="checkbox"
                  checked={platforms.includes(platform.value)}
                  onChange={() => togglePlatform(platform.value)}
                />
                <span>{platform.label}</span>
              </label>
            ))}
          </div>
        </div>
        <div className="formActions">
          <button type="button" className="btnGhost" onClick={onClose}>
            Cancel
          </button>
          <button className="btnPrimary" type="submit" disabled={isSaving || !name.trim() || platforms.length === 0}>
            {isSaving ? <RefreshCw size={16} className="spinIcon" /> : <Plus size={16} />} {isSaving ? "Creating" : "Create"}
          </button>
        </div>
      </form>
    </SideSheet>
  );
}

// ---------------------------------------------------------------------------
// Company Edit side-sheet — Details / Auth / Licensing / Products Hub
// ---------------------------------------------------------------------------

type EditTab = "details" | "auth" | "licensing" | "products" | "deploy";

function CompanyEditSheet({
  row,
  onClose,
  subscriptions,
  canManageLicensing,
  canViewLicensing,
  onLicenseAssigned,
  onError,
}: {
  row: CompanyRow | null;
  onClose: () => void;
  subscriptions: Subscription[];
  canManageLicensing: boolean;
  canViewLicensing: boolean;
  onLicenseAssigned: (updated: CompanyRow) => void;
  onError: (message: string) => void;
}) {
  const [tab, setTab] = useState<EditTab>("details");
  const customerId = row?.customer.id;

  useEffect(() => {
    if (customerId) setTab("details");
  }, [customerId]);

  if (!row) {
    return null;
  }

  return (
    <SideSheet
      open={!!row}
      onClose={onClose}
      title={row.customer.name}
      subtitle={`${row.customer.customer_number} · ${row.customer.industry ?? "General"}`}
      width={720}
    >
      <nav className="tabBar" role="tablist">
        {(["details", "auth", "licensing", "products", "deploy"] as EditTab[]).map((t) => (
          <button
            key={t}
            role="tab"
            aria-selected={tab === t}
            className={tab === t ? "tabBtn active" : "tabBtn"}
            onClick={() => setTab(t)}
          >
            {tabLabel(t)}
          </button>
        ))}
      </nav>

      {tab === "details" ? <DetailsTab row={row} /> : null}
      {tab === "auth" ? <AuthTab row={row} /> : null}
      {tab === "licensing" ? (
        <LicensingTab
          row={row}
          subscriptions={subscriptions}
          canManage={canManageLicensing}
          canView={canViewLicensing}
          onAssigned={onLicenseAssigned}
          onError={onError}
        />
      ) : null}
      {tab === "products" ? <ProductsTab row={row} /> : null}
      {tab === "deploy" ? <DeployTab row={row} onError={onError} /> : null}
    </SideSheet>
  );
}

function tabLabel(tab: EditTab): string {
  if (tab === "details") return "Details";
  if (tab === "auth") return "Authentication";
  if (tab === "licensing") return "Licensing";
  if (tab === "products") return "Products Hub";
  return "Deploy";
}

function DetailsTab({ row }: { row: CompanyRow }) {
  const { customer } = row;
  return (
    <div className="tabPanel">
      <KvList
        items={[
          ["Company ID", customer.id],
          ["Customer number", customer.customer_number],
          ["Industry", customer.industry ?? "—"],
          ["Country", customer.country ?? "—"],
          ["Company size", customer.company_size ?? "—"],
          ["Status", customer.status],
          ["Created", formatDate(customer.created_at)],
          ["Created by", customer.created_by],
        ]}
      />
    </div>
  );
}

function AuthTab({ row }: { row: CompanyRow }) {
  return (
    <div className="tabPanel">
      <p className="muted">
        Account management for {row.customer.name} lives on the Accounts page. Per-company SSO,
        2FA enforcement, and impersonation policy land in a later step.
      </p>
    </div>
  );
}

function LicensingTab({
  row,
  subscriptions,
  canManage,
  canView,
  onAssigned,
  onError,
}: {
  row: CompanyRow;
  subscriptions: Subscription[];
  canManage: boolean;
  canView: boolean;
  onAssigned: (updated: CompanyRow) => void;
  onError: (message: string) => void;
}) {
  const initialLicense = row.license;
  const [sku, setSku] = useState(initialLicense?.subscription_sku ?? subscriptions[0]?.sku ?? "");
  const [paymentPlan, setPaymentPlan] = useState<NonNullable<CompanyLicenseAssign["payment_plan"]>>(
    initialLicense?.payment_plan ?? "monthly",
  );
  const [totalSeats, setTotalSeats] = useState<number>(initialLicense?.total_seats ?? 10);
  const [reservedSeats, setReservedSeats] = useState<number>(initialLicense?.reserved_seats ?? 0);
  const [autoRenewal, setAutoRenewal] = useState<boolean>(initialLicense?.auto_renewal ?? true);
  const [minimumUsage, setMinimumUsage] = useState<number>(initialLicense?.minimum_usage ?? 0);
  const [expiresAt, setExpiresAt] = useState<string>(
    initialLicense?.expires_at ? initialLicense.expires_at.slice(0, 10) : "",
  );
  const [addons, setAddons] = useState<string[]>(initialLicense?.addons ?? []);
  const [isSaving, setIsSaving] = useState(false);

  const licenseKey = initialLicense?.id;
  useEffect(() => {
    setSku(initialLicense?.subscription_sku ?? subscriptions[0]?.sku ?? "");
    setPaymentPlan(initialLicense?.payment_plan ?? "monthly");
    setTotalSeats(initialLicense?.total_seats ?? 10);
    setReservedSeats(initialLicense?.reserved_seats ?? 0);
    setAutoRenewal(initialLicense?.auto_renewal ?? true);
    setMinimumUsage(initialLicense?.minimum_usage ?? 0);
    setExpiresAt(initialLicense?.expires_at ? initialLicense.expires_at.slice(0, 10) : "");
    setAddons(initialLicense?.addons ?? []);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [licenseKey, subscriptions]);

  const selected = useMemo(() => subscriptions.find((s) => s.sku === sku), [subscriptions, sku]);

  if (!canView) {
    return (
      <div className="tabPanel">
        <p className="muted">You don't have permission to view licensing for this company.</p>
      </div>
    );
  }

  function toggleAddon(addon: string) {
    setAddons((current) =>
      current.includes(addon) ? current.filter((a) => a !== addon) : [...current, addon],
    );
  }

  async function save(event: FormEvent) {
    event.preventDefault();
    if (!sku) return;
    setIsSaving(true);
    try {
      const payload: CompanyLicenseAssign = {
        subscription_sku: sku,
        payment_plan: paymentPlan,
        total_seats: totalSeats,
        reserved_seats: reservedSeats,
        auto_renewal: autoRenewal,
        minimum_usage: minimumUsage,
        addons,
        expires_at: expiresAt ? new Date(`${expiresAt}T00:00:00Z`).toISOString() : null,
      };
      const license = await apiPut<CompanyLicense>(`/companies/${row.customer.id}/license`, payload);
      onAssigned({ customer: row.customer, license });
    } catch (err) {
      onError(err instanceof Error ? err.message : "Failed to update license");
    } finally {
      setIsSaving(false);
    }
  }

  return (
    <form className="tabPanel formStack" onSubmit={save}>
      <div className="licensingIds">
        <CopyChip label="Company ID" value={row.customer.id} icon={<Building2 size={14} />} />
        {initialLicense ? (
          <>
            <CopyChip label="License key" value={initialLicense.license_key} icon={<Key size={14} />} />
            <CopyChip label="Company hash" value={initialLicense.company_hash} icon={<Hash size={14} />} />
          </>
        ) : null}
      </div>

      <fieldset disabled={!canManage} className="fieldsetClean">
        <div className="formGrid2">
          <div className="formRow">
            <label htmlFor="lcnSku">Subscription</label>
            <select id="lcnSku" value={sku} onChange={(event) => setSku(event.target.value)}>
              {subscriptions.map((s) => (
                <option key={s.sku} value={s.sku}>
                  {s.display_name} · ${s.list_price_per_seat.toFixed(2)}/seat
                </option>
              ))}
            </select>
          </div>
          <div className="formRow">
            <label htmlFor="lcnPlan">Payment plan</label>
            <select
              id="lcnPlan"
              value={paymentPlan}
              onChange={(event) => setPaymentPlan(event.target.value as typeof paymentPlan)}
            >
              <option value="monthly">Monthly</option>
              <option value="annual">Annual</option>
              <option value="usage">Usage-based</option>
            </select>
          </div>
        </div>

        <div className="formGrid3">
          <div className="formRow">
            <label htmlFor="lcnTotal">Total seats</label>
            <input
              id="lcnTotal"
              type="number"
              min={0}
              value={totalSeats}
              onChange={(event) => setTotalSeats(Math.max(0, Number(event.target.value)))}
            />
          </div>
          <div className="formRow">
            <label htmlFor="lcnReserved">Reserved seats</label>
            <input
              id="lcnReserved"
              type="number"
              min={0}
              value={reservedSeats}
              onChange={(event) => setReservedSeats(Math.max(0, Number(event.target.value)))}
            />
          </div>
          <div className="formRow">
            <label htmlFor="lcnMinUsage">Minimum usage</label>
            <input
              id="lcnMinUsage"
              type="number"
              min={0}
              value={minimumUsage}
              onChange={(event) => setMinimumUsage(Math.max(0, Number(event.target.value)))}
            />
          </div>
        </div>

        <div className="formGrid2">
          <div className="formRow">
            <label htmlFor="lcnExpires">Expires on</label>
            <input
              id="lcnExpires"
              type="date"
              value={expiresAt}
              onChange={(event) => setExpiresAt(event.target.value)}
            />
          </div>
          <div className="formRow toggleRow">
            <label htmlFor="lcnAuto">Auto-renewal</label>
            <label className="switch">
              <input
                id="lcnAuto"
                type="checkbox"
                checked={autoRenewal}
                onChange={(event) => setAutoRenewal(event.target.checked)}
              />
              <span />
            </label>
          </div>
        </div>

        <div className="addonGrid">
          <div className="addonGridHead">
            <ShieldCheck size={14} /> Add-ons
            {selected ? <em className="muted">{selected.available_addons.length} available on {selected.display_name}</em> : null}
          </div>
          <div className="addonGridBody">
            {(selected?.available_addons ?? []).map((addon) => {
              const isOn = addons.includes(addon);
              return (
                <button
                  key={addon}
                  type="button"
                  className={isOn ? "addonChip on" : "addonChip"}
                  onClick={() => toggleAddon(addon)}
                  disabled={!canManage}
                >
                  <span>{ADDON_LABELS[addon] ?? addon}</span>
                  {isOn ? <Check size={14} /> : <Plus size={14} />}
                </button>
              );
            })}
            {!selected ? <em className="muted">Select a subscription to view add-ons.</em> : null}
          </div>
        </div>

        {canManage ? (
          <div className="formActions">
            <button type="submit" className="btnPrimary" disabled={isSaving || !sku}>
              {isSaving ? <RefreshCw size={16} className="spinIcon" /> : <ShieldCheck size={16} />} {isSaving ? "Saving" : initialLicense ? "Update license" : "Assign license"}
            </button>
          </div>
        ) : (
          <p className="muted">Read-only — requires the <code>licensing:manage</code> permission.</p>
        )}
      </fieldset>
    </form>
  );
}

function ProductsTab({ row }: { row: CompanyRow }) {
  const products = row.license?.products ?? [];
  if (!row.license) {
    return (
      <div className="tabPanel">
        <p className="muted">No license assigned yet. Assign a subscription on the Licensing tab to materialize product entitlements.</p>
      </div>
    );
  }
  return (
    <div className="tabPanel">
      <div className="productHead">
        <Layers size={14} /> {products.length} product {products.length === 1 ? "line" : "lines"} active
      </div>
      <div className="productTable">
        <div className="productTableHead">
          <span>Product</span>
          <span>Type</span>
          <span>Model</span>
          <span>Used / Total</span>
          <span>Reserved</span>
          <span>Status</span>
        </div>
        {products.map((p) => (
          <div className="productTableRow" key={p.id}>
            <span><strong>{p.product_name}</strong><em>{p.product_code}</em></span>
            <span>{p.product_type}</span>
            <span>{p.protection_model === "bundled" ? "Bundled" : "À la carte"}</span>
            <span>{p.used_seats} / {p.total_seats}</span>
            <span>{p.reserved_seats}</span>
            <span className={`statusPill status-${p.status}`}>{p.status}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Deploy tab — generate installers + quick-deploy links
// ---------------------------------------------------------------------------

const TTL_OPTIONS: { value: number; label: string }[] = [
  { value: 3600, label: "1 hour" },
  { value: 14_400, label: "4 hours" },
  { value: 86_400, label: "24 hours" },
  { value: 259_200, label: "3 days" },
  { value: 604_800, label: "7 days" },
];

function DeployTab({ row, onError }: { row: CompanyRow; onError: (message: string) => void }) {
  const [platforms, setPlatforms] = useState<InstallerPlatform[]>(["windows_msi"]);
  const [ttl, setTtl] = useState<number>(86_400);
  const [installers, setInstallers] = useState<InstallerBuild[]>([]);
  const [links, setLinks] = useState<QuickDeployLink[]>([]);
  const [busy, setBusy] = useState<"none" | "installers" | "links">("none");
  const [info, setInfo] = useState<string | null>(null);

  function toggle(p: InstallerPlatform) {
    setPlatforms((prev) => (prev.includes(p) ? prev.filter((x) => x !== p) : [...prev, p]));
  }

  async function generateInstallers() {
    if (platforms.length === 0) {
      onError("Pick at least one platform.");
      return;
    }
    setBusy("installers");
    setInfo(null);
    try {
      const created = await apiPost<InstallerBuild[]>(`/customers/${row.customer.id}/installers`, {
        platforms,
        ttl_seconds: ttl,
        created_by: "console",
      });
      setInstallers((prev) => [...created, ...prev]);
      setInfo(`Queued ${created.length} installer build(s).`);
    } catch (err) {
      onError(err instanceof Error ? err.message : "Failed to generate installers");
    } finally {
      setBusy("none");
    }
  }

  async function generateLinks() {
    if (platforms.length === 0) {
      onError("Pick at least one platform.");
      return;
    }
    setBusy("links");
    setInfo(null);
    try {
      const created = await apiPost<QuickDeployLink[]>(`/customers/${row.customer.id}/quick-deploy`, {
        platforms,
        ttl_seconds: ttl,
        created_by: "console",
      });
      setLinks((prev) => [...created, ...prev]);
      setInfo(`Created ${created.length} quick-deploy link(s).`);
    } catch (err) {
      onError(err instanceof Error ? err.message : "Failed to create quick-deploy links");
    } finally {
      setBusy("none");
    }
  }

  async function copy(text: string) {
    try {
      await navigator.clipboard.writeText(text);
      setInfo("Copied to clipboard.");
    } catch {
      setInfo(text);
    }
  }

  return (
    <div className="tabPanel">
      <fieldset className="fieldsetClean">
        <legend><Package size={14} /> Generate installers</legend>
        <p className="muted">Builds a signed installer per platform with the active policy package and a single-use enrollment token.</p>
        <div className="formStack">
          <div className="formRow">
            <label>Platforms</label>
            <div className="addonGrid" role="group" aria-label="Installer platforms">
              {PLATFORMS.map((p) => (
                <button
                  type="button"
                  key={p.value}
                  className={`addonChip ${platforms.includes(p.value) ? "on" : ""}`}
                  onClick={() => toggle(p.value)}
                >
                  {platforms.includes(p.value) ? <Check size={12} /> : <Plus size={12} />} {p.label}
                </button>
              ))}
            </div>
          </div>
          <div className="formGrid2">
            <div className="formRow">
              <label htmlFor="deployTtl">Token TTL</label>
              <select id="deployTtl" value={ttl} onChange={(event) => setTtl(Number(event.target.value))}>
                {TTL_OPTIONS.map((o) => (
                  <option key={o.value} value={o.value}>{o.label}</option>
                ))}
              </select>
            </div>
          </div>
          <div className="formActions">
            <button type="button" className="btnSecondary" onClick={() => void generateLinks()} disabled={busy !== "none"}>
              {busy === "links" ? <RefreshCw size={16} className="spinIcon" /> : <Link2 size={16} />} Quick-deploy links
            </button>
            <button type="button" className="btnPrimary" onClick={() => void generateInstallers()} disabled={busy !== "none"}>
              {busy === "installers" ? <RefreshCw size={16} className="spinIcon" /> : <Download size={16} />} Generate installers
            </button>
          </div>
          {info ? <p className="muted"><Check size={12} /> {info}</p> : null}
        </div>
      </fieldset>

      {installers.length > 0 ? (
        <fieldset className="fieldsetClean">
          <legend><Download size={14} /> Recent installers</legend>
          <div className="installerList">
            {installers.map((build) => (
              <div className="installerRow" key={build.id}>
                <div>
                  <strong>{build.platform}</strong>
                  <em className={`statusPill status-${build.status === "ready" ? "active" : build.status === "failed" ? "expired" : "trial"}`}>{build.status}</em>
                </div>
                <span className="muted"><Clock size={12} /> {build.expires_at ? formatDate(build.expires_at) : "no expiry"}</span>
                {build.artifact_url ? (
                  <button type="button" className="iconBtn" onClick={() => void copy(build.artifact_url ?? "")} aria-label="Copy artifact URL">
                    <Copy size={14} />
                  </button>
                ) : <span className="muted">queued</span>}
              </div>
            ))}
          </div>
        </fieldset>
      ) : null}

      {links.length > 0 ? (
        <fieldset className="fieldsetClean">
          <legend><Link2 size={14} /> Quick-deploy links</legend>
          <div className="installerList">
            {links.map((link) => (
              <div className="installerRow" key={link.id}>
                <div>
                  <strong>{link.platform ?? "any"}</strong>
                  <em className="muted">{link.download_count}{link.max_downloads ? ` / ${link.max_downloads}` : ""} downloads</em>
                </div>
                <span className="muted"><Clock size={12} /> {formatDate(link.expires_at)}</span>
                <button type="button" className="iconBtn" onClick={() => void copy(link.url)} aria-label="Copy link">
                  <Copy size={14} />
                </button>
              </div>
            ))}
          </div>
        </fieldset>
      ) : null}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Small helpers / sub-components
// ---------------------------------------------------------------------------

function KvList({ items }: { items: [string, string][] }) {
  return (
    <dl className="kvList">
      {items.map(([k, v]) => (
        <div key={k}>
          <dt>{k}</dt>
          <dd>{v}</dd>
        </div>
      ))}
    </dl>
  );
}

function CopyChip({
  label,
  value,
  icon,
}: {
  label: string;
  value: string;
  icon?: ReactNode;
}) {
  const [copied, setCopied] = useState(false);
  async function onCopy() {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // ignore
    }
  }
  return (
    <button type="button" className="copyChip" onClick={onCopy} title={value}>
      {icon}
      <span className="copyChipLabel">{label}</span>
      <code>{value.length > 24 ? `${value.slice(0, 10)}…${value.slice(-6)}` : value}</code>
      {copied ? <Check size={12} /> : <Copy size={12} />}
    </button>
  );
}

function formatDate(iso: string): string {
  try {
    return new Date(iso).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
  } catch {
    return iso;
  }
}
