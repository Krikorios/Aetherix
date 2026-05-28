import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent, type ReactNode } from "react";
import {
  Building2,
  Check,
  ChevronDown,
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
  Search,
  Settings,
  ShieldCheck,
  Sparkles,
  Trash2,
} from "lucide-react";
import {
  apiGet,
  apiPost,
  apiPut,
  apiDelete,
  type AiProvider,
  type AiProbeResult,
  type BulkActionResult,
  type CompanyLicense,
  type CompanyLicenseAssign,
  type CompanySummaryPage,
  type Customer,
  type CustomerAiSettings,
  type CustomerAiSettingsUpdate,
  type CustomerQuickCreateResult,
  type InstallerBuild,
  type InstallerPlatform,
  type MeResponse,
  type PolicyPackage,
  type QuickDeployLink,
  type Subscription,
} from "../api";
import { hasPermission } from "../permissions";
import {
  ConfirmModal,
  EmptyState,
  ErrorBanner,
  LoadingRow,
  PageHeader,
  SideSheet,
  SuccessBanner,
} from "../components";

const COMPANY_SIZES = ["1-10", "11-50", "51-250", "251-1000", "1000+"] as const;
const COMPANY_TYPES = ["customer", "partner"] as const;
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

type ColumnId =
  | "name"
  | "type"
  | "status"
  | "managed"
  | "payment_plan"
  | "product_name"
  | "product_type"
  | "product_status"
  | "license_key"
  | "expires"
  | "total_seats"
  | "usage_breakdown"
  | "unlicensed"
  | "company_id"
  | "auto_renewal"
  | "minimum_usage"
  | "subscription_end"
  | "msp_trials"
  | "industry"
  | "country"
  | "size"
  | "created_at";

type ColumnDef = {
  id: ColumnId;
  label: string;
  defaultVisible: boolean;
  align?: "left" | "right" | "center";
  render: (row: CompanyRow, ctx: { subscriptions: Subscription[] }) => ReactNode;
};

const COLUMNS_STORAGE_KEY = "aetherix:companies:columns";

const PRODUCT_TYPE_LABELS: Record<string, string> = {
  core: "Core",
  advanced: "Advanced",
  enterprise: "Enterprise",
};

function formatCompanyType(value: "partner" | "customer"): string {
  return value === "partner" ? "Partner" : "Customer";
}

function sumUsed(license: CompanyLicense | null): number {
  if (!license) return 0;
  return license.products.reduce((acc, p) => acc + p.used_seats, 0);
}

function yesNo(value: boolean | null | undefined): ReactNode {
  if (value === null || value === undefined) return <span className="muted">—</span>;
  return value ? (
    <span className="pillSubtle"><Check size={12} /> Yes</span>
  ) : (
    <span className="muted">No</span>
  );
}

const COLUMN_DEFS: ColumnDef[] = [
  {
    id: "name",
    label: "Company name",
    defaultVisible: true,
    render: (row) => (
      <span className="cellCompany">
        <Building2 size={16} />
        <strong>{row.customer.name}</strong>
      </span>
    ),
  },
  {
    id: "type",
    label: "Company type",
    defaultVisible: true,
    render: (row) => <span>{formatCompanyType(row.customer.company_type)}</span>,
  },
  {
    id: "status",
    label: "Company status",
    defaultVisible: true,
    render: (row) => (
      <span className={`statusPill status-${row.customer.status}`}>{row.customer.status}</span>
    ),
  },
  {
    id: "managed",
    label: "Managed",
    defaultVisible: true,
    render: (row) => yesNo(Boolean(row.customer.assigned_policy_package_id)),
  },
  {
    id: "payment_plan",
    label: "Payment plan",
    defaultVisible: true,
    render: (row) => row.license?.payment_plan ?? <span className="muted">—</span>,
  },
  {
    id: "product_name",
    label: "Product name",
    defaultVisible: true,
    render: (row, ctx) => {
      if (!row.license) return <span className="muted">—</span>;
      const sub = ctx.subscriptions.find((s) => s.sku === row.license!.subscription_sku);
      return sub?.display_name ?? row.license.subscription_sku;
    },
  },
  {
    id: "product_type",
    label: "Product type",
    defaultVisible: false,
    render: (row, ctx) => {
      if (!row.license) return <span className="muted">—</span>;
      const sub = ctx.subscriptions.find((s) => s.sku === row.license!.subscription_sku);
      return PRODUCT_TYPE_LABELS[sub?.tier ?? ""] ?? <span className="muted">—</span>;
    },
  },
  {
    id: "product_status",
    label: "Product status",
    defaultVisible: true,
    render: (row) =>
      row.license ? (
        <span className={`statusPill status-${row.license.status}`}>{row.license.status}</span>
      ) : (
        <span className="muted">Unlicensed</span>
      ),
  },
  {
    id: "license_key",
    label: "License key",
    defaultVisible: false,
    render: (row) =>
      row.license ? <span className="mono">{row.license.license_key}</span> : <span className="muted">—</span>,
  },
  {
    id: "expires",
    label: "Expires",
    defaultVisible: true,
    render: (row) => (row.license?.expires_at ? formatDate(row.license.expires_at) : <span className="muted">—</span>),
  },
  {
    id: "total_seats",
    label: "Total seats",
    defaultVisible: false,
    align: "right",
    render: (row) => (row.license ? row.license.total_seats : <span className="muted">—</span>),
  },
  {
    id: "usage_breakdown",
    label: "Usage breakdown",
    defaultVisible: true,
    render: (row) => {
      if (!row.license) return <span className="muted">—</span>;
      const used = sumUsed(row.license);
      const reserved = row.license.reserved_seats;
      const available = Math.max(0, row.license.total_seats - used - reserved);
      return <span className="usageBreakdown">{used} used &middot; {reserved} reserved &middot; {available} available</span>;
    },
  },
  {
    id: "unlicensed",
    label: "Unlicensed",
    defaultVisible: false,
    align: "right",
    render: (row) => {
      if (!row.license) return <span className="muted">—</span>;
      const used = sumUsed(row.license);
      const overflow = Math.max(0, used - row.license.total_seats);
      return overflow > 0 ? <strong className="overflowCount">{overflow}</strong> : <span>0</span>;
    },
  },
  {
    id: "company_id",
    label: "Company ID",
    defaultVisible: true,
    render: (row) => <span className="mono">{row.customer.customer_number}</span>,
  },
  {
    id: "auto_renewal",
    label: "Auto renewal",
    defaultVisible: false,
    render: (row) => yesNo(row.license?.auto_renewal ?? null),
  },
  {
    id: "minimum_usage",
    label: "Minimum usage",
    defaultVisible: false,
    align: "right",
    render: (row) => row.license?.minimum_usage ?? <span className="muted">—</span>,
  },
  {
    id: "subscription_end",
    label: "Subscription end",
    defaultVisible: false,
    render: (row) => (row.license?.expires_at ? formatDate(row.license.expires_at) : <span className="muted">—</span>),
  },
  {
    id: "msp_trials",
    label: "MSP trials status",
    defaultVisible: false,
    render: (row) =>
      row.license?.status === "trial" ? (
        <span className="statusPill status-trial">Trial</span>
      ) : (
        <span className="muted">—</span>
      ),
  },
  {
    id: "industry",
    label: "Industry",
    defaultVisible: false,
    render: (row) => row.customer.industry ?? <span className="muted">—</span>,
  },
  {
    id: "country",
    label: "Country",
    defaultVisible: false,
    render: (row) => row.customer.country ?? <span className="muted">—</span>,
  },
  {
    id: "size",
    label: "Company size",
    defaultVisible: false,
    render: (row) => row.customer.company_size ?? <span className="muted">—</span>,
  },
  {
    id: "created_at",
    label: "Created",
    defaultVisible: false,
    render: (row) => formatDate(row.customer.created_at),
  },
];

function loadVisibleColumns(): ColumnId[] {
  try {
    const raw = window.localStorage.getItem(COLUMNS_STORAGE_KEY);
    if (raw) {
      const parsed = JSON.parse(raw) as ColumnId[];
      if (Array.isArray(parsed) && parsed.length > 0) return parsed;
    }
  } catch {
    /* ignore */
  }
  return COLUMN_DEFS.filter((c) => c.defaultVisible).map((c) => c.id);
}

export function CompaniesPage() {
  const [me, setMe] = useState<MeResponse | null>(null);

  const [rows, setRows] = useState<CompanyRow[]>([]);
  const [subscriptions, setSubscriptions] = useState<Subscription[]>([]);
  const [policyPackages, setPolicyPackages] = useState<PolicyPackage[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [selected, setSelected] = useState<CompanyRow | null>(null);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(() => new Set());
  const [visibleCols, setVisibleCols] = useState<ColumnId[]>(loadVisibleColumns);
  const [compactRows, setCompactRows] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [showMoreMenu, setShowMoreMenu] = useState(false);
  const [colSearch, setColSearch] = useState("");
  const [filterQuery, setFilterQuery] = useState("");
  const [filterStatus, setFilterStatus] = useState<"" | "active" | "suspended" | "archived">("");
  const [pageSize, setPageSize] = useState(50);
  const [offset, setOffset] = useState(0);
  const [totalRows, setTotalRows] = useState(0);
  const [bulkBusy, setBulkBusy] = useState(false);
  const [bulkStatusModal, setBulkStatusModal] = useState<"active" | "suspended" | "archived" | null>(null);
  const [bulkDeleteModal, setBulkDeleteModal] = useState(false);
  const mountedRef = useRef(true);

  useEffect(() => {
    try {
      window.localStorage.setItem(COLUMNS_STORAGE_KEY, JSON.stringify(visibleCols));
    } catch {
      /* ignore */
    }
  }, [visibleCols]);

  const orderedVisibleColumns = useMemo<ColumnDef[]>(() => {
    const set = new Set(visibleCols);
    return COLUMN_DEFS.filter((c) => set.has(c.id));
  }, [visibleCols]);

  const visibleRows = rows;
  const pageStart = totalRows === 0 ? 0 : offset + 1;
  const pageEnd = Math.min(offset + rows.length, totalRows);

  function toggleRow(id: string) {
    setSelectedIds((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function toggleAllVisible() {
    setSelectedIds((current) => {
      const allSelected = visibleRows.every((r) => current.has(r.customer.id));
      if (allSelected) {
        const next = new Set(current);
        visibleRows.forEach((r) => next.delete(r.customer.id));
        return next;
      }
      const next = new Set(current);
      visibleRows.forEach((r) => next.add(r.customer.id));
      return next;
    });
  }

  function toggleColumn(id: ColumnId) {
    setVisibleCols((current) =>
      current.includes(id) ? current.filter((c) => c !== id) : [...current, id],
    );
  }

  async function executeBulkStatus() {
    if (!bulkStatusModal) return;
    const status = bulkStatusModal;
    const ids = Array.from(selectedIds);
    if (ids.length === 0) {
      setBulkStatusModal(null);
      return;
    }
    const label =
      status === "suspended" ? "Suspend" : status === "archived" ? "Archive" : "Activate";
    
    setBulkBusy(true);
    setShowMoreMenu(false);
    try {
      const result = await apiPost<BulkActionResult>("/companies/bulk-status", { ids, status });
      if (result.failures.length) {
        setError(`${result.failures.length} update(s) failed: ${result.failures[0].error}`);
      } else {
        setError(null);
      }
      setSuccess(`${label}d ${result.ok_count} ${result.ok_count === 1 ? "company" : "companies"}.`);
      setSelectedIds(new Set());
      void load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Bulk status update failed");
    } finally {
      setBulkBusy(false);
      setBulkStatusModal(null);
    }
  }

  async function executeBulkDelete() {
    const ids = Array.from(selectedIds);
    if (ids.length === 0) {
      setBulkDeleteModal(false);
      return;
    }
    setBulkBusy(true);
    setShowMoreMenu(false);
    try {
      const result = await apiPost<BulkActionResult>("/companies/bulk-delete", { ids });
      if (result.failures.length) {
        setError(`${result.failures.length} delete(s) failed: ${result.failures[0].error}`);
      } else {
        setError(null);
      }
      setSuccess(`Deleted ${result.ok_count} ${result.ok_count === 1 ? "company" : "companies"}.`);
      setSelectedIds(new Set());
      void load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Bulk delete failed");
    } finally {
      setBulkBusy(false);
      setBulkDeleteModal(false);
    }
  }

  const canManageCompanies = hasPermission(me, { resource: "companies", level: "manage" });
  const canViewLicensing = hasPermission(me, { resource: "licensing", level: "view" });
  const canManagePolicies = hasPermission(me, { resource: "policies", level: "edit" });

  const load = useCallback(async () => {
    setIsLoading(true);
    try {
      const params = new URLSearchParams({ limit: String(pageSize), offset: String(offset) });
      const q = filterQuery.trim();
      if (q) params.set("q", q);
      if (filterStatus) params.set("status", filterStatus);
      const [summaries, subs, packages] = await Promise.all([
        apiGet<CompanySummaryPage>(`/companies/summary?${params.toString()}`),
        apiGet<Subscription[]>("/subscriptions"),
        apiGet<PolicyPackage[]>("/policy-packages"),
      ]);
      if (!mountedRef.current) return;
      setRows(summaries.items);
      setTotalRows(summaries.total);
      setSubscriptions(subs);
      setPolicyPackages(packages);
      setError(null);
    } catch (err) {
      if (mountedRef.current) setError(err instanceof Error ? err.message : "Failed to load companies");
    } finally {
      if (mountedRef.current) setIsLoading(false);
    }
  }, [filterQuery, filterStatus, offset, pageSize]);

  useEffect(() => {
    setOffset(0);
  }, [filterQuery, filterStatus, pageSize]);

  const loadMe = useCallback(async () => {
    try {
      const next = await apiGet<MeResponse>("/me");
      if (!mountedRef.current) return;
      setMe(next);
      await load();
    } catch (err) {
      if (!mountedRef.current) return;
      setMe(null);
      setError(err instanceof Error ? err.message : "Auth failed");
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

  if (!me) {
    return (
      <>
        <PageHeader
          eyebrow="MSP tenant foundation"
          title="Companies"
          subtitle="Sign in to load tenant-scoped data."
        />
        {error ? <ErrorBanner message={error} /> : null}
      </>
    );
  }

  return (
    <>
      <PageHeader
        eyebrow={me.scope.is_platform ? "Platform owner" : me.scope.partner_ids.length ? "MSP partner" : "Company user"}
        title="Companies"
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
            {canManagePolicies ? (
              <button
                type="button"
                className="btnGhost"
                onClick={() => {
                  window.dispatchEvent(new CustomEvent("aetherix:navigate", { detail: { page: "policies" } }));
                }}
              >
                <ShieldCheck size={16} /> Assign Policy
              </button>
            ) : null}
            {canManageCompanies ? (
              <button type="button" className="btnPrimary" onClick={() => setShowCreate(true)}>
                <Plus size={16} /> Add company
              </button>
            ) : null}
          </div>
        </div>

        <div className="dataToolbar">
          <div className="dataToolbarLeft">
            {canManageCompanies ? (
              <>
                <button
                  type="button"
                  className="btnDanger"
                  onClick={() => setBulkDeleteModal(true)}
                  disabled={selectedIds.size === 0 || bulkBusy}
                  title="Permanently delete selected companies and all of their data"
                >
                  <Trash2 size={14} /> Delete ({selectedIds.size})
                </button>
                <div className="moreActionsWrap">
                  <button
                    type="button"
                    className="btnGhost"
                    onClick={() => setShowMoreMenu((v) => !v)}
                    disabled={selectedIds.size === 0 || bulkBusy}
                  >
                    More actions <ChevronDown size={14} />
                  </button>
                  {showMoreMenu ? (
                    <div className="moreActionsMenu" role="menu">
                      <button type="button" onClick={() => setBulkStatusModal("active")}>
                        Activate selected
                      </button>
                      <button type="button" onClick={() => setBulkStatusModal("suspended")}>
                        Suspend selected
                      </button>
                      <button type="button" onClick={() => setBulkStatusModal("archived")}>
                        Archive selected
                      </button>
                    </div>
                  ) : null}
                </div>
              </>
            ) : null}
          </div>
          <div className="dataToolbarRight">
            <div className="searchField">
              <Search size={14} />
              <input
                placeholder="Search by name, type, company ID, or license key"
                value={filterQuery}
                onChange={(e) => setFilterQuery(e.target.value)}
              />
            </div>
            <select value={filterStatus} onChange={(e) => setFilterStatus(e.target.value as typeof filterStatus)}>
              <option value="">All statuses</option>
              <option value="active">Active</option>
              <option value="suspended">Suspended</option>
              <option value="archived">Archived</option>
            </select>
            <button
              type="button"
              className="iconBtn"
              aria-label="Settings"
              onClick={() => setShowSettings(true)}
            >
              <Settings size={16} />
            </button>
          </div>
        </div>

        <div className={`dataTableWrap${compactRows ? " compact" : ""}`}>
          <table className="dataTable">
            <thead>
              <tr>
                <th className="checkboxCell">
                  <input
                    type="checkbox"
                    aria-label="Select all"
                    checked={visibleRows.length > 0 && visibleRows.every((r) => selectedIds.has(r.customer.id))}
                    onChange={toggleAllVisible}
                  />
                </th>
                {orderedVisibleColumns.map((col) => (
                  <th key={col.id} className={col.align === "right" ? "textRight" : undefined}>{col.label}</th>
                ))}
                <th className="checkboxCell" />
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                <tr>
                  <td colSpan={orderedVisibleColumns.length + 2}>
                    <LoadingRow label="Loading companies" />
                  </td>
                </tr>
              ) : null}
              {!isLoading && visibleRows.length === 0 ? (
                <tr>
                  <td colSpan={orderedVisibleColumns.length + 2}>
                    <EmptyState>No companies match the current filters.</EmptyState>
                  </td>
                </tr>
              ) : null}
              {visibleRows.map((row) => {
                const isSelected = selectedIds.has(row.customer.id);
                return (
                  <tr
                    key={row.customer.id}
                    className={isSelected ? "selected" : undefined}
                    onClick={(e) => {
                      const target = e.target as HTMLElement;
                      if (target.closest("input,button,a,select")) return;
                      setSelected(row);
                    }}
                  >
                    <td className="checkboxCell" onClick={(e) => e.stopPropagation()}>
                      <input
                        type="checkbox"
                        aria-label={`Select ${row.customer.name}`}
                        checked={isSelected}
                        onChange={() => toggleRow(row.customer.id)}
                      />
                    </td>
                    {orderedVisibleColumns.map((col) => (
                      <td key={col.id} className={col.align === "right" ? "textRight" : undefined}>
                        {col.render(row, { subscriptions })}
                      </td>
                    ))}
                    <td className="checkboxCell actionCell">
                      <span
                        className="linkLike"
                        role="button"
                        tabIndex={0}
                        title="Deploy installer"
                        onClick={(e) => { e.stopPropagation(); window.dispatchEvent(new CustomEvent("aetherix:navigate", { detail: { page: "installers" } })); }}
                        onKeyDown={(e) => { if (e.key === "Enter") { e.stopPropagation(); window.dispatchEvent(new CustomEvent("aetherix:navigate", { detail: { page: "installers" } })); } }}
                      >
                        <Package size={14} />
                      </span>
                      <MoreHorizontal size={16} />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        <div className="tablePager">
          <span>{totalRows === 0 ? "0 companies" : `${pageStart}-${pageEnd} of ${totalRows} companies`}</span>
          <div className="pagerControls">
            <select
              value={pageSize}
              onChange={(event) => setPageSize(Number(event.target.value))}
              aria-label="Rows per page"
            >
              <option value={25}>25 / page</option>
              <option value={50}>50 / page</option>
              <option value={100}>100 / page</option>
              <option value={250}>250 / page</option>
            </select>
            <button
              type="button"
              className="btnGhost"
              onClick={() => setOffset((current) => Math.max(0, current - pageSize))}
              disabled={offset === 0 || isLoading}
            >
              Previous
            </button>
            <button
              type="button"
              className="btnGhost"
              onClick={() => setOffset((current) => current + pageSize)}
              disabled={offset + pageSize >= totalRows || isLoading}
            >
              Next
            </button>
          </div>
        </div>
      </section>

      <ConfirmModal
        open={bulkStatusModal !== null}
        title={bulkStatusModal === "suspended" ? "Suspend Companies" : bulkStatusModal === "archived" ? "Archive Companies" : "Activate Companies"}
        message={`Are you sure you want to ${bulkStatusModal === "suspended" ? "suspend" : bulkStatusModal === "archived" ? "archive" : "activate"} ${selectedIds.size} ${selectedIds.size === 1 ? "company" : "companies"}?`}
        confirmLabel={bulkStatusModal === "suspended" ? "Suspend" : bulkStatusModal === "archived" ? "Archive" : "Activate"}
        isDanger={bulkStatusModal !== "active"}
        isBusy={bulkBusy}
        onConfirm={() => void executeBulkStatus()}
        onCancel={() => setBulkStatusModal(null)}
      />

      <ConfirmModal
        open={bulkDeleteModal}
        title="Permanently Delete Companies"
        message={`You are about to delete ${selectedIds.size} ${selectedIds.size === 1 ? "company" : "companies"}. This removes all of their agents, policies, alerts, and licensing. This cannot be undone.`}
        confirmLabel="Delete"
        isDanger
        isBusy={bulkBusy}
        requireReason
        onConfirm={(reason) => void executeBulkDelete()}
        onCancel={() => setBulkDeleteModal(false)}
      />

      <SideSheet open={showSettings} onClose={() => setShowSettings(false)} title="Table settings">
        <div className="settingsDrawer">
          <label className="checkboxRow">
            <input
              type="checkbox"
              checked={compactRows}
              onChange={(e) => setCompactRows(e.target.checked)}
            />
            <span>Compact rows</span>
          </label>
          <div className="settingsSection">
            <div className="settingsLabel">Visible columns ({visibleCols.length}/{COLUMN_DEFS.length})</div>
            <div className="searchField">
              <Search size={14} />
              <input
                placeholder="Search columns"
                value={colSearch}
                onChange={(e) => setColSearch(e.target.value)}
              />
            </div>
            <div className="columnList">
              {COLUMN_DEFS.filter((c) => c.label.toLowerCase().includes(colSearch.trim().toLowerCase())).map((col) => (
                <label key={col.id} className="checkboxRow">
                  <input
                    type="checkbox"
                    checked={visibleCols.includes(col.id)}
                    onChange={() => toggleColumn(col.id)}
                  />
                  <span>{col.label}</span>
                </label>
              ))}
            </div>
            <div className="settingsActions">
              <button
                type="button"
                className="btnGhost"
                onClick={() => setVisibleCols(COLUMN_DEFS.filter((c) => c.defaultVisible).map((c) => c.id))}
              >
                Reset to defaults
              </button>
              <button
                type="button"
                className="btnGhost"
                onClick={() => setVisibleCols(COLUMN_DEFS.map((c) => c.id))}
              >
                Show all
              </button>
            </div>
          </div>
        </div>
      </SideSheet>

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
        canManageCompany={canManageCompanies}
        canViewCompany={["view", "edit", "manage"].includes(me.permissions.companies ?? "none")}
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
  const [companyType, setCompanyType] =
    useState<(typeof COMPANY_TYPES)[number]>("customer");
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
        company_type: companyType,
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
            <label htmlFor="newCompanyType">Company type</label>
            <select
              id="newCompanyType"
              value={companyType}
              onChange={(event) => setCompanyType(event.target.value as typeof companyType)}
            >
              {COMPANY_TYPES.map((type) => (
                <option key={type} value={type} className="capitalize">
                  {type}
                </option>
              ))}
            </select>
          </div>
          <div className="formRow">
            <label htmlFor="newIndustry">Industry</label>
            <input id="newIndustry" value={industry} onChange={(event) => setIndustry(event.target.value)} />
          </div>
        </div>
        <div className="formGrid2">
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

type EditTab = "details" | "auth" | "licensing" | "products" | "ai" | "deploy";

function CompanyEditSheet({
  row,
  onClose,
  subscriptions,
  canManageLicensing,
  canViewLicensing,
  canManageCompany,
  canViewCompany,
  onLicenseAssigned,
  onError,
}: {
  row: CompanyRow | null;
  onClose: () => void;
  subscriptions: Subscription[];
  canManageLicensing: boolean;
  canViewLicensing: boolean;
  canManageCompany: boolean;
  canViewCompany: boolean;
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
        {(["details", "auth", "licensing", "products", "ai", "deploy"] as EditTab[]).map((t) => (
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
      {tab === "ai" ? (
        <AiTab
          row={row}
          canManage={canManageCompany}
          canView={canViewCompany}
          onError={onError}
        />
      ) : null}
      {tab === "deploy" ? <DeployTab row={row} onError={onError} /> : null}
    </SideSheet>
  );
}

function tabLabel(tab: EditTab): string {
  if (tab === "details") return "Details";
  if (tab === "auth") return "Authentication";
  if (tab === "licensing") return "Licensing";
  if (tab === "products") return "Products Hub";
  if (tab === "ai") return "AI";
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
          ["Company type", formatCompanyType(customer.company_type)],
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
// AI tab — per-tenant AI provider + BYO key
// ---------------------------------------------------------------------------

const DEFAULT_AI_FORM: CustomerAiSettingsUpdate = {
  provider_slug: "disabled",
  model: "none",
  endpoint: null,
  redact_pii_before_send: true,
  enabled: false,
  max_calls_per_day: 1000,
};

function AiTab({
  row,
  canManage,
  canView,
  onError,
}: {
  row: CompanyRow;
  canManage: boolean;
  canView: boolean;
  onError: (message: string) => void;
}) {
  const customerId = row.customer.id;
  const [providers, setProviders] = useState<AiProvider[]>([]);
  const [settings, setSettings] = useState<CustomerAiSettings | null>(null);
  const [form, setForm] = useState<CustomerAiSettingsUpdate>(DEFAULT_AI_FORM);
  const [apiKey, setApiKey] = useState<string>("");
  const [clearKey, setClearKey] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [isSaving, setIsSaving] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [success, setSuccess] = useState<string | null>(null);
  const [isProbing, setIsProbing] = useState(false);
  const [probe, setProbe] = useState<AiProbeResult | null>(null);

  const provider = useMemo(
    () => providers.find((p) => p.slug === form.provider_slug) ?? null,
    [providers, form.provider_slug],
  );

  const load = useCallback(async () => {
    setIsLoading(true);
    try {
      const [provs, current] = await Promise.all([
        apiGet<AiProvider[]>("/ai/providers"),
        apiGet<CustomerAiSettings | null>(`/companies/${customerId}/ai`),
      ]);
      setProviders(provs);
      setSettings(current);
      if (current) {
        setForm({
          provider_slug: current.provider_slug,
          model: current.model,
          endpoint: current.endpoint,
          redact_pii_before_send: current.redact_pii_before_send,
          enabled: current.enabled,
          max_calls_per_day: current.max_calls_per_day,
          data_residency: current.data_residency,
        });
      } else {
        setForm(DEFAULT_AI_FORM);
      }
      setApiKey("");
      setClearKey(false);
    } catch (err) {
      onError(err instanceof Error ? err.message : "Failed to load AI settings");
    } finally {
      setIsLoading(false);
    }
  }, [customerId, onError]);

  useEffect(() => {
    void load();
  }, [load]);

  if (!canView) {
    return (
      <div className="tabPanel">
        <p className="muted">You don't have permission to view AI settings for this company.</p>
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="tabPanel">
        <p className="muted">Loading AI settings…</p>
      </div>
    );
  }

  function chooseProvider(slug: string) {
    const next = providers.find((p) => p.slug === slug);
    if (!next) return;
    const firstModel = next.supported_models[0] ?? "";
    setForm((cur) => ({
      ...cur,
      provider_slug: slug,
      model: firstModel || cur.model,
      endpoint: next.default_endpoint,
    }));
  }

  async function save(event: FormEvent) {
    event.preventDefault();
    if (!canManage) return;
    setIsSaving(true);
    setSuccess(null);
    setProbe(null);
    try {
      const payload: CustomerAiSettingsUpdate = {
        ...form,
        api_key: apiKey.trim() ? apiKey.trim() : null,
        clear_api_key: clearKey,
      };
      const updated = await apiPut<CustomerAiSettings>(
        `/companies/${customerId}/ai`,
        payload,
      );
      setSettings(updated);
      setApiKey("");
      setClearKey(false);
      setSuccess("AI settings saved.");
    } catch (err) {
      onError(err instanceof Error ? err.message : "Failed to save AI settings");
    } finally {
      setIsSaving(false);
    }
  }

  async function executeRemove() {
    if (!canManage || !settings) return;
    setIsDeleting(true);
    setSuccess(null);
    try {
      await apiDelete(`/companies/${customerId}/ai`);
      setSettings(null);
      setForm(DEFAULT_AI_FORM);
      setApiKey("");
      setClearKey(false);
      setSuccess("AI settings cleared.");
    } catch (err) {
      onError(err instanceof Error ? err.message : "Failed to clear AI settings");
    } finally {
      setIsDeleting(false);
      setShowDeleteModal(false);
    }
  }

  async function runProbe() {
    if (!canManage) return;
    setIsProbing(true);
    setProbe(null);
    try {
      const result = await apiPost<AiProbeResult>(
        `/companies/${customerId}/ai/test`,
        {},
      );
      setProbe(result);
    } catch (err) {
      onError(err instanceof Error ? err.message : "Failed to test AI provider");
    } finally {
      setIsProbing(false);
    }
  }

  const requiresKey = provider?.requires_byo_key === true;
  const hasStoredKey = settings?.has_api_key === true;
  const disabledForm = !canManage;

  return (
    <form className="tabPanel" onSubmit={save}>
      <div className="muted formIntro">
        <Sparkles size={14} className="sparklesIcon" />
        Choose how semantic DLP and alert summarization route AI calls for{" "}
        <strong>{row.customer.name}</strong>. BYO API keys are encrypted at rest and never
        returned by the API.
      </div>

      {success ? <SuccessBanner message={success} /> : null}

      <fieldset disabled={disabledForm} className="fieldsetClean">
        <div className="formGrid2">
          <div className="formRow">
            <label htmlFor="aiProvider">Provider</label>
            <select
              id="aiProvider"
              value={form.provider_slug}
              onChange={(e) => chooseProvider(e.target.value)}
            >
              {providers.map((p) => (
                <option key={p.slug} value={p.slug}>
                  {p.display_name}
                  {p.requires_byo_key ? " · BYO key" : ""}
                </option>
              ))}
            </select>
            {provider?.notes ? <em className="muted">{provider.notes}</em> : null}
          </div>
          <div className="formRow">
            <label htmlFor="aiModel">Model</label>
            {provider && provider.supported_models.length > 0 ? (
              <select
                id="aiModel"
                value={form.model}
                onChange={(e) => setForm((cur) => ({ ...cur, model: e.target.value }))}
              >
                {provider.supported_models.map((m) => (
                  <option key={m} value={m}>
                    {m}
                  </option>
                ))}
              </select>
            ) : (
              <input
                id="aiModel"
                type="text"
                value={form.model}
                onChange={(e) => setForm((cur) => ({ ...cur, model: e.target.value }))}
              />
            )}
          </div>
        </div>

        <div className="formRow">
          <label htmlFor="aiEndpoint">Endpoint (optional override)</label>
          <input
            id="aiEndpoint"
            type="url"
            placeholder={provider?.default_endpoint ?? "Leave blank to use the provider default"}
            value={form.endpoint ?? ""}
            onChange={(e) =>
              setForm((cur) => ({
                ...cur,
                endpoint: e.target.value ? e.target.value : null,
              }))
            }
          />
        </div>

        {requiresKey ? (
          <div className="formRow">
            <label htmlFor="aiKey">
              API key
              <span className="muted withMargin">
                {hasStoredKey
                  ? `stored · ****${settings?.api_key_last4 ?? ""}`
                  : "not configured"}
              </span>
            </label>
            <input
              id="aiKey"
              type="password"
              autoComplete="off"
              placeholder={hasStoredKey ? "Leave blank to keep existing key" : "Paste BYO API key"}
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
            />
            {hasStoredKey ? (
              <label className="checkboxRow">
                <input
                  type="checkbox"
                  checked={clearKey}
                  onChange={(e) => setClearKey(e.target.checked)}
                />
                <span>Remove stored API key</span>
              </label>
            ) : null}
          </div>
        ) : null}

        <div className="formGrid2">
          <div className="formRow">
            <label htmlFor="aiLimit">Daily call limit</label>
            <input
              id="aiLimit"
              type="number"
              min={0}
              max={1_000_000}
              value={form.max_calls_per_day ?? 1000}
              onChange={(e) =>
                setForm((cur) => ({
                  ...cur,
                  max_calls_per_day: Math.max(0, Number(e.target.value) || 0),
                }))
              }
            />
          </div>
          <div className="formRow">
            <label htmlFor="aiResidency">Data residency (optional)</label>
            <input
              id="aiResidency"
              type="text"
              placeholder="e.g. EU, US, on-prem"
              value={form.data_residency ?? ""}
              onChange={(e) =>
                setForm((cur) => ({
                  ...cur,
                  data_residency: e.target.value ? e.target.value : null,
                }))
              }
            />
          </div>
        </div>

        <label className="checkboxRow">
          <input
            type="checkbox"
            checked={form.redact_pii_before_send ?? true}
            onChange={(e) =>
              setForm((cur) => ({ ...cur, redact_pii_before_send: e.target.checked }))
            }
          />
          <span>Redact PII before sending to provider</span>
        </label>

        <label className="checkboxRow">
          <input
            type="checkbox"
            checked={form.enabled ?? false}
            onChange={(e) => setForm((cur) => ({ ...cur, enabled: e.target.checked }))}
          />
          <span>Enable AI calls for this company</span>
        </label>
      </fieldset>

      <div className="formActions">
        <button type="submit" className="btnPrimary" disabled={disabledForm || isSaving}>
          {isSaving ? "Saving…" : settings ? "Save changes" : "Save settings"}
        </button>
        {settings ? (
          <button
            type="button"
            className="btnGhost"
            onClick={runProbe}
            disabled={disabledForm || isProbing}
            title="Send a minimal request to the configured provider to verify the credentials and endpoint."
          >
            {isProbing ? "Testing…" : "Test connection"}
          </button>
        ) : null}
        {settings ? (
          <>
            <button
              type="button"
              className="btnGhost"
              onClick={() => setShowDeleteModal(true)}
              disabled={disabledForm || isDeleting}
            >
              {isDeleting ? "Removing…" : "Reset to platform default"}
            </button>
            <ConfirmModal
              open={showDeleteModal}
              title="Reset AI Settings"
              message="Remove AI settings for this company? Tenant calls will fall back to platform defaults."
              confirmLabel="Reset"
              isDanger
              isBusy={isDeleting}
              onConfirm={() => void executeRemove()}
              onCancel={() => setShowDeleteModal(false)}
            />
          </>
        ) : null}
        {!canManage ? (
          <span className="muted">Read-only — companies:manage required to change AI settings.</span>
        ) : null}
      </div>
      {probe ? (
        <div
          className="muted"
          style={{
            marginTop: 8,
            padding: "8px 10px",
            borderRadius: 6,
            background: probe.ok ? "rgba(38, 145, 87, 0.12)" : "rgba(176, 60, 60, 0.12)",
            color: probe.ok ? "#1e7c47" : "#9b2c2c",
          }}
        >
          <strong>{probe.ok ? "OK" : "Failed"}</strong>
          {probe.latency_ms != null ? ` · ${probe.latency_ms}ms` : ""}
          {probe.status_code != null ? ` · HTTP ${probe.status_code}` : ""}
          {probe.message ? ` — ${probe.message}` : ""}
        </div>
      ) : null}
    </form>
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

function getSigningBadge(signingStatus: string | null | undefined, buildStatus: string): { label: string; variant: "pending" | "notarized" | "signed" | "unsigned" } {
  if (buildStatus === "queued") {
    return { label: "Verification Pending", variant: "pending" };
  }
  if (signingStatus === "notarized") {
    return { label: "Notarized (Apple Dev / Microsoft WHQL)", variant: "notarized" };
  }
  if (signingStatus === "signed") {
    return { label: "Signed (Symantec EV)", variant: "signed" };
  }
  return { label: "Unsigned (Warning)", variant: "unsigned" };
}

function getTtlRemainingText(expiresAtStr: string | null | undefined): string {
  if (!expiresAtStr) return "no expiry";
  const expiresAt = new Date(expiresAtStr).getTime();
  const now = new Date().getTime();
  const diffMs = expiresAt - now;
  if (diffMs <= 0) return "expired";
  
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMins / 60);
  const diffDays = Math.floor(diffHours / 24);
  
  if (diffDays > 0) {
    return `${diffDays}d ${diffHours % 24}h remaining`;
  }
  if (diffHours > 0) {
    return `${diffHours}h ${diffMins % 60}m remaining`;
  }
  if (diffMins > 0) {
    return `${diffMins}m remaining`;
  }
  return "expires soon";
}

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
            {installers.map((build) => {
              const signing = getSigningBadge(build.signing_status, build.status);
              const remaining = getTtlRemainingText(build.expires_at);
              return (
                <div className="installerRow" key={build.id}>
                  <div className="installerRowMain">
                    <div style={{ display: "flex", alignItems: "center", gap: "8px", flexWrap: "wrap" }}>
                      <span className="platformName">{build.platform}</span>
                      <em className={`statusPill status-${build.status === "ready" ? "active" : build.status === "failed" ? "expired" : "trial"}`}>{build.status}</em>
                      <span className={`signingBadge ${signing.variant}`}>{signing.label}</span>
                    </div>
                    {build.artifact_sha256 && (
                      <div style={{ marginTop: "4px" }}>
                        <CopyChip
                          label="SHA-256"
                          value={build.artifact_sha256}
                          icon={<ShieldCheck size={12} style={{ color: "var(--healthy)" }} />}
                        />
                      </div>
                    )}
                  </div>
                  <span className="installerRowMeta">
                    <Clock size={12} /> {remaining}
                  </span>
                  <div className="installerRowActions">
                    {build.artifact_url ? (
                      <>
                        <button
                          type="button"
                          className="iconBtn"
                          onClick={() => void copy(build.artifact_url ?? "")}
                          aria-label="Copy artifact URL"
                          title="Copy download link"
                        >
                          <Copy size={14} />
                        </button>
                        <a
                          href={build.artifact_url}
                          download
                          className="iconBtn"
                          aria-label="Download artifact"
                          title="Download installer file"
                        >
                          <Download size={14} />
                        </a>
                      </>
                    ) : (
                      <span className="muted" style={{ fontSize: "12px" }}>queued</span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </fieldset>
      ) : null}

      {links.length > 0 ? (
        <fieldset className="fieldsetClean">
          <legend><Link2 size={14} /> Quick-deploy links</legend>
          <div className="installerList">
            {links.map((link) => {
              const remaining = getTtlRemainingText(link.expires_at);
              return (
                <div className="installerRow" key={link.id}>
                  <div className="installerRowMain">
                    <div style={{ display: "flex", alignItems: "center", gap: "8px", flexWrap: "wrap" }}>
                      <span className="platformName">{link.platform ?? "any"}</span>
                      <em className="muted" style={{ fontSize: "11px", fontStyle: "normal" }}>{link.download_count}{link.max_downloads ? ` / ${link.max_downloads}` : ""} downloads</em>
                    </div>
                    <code style={{ fontSize: "11px", color: "var(--muted)", wordBreak: "break-all" }}>{link.url}</code>
                  </div>
                  <span className="installerRowMeta">
                    <Clock size={12} /> {remaining}
                  </span>
                  <button type="button" className="iconBtn" onClick={() => void copy(link.url)} aria-label="Copy link" title="Copy quick deploy link">
                    <Copy size={14} />
                  </button>
                </div>
              );
            })}
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
