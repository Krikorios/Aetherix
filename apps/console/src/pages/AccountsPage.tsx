import { FormEvent, useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Copy,
  KeyRound,
  Link2,
  Mail,
  Plus,
  RefreshCw,
  Search,
  ShieldCheck,
  Trash2,
  UserCog,
  UserPlus,
  X,
} from "lucide-react";
import {
  apiDelete,
  apiGet,
  apiPost,
  type Account,
  type BulkActionResult,
  type AccountCreated,
  type AccountCreatePayload,
  type AccountStatus,
  type Customer,
  type InviteDelivery,
  type MeResponse,
  type Partner,
  type Role,
  type RoleAssignment,
  type RoleAssignmentRequest,
  type RoleCode,
  type TwoFactorState,
} from "../api";
import {
  ConfirmModal,
  EmptyState,
  ErrorBanner,
  LoadingRow,
  PageHeader,
  SideSheet,
  SuccessBanner,
} from "../components";

const ROLE_LABEL: Record<RoleCode, string> = {
  platform_owner: "Platform Owner",
  msp_partner: "MSP Partner",
  company_admin: "Company Administrator",
  company_tech: "Company Technician",
  company_viewer: "Company Viewer",
};

const STATUS_LABEL: Record<AccountStatus, string> = {
  invited: "Invited",
  active: "Active",
  locked: "Locked",
  suspended: "Suspended",
};

const TWOFA_LABEL: Record<TwoFactorState, string> = {
  missing: "Missing",
  enabled: "Enabled",
  enforced: "Enforced",
};

type PermissionLevel = "none" | "view" | "edit" | "manage";

const PERMISSION_RANK: Record<PermissionLevel, number> = {
  none: 0,
  view: 1,
  edit: 2,
  manage: 3,
};

const ROLE_PERMISSIONS: Record<RoleCode, Record<string, PermissionLevel>> = {
  platform_owner: {
    accounts: "manage",
    policies: "manage",
    companies: "manage",
    incidents: "manage",
    licensing: "manage",
    impersonate: "manage",
  },
  msp_partner: {
    accounts: "manage",
    policies: "manage",
    companies: "manage",
    incidents: "manage",
    licensing: "manage",
    impersonate: "edit",
  },
  company_admin: {
    accounts: "manage",
    policies: "edit",
    companies: "view",
    incidents: "manage",
    licensing: "view",
    impersonate: "none",
  },
  company_tech: {
    accounts: "none",
    policies: "edit",
    companies: "view",
    incidents: "edit",
    licensing: "none",
    impersonate: "none",
  },
  company_viewer: {
    accounts: "none",
    policies: "view",
    companies: "view",
    incidents: "view",
    licensing: "view",
    impersonate: "none",
  },
};

const COMPANY_FILTER_ALL = "__all__";

export function AccountsPage() {
  const [me, setMe] = useState<MeResponse | null>(null);
  const [accounts, setAccounts] = useState<Account[]>([]);
  const [roles, setRoles] = useState<Role[]>([]);
  const [companies, setCompanies] = useState<Customer[]>([]);
  const [partners, setPartners] = useState<Partner[]>([]);

  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const [query, setQuery] = useState("");
  const [roleFilter, setRoleFilter] = useState<RoleCode | "all">("all");
  const [statusFilter, setStatusFilter] = useState<AccountStatus | "all">("all");
  const [companyFilter, setCompanyFilter] = useState<string>(COMPANY_FILTER_ALL);
  const [twoFactorFilter, setTwoFactorFilter] = useState<TwoFactorState | "all">("all");

  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [editing, setEditing] = useState<Account | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [bulkDeleteModal, setBulkDeleteModal] = useState(false);
  const [isBulkDeleting, setIsBulkDeleting] = useState(false);
  const mountedRef = useRef(true);

  const load = useCallback(async () => {
    setIsLoading(true);
    try {
      const [acc, rls, cmps, pts] = await Promise.all([
        apiGet<Account[]>("/accounts"),
        apiGet<Role[]>("/roles"),
        apiGet<Customer[]>("/companies"),
        apiGet<Partner[]>("/partners").catch(() => [] as Partner[]),
      ]);
      if (!mountedRef.current) return;
      setAccounts(acc);
      setRoles(rls);
      setCompanies(cmps);
      setPartners(pts);
      setError(null);
    } catch (err) {
      if (mountedRef.current) setError(err instanceof Error ? err.message : "Failed to load accounts");
    } finally {
      if (mountedRef.current) setIsLoading(false);
    }
  }, []);

  const loadMe = useCallback(async () => {
    try {
      const next = await apiGet<MeResponse>("/me");
      if (!mountedRef.current) return;
      setMe(next);
      await load();
    } catch (err) {
      if (mountedRef.current) {
        setMe(null);
        setError(err instanceof Error ? err.message : "Auth failed");
        setIsLoading(false);
      }
    }
  }, [load]);

  useEffect(() => {
    mountedRef.current = true;
    void loadMe();
    return () => {
      mountedRef.current = false;
    };
  }, [loadMe]);

  const canManage = (me?.permissions.accounts ?? "none") === "manage";

  // ---------- derived lookups ----------
  const companyMap = useMemo(() => new Map(companies.map((c) => [c.id, c])), [companies]);
  const partnerMap = useMemo(() => new Map(partners.map((p) => [p.id, p])), [partners]);
  const roleMap = useMemo(() => new Map(roles.map((r) => [r.code, r])), [roles]);

  // ---------- filtering ----------
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return accounts.filter((account) => {
      if (q && !`${account.full_name} ${account.email}`.toLowerCase().includes(q)) return false;
      if (statusFilter !== "all" && account.status !== statusFilter) return false;
      if (roleFilter !== "all" && !account.roles.some((r) => r.role_code === roleFilter)) return false;
      if (twoFactorFilter !== "all" && account.two_factor !== twoFactorFilter) return false;
      if (companyFilter !== COMPANY_FILTER_ALL) {
        const scopeMatches = account.roles.some((r) => {
          if (r.customer_id === companyFilter) return true;
          const company = companyMap.get(companyFilter);
          if (!company) return false;
          return r.partner_id === company.partner_id;
        });
        if (!scopeMatches) return false;
      }
      return true;
    });
  }, [accounts, query, statusFilter, roleFilter, companyFilter, twoFactorFilter, companyMap]);

  // ---------- actions ----------
  async function executeBulkDelete() {
    if (!canManage || selectedIds.length === 0) return;
    const ids = selectedIds.filter((id) => id !== me?.account.id);
    if (ids.length === 0) {
      setError("You cannot delete your own account.");
      setBulkDeleteModal(false);
      return;
    }
    setIsBulkDeleting(true);
    try {
      const result = await apiPost<BulkActionResult>("/accounts/bulk-delete", { ids });
      setSelectedIds([]);
      if (result.failures.length) {
        setError(`${result.failures.length} delete(s) failed: ${result.failures[0].error}`);
      } else {
        setError(null);
      }
      setSuccess(`Deleted ${result.ok_count} account${result.ok_count === 1 ? "" : "s"}.`);
      void load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Bulk action failed");
    } finally {
      setIsBulkDeleting(false);
      setBulkDeleteModal(false);
    }
  }

  if (!me) {
    return (
      <>
        <PageHeader eyebrow="Identity" title="Accounts" />
        {error ? <ErrorBanner message={error} /> : null}
        <section className="panel">
          <EmptyState>
            Please{" "}
            <span
              className="linkLike"
              role="button"
              tabIndex={0}
              onClick={() => window.dispatchEvent(new CustomEvent("aetherix:navigate", { detail: { page: "companies" } }))}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  window.dispatchEvent(new CustomEvent("aetherix:navigate", { detail: { page: "companies" } }));
                }
              }}
            >
              sign in
            </span>{" "}
            to view accounts.
          </EmptyState>
        </section>
      </>
    );
  }

  return (
    <>
      <PageHeader
        eyebrow={me.scope.is_platform ? "Platform owner" : me.scope.partner_ids.length ? "MSP partner" : "Company user"}
        title="Accounts"
        subtitle={`${accounts.length} ${accounts.length === 1 ? "account" : "accounts"} in scope.`}
      />
      {error ? <ErrorBanner message={error} /> : null}
      {success ? <SuccessBanner message={success} /> : null}

      <section className="accountToolbar">
        <div className="accountFiltersGroup">
          <div className="searchBox">
            <Search size={16} />
            <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Full name or email" />
          </div>
          <select value={roleFilter} onChange={(event) => setRoleFilter(event.target.value as RoleCode | "all")} aria-label="Role filter">
            <option value="all">All roles</option>
            {roles.map((r) => (
              <option key={r.code} value={r.code}>{ROLE_LABEL[r.code]}</option>
            ))}
          </select>
          <select value={statusFilter} onChange={(event) => setStatusFilter(event.target.value as AccountStatus | "all")} aria-label="Status filter">
            <option value="all">All statuses</option>
            <option value="active">Active</option>
            <option value="invited">Invited</option>
            <option value="locked">Locked</option>
            <option value="suspended">Suspended</option>
          </select>
          <select value={companyFilter} onChange={(event) => setCompanyFilter(event.target.value)} aria-label="Company filter">
            <option value={COMPANY_FILTER_ALL}>All recursively</option>
            {companies.map((c) => (
              <option key={c.id} value={c.id}>{c.name}</option>
            ))}
          </select>
          <select value={twoFactorFilter} onChange={(event) => setTwoFactorFilter(event.target.value as TwoFactorState | "all")} aria-label="2FA filter">
            <option value="all">All 2FA states</option>
            <option value="missing">2FA: Missing</option>
            <option value="enabled">2FA: Enabled</option>
            <option value="enforced">2FA: Enforced</option>
          </select>
        </div>
        <div className="accountActionsGroup">
          <button type="button" className="btnGhost" onClick={() => void load()}><RefreshCw size={16} /> Refresh</button>
          {canManage ? (
            <>
              <button type="button" className="btnDanger" disabled={selectedIds.length === 0} onClick={() => setBulkDeleteModal(true)}>
                <Trash2 size={16} /> Delete ({selectedIds.length})
              </button>
              <button type="button" className="btnPrimary" onClick={() => setShowCreate(true)}>
                <UserPlus size={16} /> Add account
              </button>
            </>
          ) : null}
        </div>
      </section>

      <section className="panel accountTablePanel">
        <div className="accountTableHead">
          <span />
          <span>Full name</span>
          <span>Email</span>
          <span>Status</span>
          <span>Roles</span>
          <span>2FA</span>
          <span>Last login</span>
          <span>Created</span>
        </div>
        {isLoading ? <LoadingRow label="Loading accounts" /> : null}
        {!isLoading && filtered.length === 0 ? (
          <EmptyState>No accounts match the current filters.</EmptyState>
        ) : null}
        {filtered.map((account) => {
          const checked = selectedIds.includes(account.id);
          return (
            <button className="accountRow" key={account.id} type="button" onClick={() => setEditing(account)}>
              <input
                type="checkbox"
                checked={checked}
                disabled={!canManage}
                onChange={(event) => {
                  event.stopPropagation();
                  setSelectedIds((current) => (event.target.checked ? [...current, account.id] : current.filter((id) => id !== account.id)));
                }}
                onClick={(event) => event.stopPropagation()}
                aria-label={`Select ${account.full_name}`}
              />
              <strong>{account.full_name}</strong>
              <span>{account.email}</span>
              <span className={`statusPill status-${account.status}`}>{STATUS_LABEL[account.status]}</span>
              <span className="roleStack">
                {account.roles.length === 0 ? <em className="muted">No roles</em> : account.roles.map((r) => (
                  <em key={r.id} className="pillSubtle">{ROLE_LABEL[r.role_code]}</em>
                ))}
              </span>
              <span>{TWOFA_LABEL[account.two_factor]}</span>
              <span>{account.last_login_at ? formatDate(account.last_login_at) : "—"}</span>
              <span>{formatDate(account.created_at)}</span>
            </button>
          );
        })}
      </section>

      <section className="panel matrixPanel">
        <header className="matrixPanelHeader">
          <ShieldCheck size={18} style={{ color: "var(--primary)" }} /> 
          <div>
            <h3 style={{ margin: 0, fontSize: "16px", fontWeight: 700 }}>Platform Permissions &amp; Role Matrix Reference</h3>
            <p className="muted" style={{ margin: "2px 0 0 0", fontSize: "13px" }}>Unified overview of role capability thresholds across all Aetherix resources.</p>
          </div>
        </header>

        {/* Desktop responsive matrix table */}
        <div className="matrixTableWrapper">
          <table className="matrixTable">
            <thead>
              <tr>
                <th>Role</th>
                <th>Scope</th>
                <th>Accounts</th>
                <th>Policies</th>
                <th>Companies</th>
                <th>Incidents</th>
                <th>Licensing</th>
                <th>Impersonation</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td><strong>Platform Owner</strong></td>
                <td><span className="matrixScope">Global (All)</span></td>
                <td><span className="statusPill status-manage">manage</span></td>
                <td><span className="statusPill status-manage">manage</span></td>
                <td><span className="statusPill status-manage">manage</span></td>
                <td><span className="statusPill status-manage">manage</span></td>
                <td><span className="statusPill status-manage">manage</span></td>
                <td><span className="statusPill status-manage">manage</span></td>
              </tr>
              <tr>
                <td><strong>MSP Partner</strong></td>
                <td><span className="matrixScope">Partner level</span></td>
                <td><span className="statusPill status-manage">manage</span></td>
                <td><span className="statusPill status-manage">manage</span></td>
                <td><span className="statusPill status-manage">manage</span></td>
                <td><span className="statusPill status-manage">manage</span></td>
                <td><span className="statusPill status-manage">manage</span></td>
                <td><span className="statusPill status-edit">edit</span></td>
              </tr>
              <tr>
                <td><strong>Company Administrator</strong></td>
                <td><span className="matrixScope">Company scope</span></td>
                <td><span className="statusPill status-manage">manage</span></td>
                <td><span className="statusPill status-edit">edit</span></td>
                <td><span className="statusPill status-view">view</span></td>
                <td><span className="statusPill status-manage">manage</span></td>
                <td><span className="statusPill status-view">view</span></td>
                <td><span className="statusPill status-none">none</span></td>
              </tr>
              <tr>
                <td><strong>Company Technician</strong></td>
                <td><span className="matrixScope">Assigned companies</span></td>
                <td><span className="statusPill status-none">none</span></td>
                <td><span className="statusPill status-edit">edit</span></td>
                <td><span className="statusPill status-view">view</span></td>
                <td><span className="statusPill status-edit">edit</span></td>
                <td><span className="statusPill status-none">none</span></td>
                <td><span className="statusPill status-none">none</span></td>
              </tr>
              <tr>
                <td><strong>Company Viewer</strong></td>
                <td><span className="matrixScope">Read-only view</span></td>
                <td><span className="statusPill status-none">none</span></td>
                <td><span className="statusPill status-view">view</span></td>
                <td><span className="statusPill status-view">view</span></td>
                <td><span className="statusPill status-view">view</span></td>
                <td><span className="statusPill status-view">view</span></td>
                <td><span className="statusPill status-none">none</span></td>
              </tr>
            </tbody>
          </table>
        </div>

        {/* Mobile responsive cards view */}
        <div className="matrixMobileCards">
          {[
            {
              role: "Platform Owner",
              scope: "Global (All)",
              perms: { accounts: "manage", policies: "manage", companies: "manage", incidents: "manage", licensing: "manage", impersonate: "manage" }
            },
            {
              role: "MSP Partner",
              scope: "Partner level",
              perms: { accounts: "manage", policies: "manage", companies: "manage", incidents: "manage", licensing: "manage", impersonate: "edit" }
            },
            {
              role: "Company Administrator",
              scope: "Company scope",
              perms: { accounts: "manage", policies: "edit", companies: "view", incidents: "manage", licensing: "view", impersonate: "none" }
            },
            {
              role: "Company Technician",
              scope: "Assigned companies",
              perms: { accounts: "none", policies: "edit", companies: "view", incidents: "edit", licensing: "none", impersonate: "none" }
            },
            {
              role: "Company Viewer",
              scope: "Read-only view",
              perms: { accounts: "none", policies: "view", companies: "view", incidents: "view", licensing: "view", impersonate: "none" }
            }
          ].map((item) => (
            <div key={item.role} className="matrixCard">
              <div className="matrixCardHead">
                <strong style={{ fontSize: "14px", fontWeight: 700 }}>{item.role}</strong>
                <span className="matrixCardScope">{item.scope}</span>
              </div>
              <div className="matrixCardBody">
                {Object.entries(item.perms).map(([res, lvl]) => (
                  <div key={res} className="matrixCardRow">
                    <span className="matrixCardRowLabel">{res}</span>
                    <span className={`statusPill status-${lvl}`}>{lvl}</span>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </section>

      <ConfirmModal
        open={bulkDeleteModal}
        title="Permanently Delete Accounts"
        message={`You are about to delete ${selectedIds.length} ${selectedIds.length === 1 ? "account" : "accounts"}. This removes all of their role assignments and login challenges. This cannot be undone.`}
        confirmLabel="Delete"
        isDanger
        isBusy={isBulkDeleting}
        requireReason
        onConfirm={(reason) => void executeBulkDelete()}
        onCancel={() => setBulkDeleteModal(false)}
      />

      <CreateAccountSheet
        open={showCreate}
        roles={roles}
        companies={companies}
        partners={partners}
        canManage={canManage}
        onClose={() => setShowCreate(false)}
        onCreated={(result) => {
          setAccounts((current) => [result.account, ...current]);
          setSuccess(null);
        }}
        onError={(message) => setError(message)}
      />

      <AccountEditSheet
        account={editing}
        meId={me.account.id}
        roles={roles}
        companies={companies}
        partners={partners}
        canManage={canManage}
        roleMap={roleMap}
        companyMap={companyMap}
        partnerMap={partnerMap}
        onClose={() => setEditing(null)}
        onChanged={(updated) => {
          setAccounts((current) => current.map((a) => (a.id === updated.id ? updated : a)));
          setEditing(updated);
        }}
        onDeleted={(deletedId) => {
          setAccounts((current) => current.filter((a) => a.id !== deletedId));
          setEditing(null);
        }}
        onError={(message) => setError(message)}
      />
    </>
  );
}

// ---------------------------------------------------------------------------
// Create Account
// ---------------------------------------------------------------------------

function CreateAccountSheet({
  open,
  roles,
  companies,
  partners,
  canManage,
  onClose,
  onCreated,
  onError,
}: {
  open: boolean;
  roles: Role[];
  companies: Customer[];
  partners: Partner[];
  canManage: boolean;
  onClose: () => void;
  onCreated: (result: AccountCreated) => void;
  onError: (message: string) => void;
}) {
  const [email, setEmail] = useState("");
  const [fullName, setFullName] = useState("");
  const [roleCode, setRoleCode] = useState<RoleCode>("company_admin");
  const [partnerId, setPartnerId] = useState<string>("");
  const [customerId, setCustomerId] = useState<string>("");
  const [delivery, setDelivery] = useState<InviteDelivery>("email");
  const [isSaving, setIsSaving] = useState(false);
  const [inviteResult, setInviteResult] = useState<AccountCreated | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!open) return;
    setEmail("");
    setFullName("");
    setRoleCode("company_admin");
    setPartnerId(partners[0]?.id ?? "");
    setCustomerId(companies[0]?.id ?? "");
    setDelivery("email");
    setInviteResult(null);
    setCopied(false);
  }, [open, partners, companies]);

  const needsPartner = roleCode === "msp_partner";
  const needsCompany = roleCode === "company_admin" || roleCode === "company_tech" || roleCode === "company_viewer";

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!canManage) return;
    setIsSaving(true);
    try {
      const initial: RoleAssignmentRequest | null =
        roleCode === "platform_owner"
          ? { role_code: roleCode }
          : needsPartner
            ? { role_code: roleCode, partner_id: partnerId || null }
            : needsCompany
              ? { role_code: roleCode, customer_id: customerId || null }
              : null;
      const payload: AccountCreatePayload = {
        email: email.trim(),
        full_name: fullName.trim(),
        initial_role: initial,
        delivery,
        created_by: "console",
      };
      const created = await apiPost<AccountCreated>("/accounts", payload);
      setInviteResult(created);
      onCreated(created);
    } catch (err) {
      onError(err instanceof Error ? err.message : "Failed to create account");
    } finally {
      setIsSaving(false);
    }
  }

  async function copyInviteUrl() {
    if (!inviteResult?.invite_url) return;
    try {
      await navigator.clipboard.writeText(inviteResult.invite_url);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard API may be unavailable (e.g. insecure context); fall back
      // to selecting the text so the user can copy manually.
      const input = document.getElementById("inviteLinkValue") as HTMLInputElement | null;
      input?.select();
    }
  }

  return (
    <SideSheet open={open} onClose={onClose} title="Add account" subtitle="Invite a user and assign their first role" width={560}>
      {inviteResult ? (
        inviteResult.delivery === "email" ? (
          <div className="inviteSuccessWrapper emailInviteSuccess">
            <div className="inviteSuccessIcon emailIconContainer">
              <Mail size={42} style={{ color: "var(--success)" }} />
            </div>
            <h3>Invitation Email Queued</h3>
            <p className="inviteSuccessDesc">
              We&rsquo;ve successfully queued an invitation email for <strong>{inviteResult.account.email}</strong>. 
              The system emails them a secure setup link directly.
            </p>
            <div className="inviteDetailFields">
              <div className="formRow">
                <label className="muted">Recipient Name</label>
                <strong>{inviteResult.account.full_name}</strong>
              </div>
              <div className="formRow">
                <label className="muted">Delivery Method</label>
                <span>Aetherix SMTP Mailer</span>
              </div>
              <div className="formRow">
                <label className="muted">Token State</label>
                <code style={{ fontSize: "11px" }}>SHA-256 Hashed & Persisted</code>
              </div>
            </div>
            <div className="formActions" style={{ justifyContent: "center" }}>
              <button type="button" className="btnPrimary" onClick={onClose}>Done</button>
            </div>
          </div>
        ) : (
          <div className="inviteSuccessWrapper linkInviteSuccess">
            <div className="inviteSuccessIcon linkIconContainer">
              <Link2 size={42} style={{ color: "var(--primary)" }} />
            </div>
            <h3>Manual Setup Link Active</h3>
            <p className="inviteSuccessDesc">
              A one-time registration link is ready for manual distribution to <strong>{inviteResult.account.email}</strong>.
            </p>
            <div className="formRow">
              <label htmlFor="inviteLinkValue">Secure Setup URL</label>
              <div style={{ display: "flex", gap: 8, marginTop: 4 }}>
                <input
                  id="inviteLinkValue"
                  readOnly
                  value={inviteResult.invite_url || ""}
                  onFocus={(event) => event.currentTarget.select()}
                  style={{ flex: 1 }}
                />
                <button type="button" className="btnSecondary" onClick={() => void copyInviteUrl()}>
                  <Copy size={16} /> {copied ? "Copied" : "Copy"}
                </button>
              </div>
              {inviteResult.invite_expires_at ? (
                <small className="muted" style={{ display: "block", marginTop: 6 }}>
                  Expires {new Date(inviteResult.invite_expires_at).toLocaleString()}. The link can only be used once. Do not share via insecure public channels.
                </small>
              ) : null}
            </div>
            <div className="formActions" style={{ justifyContent: "center", marginTop: 24 }}>
              <button type="button" className="btnPrimary" onClick={onClose}>Done</button>
            </div>
          </div>
        )
      ) : (
        <form className="formStack" onSubmit={submit}>
          <div className="formGrid2">
            <div className="formRow">
              <label htmlFor="acctName">Full name</label>
              <input id="acctName" required value={fullName} onChange={(event) => setFullName(event.target.value)} />
            </div>
            <div className="formRow">
              <label htmlFor="acctEmail">Email</label>
              <input id="acctEmail" required type="email" value={email} onChange={(event) => setEmail(event.target.value)} />
            </div>
          </div>
          <div className="formRow">
            <label htmlFor="acctRole">Role</label>
            <select id="acctRole" value={roleCode} onChange={(event) => setRoleCode(event.target.value as RoleCode)}>
              {roles.map((r) => (
                <option key={r.code} value={r.code}>{ROLE_LABEL[r.code]}</option>
              ))}
            </select>
          </div>
          {needsPartner ? (
            <div className="formRow">
              <label htmlFor="acctPartner">Partner</label>
              <select id="acctPartner" value={partnerId} onChange={(event) => setPartnerId(event.target.value)}>
                {partners.map((p) => (
                  <option key={p.id} value={p.id}>{p.name}</option>
                ))}
              </select>
            </div>
          ) : null}
          {needsCompany ? (
            <div className="formRow">
              <label htmlFor="acctCompany">Company</label>
              <select id="acctCompany" value={customerId} onChange={(event) => setCustomerId(event.target.value)}>
                {companies.map((c) => (
                  <option key={c.id} value={c.id}>{c.name}</option>
                ))}
              </select>
            </div>
          ) : null}
          <fieldset className="deliveryChoice">
            <legend>Invitation Delivery Channels</legend>
            <div className="deliveryOptionsGrid">
              <label className={`deliveryOptionCard ${delivery === "email" ? "active" : ""}`} onClick={() => setDelivery("email")}>
                <input
                  type="radio"
                  name="acctDelivery"
                  value="email"
                  checked={delivery === "email"}
                  onChange={() => setDelivery("email")}
                  aria-describedby="emailDesc"
                />
                <div className="deliveryOptionContent">
                  <div className="deliveryOptionHeader">
                    <Mail size={16} style={{ color: delivery === "email" ? "var(--primary)" : "var(--muted)" }} />
                    <strong>Send invitation email</strong>
                  </div>
                  <span id="emailDesc" className="deliveryOptionSub">The system emails them a secure setup link directly.</span>
                </div>
              </label>

              <label className={`deliveryOptionCard ${delivery === "link" ? "active" : ""}`} onClick={() => setDelivery("link")}>
                <input
                  type="radio"
                  name="acctDelivery"
                  value="link"
                  checked={delivery === "link"}
                  onChange={() => setDelivery("link")}
                  aria-describedby="linkDesc"
                />
                <div className="deliveryOptionContent">
                  <div className="deliveryOptionHeader">
                    <Link2 size={16} style={{ color: delivery === "link" ? "var(--primary)" : "var(--muted)" }} />
                    <strong>Manual Link Generation</strong>
                  </div>
                  <span id="linkDesc" className="deliveryOptionSub">Get a setup link to copy and forward manually offband.</span>
                </div>
              </label>
            </div>
          </fieldset>
          <div className="formActions">
            <button type="button" className="btnGhost" onClick={onClose}>Cancel</button>
            <button type="submit" className="btnPrimary" disabled={isSaving || !email.trim() || !fullName.trim()}>
              {isSaving ? <RefreshCw size={16} className="spinIcon" /> : delivery === "link" ? <Link2 size={16} /> : <Plus size={16} />}
              {isSaving
                ? (delivery === "link" ? "Generating" : "Inviting")
                : (delivery === "link" ? "Generate link" : "Send invite")}
            </button>
          </div>
        </form>
      )}
    </SideSheet>
  );
}

// ---------------------------------------------------------------------------
// Edit Account — add/revoke role assignments
// ---------------------------------------------------------------------------

function AccountEditSheet({
  account,
  meId,
  roles,
  companies,
  partners,
  canManage,
  roleMap,
  companyMap,
  partnerMap,
  onClose,
  onChanged,
  onDeleted,
  onError,
}: {
  account: Account | null;
  meId: string;
  roles: Role[];
  companies: Customer[];
  partners: Partner[];
  canManage: boolean;
  roleMap: Map<RoleCode, Role>;
  companyMap: Map<string, Customer>;
  partnerMap: Map<string, Partner>;
  onClose: () => void;
  onChanged: (next: Account) => void;
  onDeleted: (id: string) => void;
  onError: (message: string) => void;
}) {
  const [newRole, setNewRole] = useState<RoleCode>("company_admin");
  const [newPartnerId, setNewPartnerId] = useState("");
  const [newCustomerId, setNewCustomerId] = useState("");
  const [busy, setBusy] = useState(false);
  const [revokeModal, setRevokeModal] = useState<string | null>(null);
  const [deleteModal, setDeleteModal] = useState(false);

  const effectivePermissions = useMemo(() => {
    const result: Record<string, PermissionLevel> = {
      accounts: "none",
      policies: "none",
      companies: "none",
      incidents: "none",
      licensing: "none",
      impersonate: "none",
    };

    if (!account) return result;

    for (const r of account.roles) {
      const rolePerms = ROLE_PERMISSIONS[r.role_code];
      if (!rolePerms) continue;
      for (const [key, level] of Object.entries(rolePerms)) {
        const currentVal = result[key] || "none";
        if (PERMISSION_RANK[level] > PERMISSION_RANK[currentVal]) {
          result[key] = level;
        }
      }
    }
    return result;
  }, [account]);

  useEffect(() => {
    if (!account) return;
    setNewRole("company_admin");
    setNewPartnerId(partners[0]?.id ?? "");
    setNewCustomerId(companies[0]?.id ?? "");
  }, [account?.id, partners, companies]);

  if (!account) return null;

  const needsPartner = newRole === "msp_partner";
  const needsCompany = newRole === "company_admin" || newRole === "company_tech" || newRole === "company_viewer";

  async function reloadAccount() {
    if (!account) return;
    try {
      const refreshed = await apiGet<Account>(`/accounts/${account.id}`);
      onChanged(refreshed);
    } catch (err) {
      onError(err instanceof Error ? err.message : "Failed to refresh account");
    }
  }

  async function addRole() {
    if (!canManage || !account) return;
    setBusy(true);
    try {
      const body: RoleAssignmentRequest =
        newRole === "platform_owner"
          ? { role_code: newRole }
          : needsPartner
            ? { role_code: newRole, partner_id: newPartnerId || null }
            : needsCompany
              ? { role_code: newRole, customer_id: newCustomerId || null }
              : { role_code: newRole };
      await apiPost<RoleAssignment>(`/accounts/${account.id}/roles`, body);
      await reloadAccount();
    } catch (err) {
      onError(err instanceof Error ? err.message : "Failed to assign role");
    } finally {
      setBusy(false);
    }
  }

  async function executeRevoke() {
    if (!canManage || !account || !revokeModal) return;
    setBusy(true);
    try {
      await apiDelete(`/accounts/${account.id}/roles/${revokeModal}`);
      await reloadAccount();
    } catch (err) {
      onError(err instanceof Error ? err.message : "Failed to revoke role");
    } finally {
      setBusy(false);
      setRevokeModal(null);
    }
  }

  async function executeDelete() {
    if (!canManage || !account) return;
    if (account.id === meId) {
      onError("You cannot delete your own account.");
      setDeleteModal(false);
      return;
    }
    setBusy(true);
    try {
      await apiDelete(`/accounts/${account.id}`);
      onDeleted(account.id);
    } catch (err) {
      onError(err instanceof Error ? err.message : "Failed to delete account");
    } finally {
      setBusy(false);
      setDeleteModal(false);
    }
  }

  function scopeLabel(r: RoleAssignment): string {
    if (r.customer_id) return companyMap.get(r.customer_id)?.name ?? `company:${r.customer_id.slice(0, 8)}`;
    if (r.partner_id) return partnerMap.get(r.partner_id)?.name ?? `partner:${r.partner_id.slice(0, 8)}`;
    return "All (platform)";
  }

  return (
    <SideSheet
      open={!!account}
      onClose={onClose}
      title={account.full_name}
      subtitle={account.email}
      width={680}
    >
      <div className="tabPanel">
        <div className="formGrid2">
          <KvItem label="Status" value={STATUS_LABEL[account.status]} />
          <KvItem label="2FA" value={TWOFA_LABEL[account.two_factor]} />
          <KvItem label="Last login" value={account.last_login_at ? formatDate(account.last_login_at) : "—"} />
          <KvItem label="Created" value={formatDate(account.created_at)} />
          <KvItem label="Password expires" value={account.password_expires_at ? formatDate(account.password_expires_at) : "Never"} />
          <KvItem label="Locked until" value={account.locked_until ? formatDate(account.locked_until) : "—"} />
        </div>

        <section className="rolePanel">
          <header>
            <ShieldCheck size={14} /> <strong>Role assignments</strong>
            <em className="muted">{account.roles.length} active</em>
          </header>
          <div className="roleList">
            {account.roles.length === 0 ? (
              <p className="muted">No roles yet — assign one below.</p>
            ) : (
              account.roles.map((r) => {
                const role = roleMap.get(r.role_code);
                return (
                  <div className="roleListRow" key={r.id}>
                    <div>
                      <strong>{role?.display_name ?? ROLE_LABEL[r.role_code]}</strong>
                      <em>{scopeLabel(r)}</em>
                    </div>
                    <span className="muted">Granted {formatDate(r.granted_at)}</span>
                    {canManage ? (
                      <button type="button" className="iconBtn" onClick={() => setRevokeModal(r.id)} disabled={busy} aria-label="Revoke role">
                        <X size={14} />
                      </button>
                    ) : null}
                  </div>
                );
              })
            )}
          </div>
        </section>

        <section className="rolePanel permissionsSummaryPanel">
          <header>
            <ShieldCheck size={14} style={{ color: "var(--primary)" }} /> <strong>Maximum Merged Permissions Map</strong>
            <em className="muted">Effective privileges for this user</em>
          </header>
          <div className="mergedPermissionsGrid">
            {Object.entries(effectivePermissions).map(([key, value]) => {
              const rank = PERMISSION_RANK[value];
              return (
                <div key={key} className="mergedPermissionItem">
                  <div className="permissionInfo">
                    <span className="permissionResourceName">{key}</span>
                    <span className={`statusPill status-${value} permissionLevelLabel`}>{value}</span>
                  </div>
                  <div className="permissionGauge" title={`${key}: ${value}`}>
                    {[1, 2, 3].map((step) => (
                      <div
                        key={step}
                        className={`gaugeStep ${step <= rank ? `filled-${value}` : ""}`}
                      />
                    ))}
                  </div>
                </div>
              );
            })}
          </div>
        </section>

        {canManage ? (
          <section className="rolePanel">
            <header>
              <UserCog size={14} /> <strong>Assign new role</strong>
            </header>
            <div className="formGrid2">
              <div className="formRow">
                <label htmlFor="newRoleSel">Role</label>
                <select id="newRoleSel" value={newRole} onChange={(event) => setNewRole(event.target.value as RoleCode)}>
                  {roles.map((r) => (
                    <option key={r.code} value={r.code}>{ROLE_LABEL[r.code]}</option>
                  ))}
                </select>
              </div>
              {needsPartner ? (
                <div className="formRow">
                  <label htmlFor="newPartnerSel">Partner</label>
                  <select id="newPartnerSel" value={newPartnerId} onChange={(event) => setNewPartnerId(event.target.value)}>
                    {partners.map((p) => (
                      <option key={p.id} value={p.id}>{p.name}</option>
                    ))}
                  </select>
                </div>
              ) : null}
              {needsCompany ? (
                <div className="formRow">
                  <label htmlFor="newCompanySel">Company</label>
                  <select id="newCompanySel" value={newCustomerId} onChange={(event) => setNewCustomerId(event.target.value)}>
                    {companies.map((c) => (
                      <option key={c.id} value={c.id}>{c.name}</option>
                    ))}
                  </select>
                </div>
              ) : null}
            </div>
            <div className="formActions">
              <button type="button" className="btnPrimary" onClick={() => void addRole()} disabled={busy}>
                {busy ? <RefreshCw size={16} className="spinIcon" /> : <Plus size={16} />} Assign
              </button>
            </div>
          </section>
        ) : null}

        <section className="rolePanel muted">
          <header>
            <KeyRound size={14} /> <strong>Authentication</strong>
          </header>
          <p>Password rotation, lockout policy, and SSO assignments land in a later step. 2FA enforcement is currently inherited from the role.</p>
        </section>

        {canManage && account.id !== meId ? (
          <section className="rolePanel dangerPanel">
            <header>
              <Trash2 size={14} /> <strong>Danger zone</strong>
            </header>
            <p className="muted">Permanently delete this account. All role assignments and impersonation history will be removed.</p>
            <div className="formActions">
              <button type="button" className="btnDanger" onClick={() => setDeleteModal(true)} disabled={busy}>
                <Trash2 size={16} /> Delete account
              </button>
            </div>
          </section>
        ) : null}
      </div>

      <ConfirmModal
        open={revokeModal !== null}
        title="Revoke Role Assignment"
        message="Are you sure you want to revoke this role assignment? This immediately removes associated access privileges."
        confirmLabel="Revoke"
        isDanger
        isBusy={busy}
        onConfirm={() => void executeRevoke()}
        onCancel={() => setRevokeModal(null)}
      />

      <ConfirmModal
        open={deleteModal}
        title="Delete Account"
        message={`Permanently delete account ${account.full_name} (${account.email})? This removes all of their role assignments and login challenges. This cannot be undone.`}
        confirmLabel="Delete"
        isDanger
        isBusy={busy}
        requireReason
        onConfirm={(reason) => void executeDelete()}
        onCancel={() => setDeleteModal(false)}
      />
    </SideSheet>
  );
}

function KvItem({ label, value }: { label: string; value: string }) {
  return (
    <div className="formRow">
      <label className="muted">{label}</label>
      <div>{value}</div>
    </div>
  );
}

function formatDate(iso: string): string {
  try {
    return new Date(iso).toLocaleString(undefined, { year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
  } catch {
    return iso;
  }
}
