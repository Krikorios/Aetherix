import { FormEvent, useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  KeyRound,
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
  getAccountId,
  type Account,
  type AccountCreatePayload,
  type AccountStatus,
  type Customer,
  type MeResponse,
  type Partner,
  type Role,
  type RoleAssignment,
  type RoleAssignmentRequest,
  type RoleCode,
  type TwoFactorState,
} from "../api";
import {
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

const ROLE_HIERARCHY: { code: RoleCode; scope: string }[] = [
  { code: "platform_owner", scope: "Creates partners, manages global settings, sees every tenant, audited impersonation." },
  { code: "msp_partner", scope: "Creates companies, manages licensing, users, installers, and partner branding." },
  { code: "company_admin", scope: "Manages one company's endpoints, policies, users, reports, and response actions." },
  { code: "company_tech", scope: "Works incidents, quarantine, tasks, and health queues for assigned companies." },
  { code: "company_viewer", scope: "Read-only access for auditors, executives, and customer managers." },
];

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

  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [editing, setEditing] = useState<Account | null>(null);
  const [showCreate, setShowCreate] = useState(false);
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
    if (!getAccountId()) {
      setMe(null);
      setError("Sign in on the Companies page first — accounts requires a tenant context.");
      setIsLoading(false);
      return;
    }
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
  }, [accounts, query, statusFilter, roleFilter, companyFilter, companyMap]);

  // ---------- actions ----------
  async function deleteSelected() {
    if (!canManage || selectedIds.length === 0) return;
    if (!confirm(`Delete ${selectedIds.length} account(s)? This cannot be undone.`)) return;
    try {
      // Backend does not yet expose DELETE /accounts — fall back to revoking all roles.
      for (const id of selectedIds) {
        const account = accounts.find((a) => a.id === id);
        if (!account) continue;
        for (const role of account.roles) {
          await apiDelete(`/accounts/${id}/roles/${role.id}`);
        }
      }
      setSuccess(`Revoked all role assignments for ${selectedIds.length} account(s).`);
      setSelectedIds([]);
      void load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Bulk action failed");
    }
  }

  if (!me) {
    return (
      <>
        <PageHeader
          eyebrow="Identity control plane"
          title="Accounts"
          subtitle="Role-scoped access for the platform, MSP partners, and company users with audited impersonation."
        />
        {error ? <ErrorBanner message={error} /> : null}
        <section className="panel">
          <EmptyState>Please sign in on the Companies page to view accounts.</EmptyState>
        </section>
      </>
    );
  }

  return (
    <>
      <PageHeader
        eyebrow="Identity control plane"
        title="Accounts"
        subtitle={`Signed in as ${me.account.email}. ${accounts.length} ${accounts.length === 1 ? "account" : "accounts"} in scope.`}
      />
      {error ? <ErrorBanner message={error} /> : null}
      {success ? <SuccessBanner message={success} /> : null}

      <section className="hierarchyStrip" aria-label="Aetherix account hierarchy">
        {ROLE_HIERARCHY.map((item, idx) => (
          <article key={item.code}>
            <span>{idx + 1}</span>
            <strong>{ROLE_LABEL[item.code]}</strong>
            <p>{item.scope}</p>
          </article>
        ))}
      </section>

      <section className="panel accountToolbar">
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
        <button type="button" className="btnGhost" onClick={() => void load()}><RefreshCw size={16} /> Refresh</button>
        {canManage ? (
          <>
            <button type="button" className="btnSecondary" disabled={selectedIds.length === 0} onClick={() => void deleteSelected()}>
              <Trash2 size={16} /> Revoke
            </button>
            <button type="button" className="btnPrimary" onClick={() => setShowCreate(true)}>
              <UserPlus size={16} /> Add account
            </button>
          </>
        ) : null}
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
        <div className="panelHeader">
          <div>
            <h2>Permission matrix</h2>
            <span>Roles seeded by the platform. Permissions merge across all role assignments per account.</span>
          </div>
        </div>
        <div className="permissionMatrix">
          <div className="permissionMatrixHead">
            <span>Role</span>
            {roles[0] ? Object.keys(roles[0].permissions).map((k) => <span key={k}>{k}</span>) : null}
          </div>
          {roles.map((r) => (
            <div className="permissionMatrixRow" key={r.code}>
              <strong>{ROLE_LABEL[r.code]}</strong>
              {Object.values(r.permissions).map((level, i) => (
                <span key={i} className={`statusPill perm-${level}`}>{level}</span>
              ))}
            </div>
          ))}
        </div>
      </section>

      <CreateAccountSheet
        open={showCreate}
        roles={roles}
        companies={companies}
        partners={partners}
        canManage={canManage}
        onClose={() => setShowCreate(false)}
        onCreated={(account) => {
          setShowCreate(false);
          setSuccess(`Invited ${account.email}.`);
          setAccounts((current) => [account, ...current]);
        }}
        onError={(message) => setError(message)}
      />

      <AccountEditSheet
        account={editing}
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
  onCreated: (account: Account) => void;
  onError: (message: string) => void;
}) {
  const [email, setEmail] = useState("");
  const [fullName, setFullName] = useState("");
  const [roleCode, setRoleCode] = useState<RoleCode>("company_admin");
  const [partnerId, setPartnerId] = useState<string>("");
  const [customerId, setCustomerId] = useState<string>("");
  const [isSaving, setIsSaving] = useState(false);

  useEffect(() => {
    if (!open) return;
    setEmail("");
    setFullName("");
    setRoleCode("company_admin");
    setPartnerId(partners[0]?.id ?? "");
    setCustomerId(companies[0]?.id ?? "");
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
        created_by: "console",
      };
      const created = await apiPost<Account>("/accounts", payload);
      onCreated(created);
    } catch (err) {
      onError(err instanceof Error ? err.message : "Failed to create account");
    } finally {
      setIsSaving(false);
    }
  }

  return (
    <SideSheet open={open} onClose={onClose} title="Add account" subtitle="Invite a user and assign their first role" width={560}>
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
        <div className="formActions">
          <button type="button" className="btnGhost" onClick={onClose}>Cancel</button>
          <button type="submit" className="btnPrimary" disabled={isSaving || !email.trim() || !fullName.trim()}>
            {isSaving ? <RefreshCw size={16} className="spinIcon" /> : <Plus size={16} />} {isSaving ? "Inviting" : "Invite"}
          </button>
        </div>
      </form>
    </SideSheet>
  );
}

// ---------------------------------------------------------------------------
// Edit Account — add/revoke role assignments
// ---------------------------------------------------------------------------

function AccountEditSheet({
  account,
  roles,
  companies,
  partners,
  canManage,
  roleMap,
  companyMap,
  partnerMap,
  onClose,
  onChanged,
  onError,
}: {
  account: Account | null;
  roles: Role[];
  companies: Customer[];
  partners: Partner[];
  canManage: boolean;
  roleMap: Map<RoleCode, Role>;
  companyMap: Map<string, Customer>;
  partnerMap: Map<string, Partner>;
  onClose: () => void;
  onChanged: (next: Account) => void;
  onError: (message: string) => void;
}) {
  const [newRole, setNewRole] = useState<RoleCode>("company_admin");
  const [newPartnerId, setNewPartnerId] = useState("");
  const [newCustomerId, setNewCustomerId] = useState("");
  const [busy, setBusy] = useState(false);

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

  async function revoke(assignmentId: string) {
    if (!canManage || !account) return;
    if (!confirm("Revoke this role assignment?")) return;
    setBusy(true);
    try {
      await apiDelete(`/accounts/${account.id}/roles/${assignmentId}`);
      await reloadAccount();
    } catch (err) {
      onError(err instanceof Error ? err.message : "Failed to revoke role");
    } finally {
      setBusy(false);
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
                      <button type="button" className="iconBtn" onClick={() => void revoke(r.id)} disabled={busy} aria-label="Revoke role">
                        <X size={14} />
                      </button>
                    ) : null}
                  </div>
                );
              })
            )}
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
      </div>
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
