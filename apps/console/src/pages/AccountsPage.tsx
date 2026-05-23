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
  getAccountId,
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
    const ids = selectedIds.filter((id) => id !== me?.account.id);
    if (ids.length === 0) {
      setError("You cannot delete your own account.");
      return;
    }
    if (!confirm(`Permanently delete ${ids.length} account(s)? This removes all of their role assignments and cannot be undone.`)) return;
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
    }
  }

  if (!me) {
    return (
      <>
        <PageHeader eyebrow="Identity" title="Accounts" />
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
        eyebrow={me.scope.is_platform ? "Platform owner" : me.scope.partner_ids.length ? "MSP partner" : "Company user"}
        title="Accounts"
        subtitle={`${accounts.length} ${accounts.length === 1 ? "account" : "accounts"} in scope.`}
      />
      {error ? <ErrorBanner message={error} /> : null}
      {success ? <SuccessBanner message={success} /> : null}

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
            <button type="button" className="btnDanger" disabled={selectedIds.length === 0} onClick={() => void deleteSelected()}>
              <Trash2 size={16} /> Delete ({selectedIds.length})
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

      <CreateAccountSheet
        open={showCreate}
        roles={roles}
        companies={companies}
        partners={partners}
        canManage={canManage}
        onClose={() => setShowCreate(false)}
        onCreated={(result) => {
          setAccounts((current) => [result.account, ...current]);
          if (result.delivery === "email") {
            setShowCreate(false);
            setSuccess(`Invitation email queued for ${result.account.email}.`);
          } else {
            // Keep the sheet open so the creator can copy the invite link
            // and dismiss it themselves.
            setSuccess(null);
          }
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
      if (created.delivery === "link" && created.invite_url) {
        // Keep the sheet open so the creator can copy/share the link.
        setInviteResult(created);
      }
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
      {inviteResult?.invite_url ? (
        <div className="formStack">
          <div className="successBanner" role="status">
            <strong>Account created for {inviteResult.account.email}.</strong>
            <span>Share the one-time setup link below so they can set their password.</span>
          </div>
          <div className="formRow">
            <label htmlFor="inviteLinkValue">One-time setup link</label>
            <div style={{ display: "flex", gap: 8 }}>
              <input
                id="inviteLinkValue"
                readOnly
                value={inviteResult.invite_url}
                onFocus={(event) => event.currentTarget.select()}
                style={{ flex: 1 }}
              />
              <button type="button" className="btnSecondary" onClick={() => void copyInviteUrl()}>
                <Copy size={16} /> {copied ? "Copied" : "Copy"}
              </button>
            </div>
            {inviteResult.invite_expires_at ? (
              <small className="muted">
                Expires {new Date(inviteResult.invite_expires_at).toLocaleString()}. The link can only be used once.
              </small>
            ) : null}
          </div>
          <div className="formActions">
            <button type="button" className="btnPrimary" onClick={onClose}>Done</button>
          </div>
        </div>
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
            <legend>How should they receive the invite?</legend>
            <label className="deliveryOption">
              <input
                type="radio"
                name="acctDelivery"
                value="email"
                checked={delivery === "email"}
                onChange={() => setDelivery("email")}
              />
              <span>
                <strong><Mail size={14} aria-hidden="true" /> Send invitation email</strong>
                <small className="muted">The system emails them a setup link directly.</small>
              </span>
            </label>
            <label className="deliveryOption">
              <input
                type="radio"
                name="acctDelivery"
                value="link"
                checked={delivery === "link"}
                onChange={() => setDelivery("link")}
              />
              <span>
                <strong><Link2 size={14} aria-hidden="true" /> Generate a link I&rsquo;ll send manually</strong>
                <small className="muted">You&rsquo;ll receive a one-time setup link to forward through your own channel.</small>
              </span>
            </label>
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

  async function deleteAccount() {
    if (!canManage || !account) return;
    if (account.id === meId) {
      onError("You cannot delete your own account.");
      return;
    }
    if (!confirm(`Permanently delete ${account.full_name} (${account.email})? This removes all of their role assignments and cannot be undone.`)) return;
    setBusy(true);
    try {
      await apiDelete(`/accounts/${account.id}`);
      onDeleted(account.id);
    } catch (err) {
      onError(err instanceof Error ? err.message : "Failed to delete account");
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

        {canManage && account.id !== meId ? (
          <section className="rolePanel dangerPanel">
            <header>
              <Trash2 size={14} /> <strong>Danger zone</strong>
            </header>
            <p className="muted">Permanently delete this account. All role assignments and impersonation history will be removed.</p>
            <div className="formActions">
              <button type="button" className="btnDanger" onClick={() => void deleteAccount()} disabled={busy}>
                <Trash2 size={16} /> Delete account
              </button>
            </div>
          </section>
        ) : null}
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
