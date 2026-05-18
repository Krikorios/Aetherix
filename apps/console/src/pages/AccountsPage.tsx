import { FormEvent, useMemo, useState } from "react";
import { Filter, KeyRound, Plus, Search, Trash2, UserCog, X } from "lucide-react";
import { PageHeader } from "../components";

type Role = "Platform Owner" | "MSP Partner" | "Company Administrator" | "Company Technician" | "Company Viewer";
type AccountStatus = "Active" | "Invited" | "Locked" | "Suspended";
type TwoFactorState = "Enforced" | "Enabled" | "Missing";
type PermissionLevel = "Manage" | "Edit" | "View" | "None";

type Account = {
  id: string;
  fullName: string;
  email: string;
  status: AccountStatus;
  role: Role;
  twoFactor: TwoFactorState;
  passwordExpiration: string;
  accountLockout: string;
  company: string;
  partner: string;
  permissions: Record<string, PermissionLevel>;
};

const MODULES = ["Companies", "Accounts", "Policies", "Incidents", "Reports", "Licensing"];

const ROLE_SCOPE: Record<Role, string> = {
  "Platform Owner": "Creates MSP partners, manages global settings, sees every tenant, and can impersonate with audit.",
  "MSP Partner": "Creates companies, manages licensing, users, installers, and partner white-label settings.",
  "Company Administrator": "Manages one company’s endpoints, policies, users, reports, and response actions.",
  "Company Technician": "Works incidents, quarantine, tasks, and health queues for assigned companies.",
  "Company Viewer": "Read-only access for auditors, executives, and customer managers.",
};

const ROLE_MATRIX: { role: Role; scope: string; companies: string; accounts: string; licensing: string; impersonation: string }[] = [
  { role: "Platform Owner", scope: "All MSPs + companies", companies: "Manage", accounts: "Manage", licensing: "Manage", impersonation: "Any partner or company" },
  { role: "MSP Partner", scope: "Own partner tree", companies: "Manage", accounts: "Manage company users", licensing: "Manage own subscriptions", impersonation: "Own companies only" },
  { role: "Company Administrator", scope: "Assigned company", companies: "View own company", accounts: "Manage company users", licensing: "View entitlement", impersonation: "No" },
  { role: "Company Technician", scope: "Assigned company", companies: "View", accounts: "No", licensing: "No", impersonation: "No" },
  { role: "Company Viewer", scope: "Assigned company", companies: "View", accounts: "No", licensing: "No", impersonation: "No" },
];

const INITIAL_ACCOUNTS: Account[] = [
  {
    id: "acct-1",
    fullName: "Maya Rosen",
    email: "maya@menagenix.com",
    status: "Active",
    role: "Platform Owner",
    twoFactor: "Enforced",
    passwordExpiration: "Never",
    accountLockout: "No lockout",
    company: "All recursively",
    partner: "Menagenix",
    permissions: modulePermissions("Manage"),
  },
  {
    id: "acct-2",
    fullName: "Eli Navarro",
    email: "eli@northstar-msp.com",
    status: "Active",
    role: "MSP Partner",
    twoFactor: "Enabled",
    passwordExpiration: "82 days",
    accountLockout: "No lockout",
    company: "All recursively",
    partner: "Northstar MSP",
    permissions: { ...modulePermissions("Manage"), Accounts: "Edit" },
  },
  {
    id: "acct-3",
    fullName: "Priya Shah",
    email: "priya@northwinddental.example",
    status: "Invited",
    role: "Company Administrator",
    twoFactor: "Enforced",
    passwordExpiration: "90 days",
    accountLockout: "No lockout",
    company: "Northwind Dental",
    partner: "Northstar MSP",
    permissions: { Companies: "View", Accounts: "Manage", Policies: "Edit", Incidents: "Manage", Reports: "View", Licensing: "View" },
  },
  {
    id: "acct-4",
    fullName: "Theo Grant",
    email: "theo@contosoplumbing.example",
    status: "Locked",
    role: "Company Technician",
    twoFactor: "Missing",
    passwordExpiration: "14 days",
    accountLockout: "Locked after 5 attempts",
    company: "Contoso Plumbing",
    partner: "Northstar MSP",
    permissions: { Companies: "View", Accounts: "None", Policies: "View", Incidents: "Edit", Reports: "View", Licensing: "None" },
  },
];

function modulePermissions(level: PermissionLevel): Record<string, PermissionLevel> {
  return Object.fromEntries(MODULES.map((moduleName) => [moduleName, level])) as Record<string, PermissionLevel>;
}

function roleDefaults(role: Role): Record<string, PermissionLevel> {
  if (role === "Platform Owner" || role === "MSP Partner") return modulePermissions("Manage");
  if (role === "Company Administrator") return { Companies: "View", Accounts: "Manage", Policies: "Edit", Incidents: "Manage", Reports: "View", Licensing: "View" };
  if (role === "Company Technician") return { Companies: "View", Accounts: "None", Policies: "View", Incidents: "Edit", Reports: "View", Licensing: "None" };
  return { Companies: "View", Accounts: "None", Policies: "View", Incidents: "View", Reports: "View", Licensing: "None" };
}

export function AccountsPage() {
  const [accounts, setAccounts] = useState<Account[]>(INITIAL_ACCOUNTS);
  const [query, setQuery] = useState("");
  const [roleFilter, setRoleFilter] = useState<Role | "All">("All");
  const [statusFilter, setStatusFilter] = useState<AccountStatus | "All">("All");
  const [companyFilter, setCompanyFilter] = useState("All recursively");
  const [twoFactorFilter, setTwoFactorFilter] = useState<TwoFactorState | "All">("All");
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [modalOpen, setModalOpen] = useState(false);
  const [editingAccount, setEditingAccount] = useState<Account | null>(null);

  const companies = useMemo(() => ["All recursively", ...Array.from(new Set(accounts.map((account) => account.company).filter((company) => company !== "All recursively")))], [accounts]);

  const filteredAccounts = accounts.filter((account) => {
    const textMatch = `${account.fullName} ${account.email}`.toLowerCase().includes(query.toLowerCase());
    const roleMatch = roleFilter === "All" || account.role === roleFilter;
    const statusMatch = statusFilter === "All" || account.status === statusFilter;
    const companyMatch = companyFilter === "All recursively" || account.company === companyFilter;
    const twoFactorMatch = twoFactorFilter === "All" || account.twoFactor === twoFactorFilter;
    return textMatch && roleMatch && statusMatch && companyMatch && twoFactorMatch;
  });

  function deleteSelected() {
    setAccounts((current) => current.filter((account) => !selectedIds.includes(account.id)));
    setSelectedIds([]);
  }

  function saveAccount(account: Account) {
    setAccounts((current) => {
      if (current.some((item) => item.id === account.id)) {
        return current.map((item) => (item.id === account.id ? account : item));
      }
      return [account, ...current];
    });
    setModalOpen(false);
    setEditingAccount(null);
  }

  return (
    <>
      <PageHeader
        eyebrow="Identity control plane"
        title="Accounts"
        subtitle="Role-scoped access for Menagenix, MSP partners, and company users with audited support impersonation"
      />

      <section className="hierarchyStrip" aria-label="Aetherix account hierarchy">
        {(["Platform Owner", "MSP Partner", "Company Administrator", "Company Technician", "Company Viewer"] as Role[]).map((role, index) => (
          <article key={role}>
            <span>{index + 1}</span>
            <strong>{role}</strong>
            <p>{ROLE_SCOPE[role]}</p>
          </article>
        ))}
      </section>

      <section className="panel accountToolbar">
        <div className="searchBox">
          <Search size={16} />
          <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Full Name or Email" />
        </div>
        <select value={roleFilter} onChange={(event) => setRoleFilter(event.target.value as Role | "All")} aria-label="Role filter">
          <option>All</option>
          {ROLE_MATRIX.map((item) => <option key={item.role}>{item.role}</option>)}
        </select>
        <select value={statusFilter} onChange={(event) => setStatusFilter(event.target.value as AccountStatus | "All")} aria-label="Status filter">
          <option>All</option>
          <option>Active</option>
          <option>Invited</option>
          <option>Locked</option>
          <option>Suspended</option>
        </select>
        <select value={companyFilter} onChange={(event) => setCompanyFilter(event.target.value)} aria-label="Company filter">
          {companies.map((company) => <option key={company}>{company}</option>)}
        </select>
        <select value={twoFactorFilter} onChange={(event) => setTwoFactorFilter(event.target.value as TwoFactorState | "All")} aria-label="2FA filter">
          <option>All</option>
          <option>Enforced</option>
          <option>Enabled</option>
          <option>Missing</option>
        </select>
        <button className="btnSecondary" type="button"><Filter size={16} /> Filters</button>
        <button className="btnSecondary" type="button" disabled={selectedIds.length === 0} onClick={deleteSelected}><Trash2 size={16} /> Delete</button>
        <button className="btnPrimary" type="button" onClick={() => { setEditingAccount(null); setModalOpen(true); }}><Plus size={16} /> Add Account</button>
      </section>

      <section className="panel accountTablePanel">
        <div className="accountTableHead">
          <span />
          <span>Full Name</span>
          <span>Email</span>
          <span>Status</span>
          <span>Role</span>
          <span>2FA</span>
          <span>Password expiration</span>
          <span>Account lockout</span>
          <span>Company</span>
        </div>
        {filteredAccounts.map((account) => (
          <button className="accountRow" key={account.id} type="button" onClick={() => { setEditingAccount(account); setModalOpen(true); }}>
            <input
              type="checkbox"
              checked={selectedIds.includes(account.id)}
              onChange={(event) => {
                event.stopPropagation();
                setSelectedIds((current) => event.target.checked ? [...current, account.id] : current.filter((id) => id !== account.id));
              }}
              onClick={(event) => event.stopPropagation()}
              aria-label={`Select ${account.fullName}`}
            />
            <strong>{account.fullName}</strong>
            <span>{account.email}</span>
            <span className={`statusPill status-${account.status.toLowerCase()}`}>{account.status}</span>
            <span>{account.role}</span>
            <span>{account.twoFactor}</span>
            <span>{account.passwordExpiration}</span>
            <span>{account.accountLockout}</span>
            <span>{account.company}</span>
          </button>
        ))}
      </section>

      <section className="panel matrixPanel">
        <div className="panelHeader">
          <div>
            <h2>Final Hierarchy Recommendation</h2>
            <span>Isolation is enforced from partner tree to company assignment; support impersonation is Platform Owner only and audit logged.</span>
          </div>
        </div>
        <div className="matrixGrid">
          <span>Role</span><span>Scope</span><span>Companies</span><span>Accounts</span><span>Licensing</span><span>Impersonation</span>
          {ROLE_MATRIX.map((item) => (
            <div className="matrixRow" key={item.role}>
              <strong>{item.role}</strong><span>{item.scope}</span><span>{item.companies}</span><span>{item.accounts}</span><span>{item.licensing}</span><span>{item.impersonation}</span>
            </div>
          ))}
        </div>
      </section>

      {modalOpen ? (
        <AccountModal
          account={editingAccount}
          companies={companies.filter((company) => company !== "All recursively")}
          onClose={() => { setModalOpen(false); setEditingAccount(null); }}
          onSave={saveAccount}
        />
      ) : null}
    </>
  );
}

function AccountModal({ account, companies, onClose, onSave }: { account: Account | null; companies: string[]; onClose: () => void; onSave: (account: Account) => void }) {
  const [fullName, setFullName] = useState(account?.fullName ?? "");
  const [email, setEmail] = useState(account?.email ?? "");
  const [role, setRole] = useState<Role>(account?.role ?? "Company Administrator");
  const [company, setCompany] = useState(account?.company === "All recursively" ? companies[0] ?? "Northwind Dental" : account?.company ?? companies[0] ?? "Northwind Dental");
  const [twoFactorEnforced, setTwoFactorEnforced] = useState(account?.twoFactor !== "Missing");
  const [passwordPolicy, setPasswordPolicy] = useState(account?.passwordExpiration ?? "90 days");
  const [permissions, setPermissions] = useState<Record<string, PermissionLevel>>(account?.permissions ?? roleDefaults(role));

  function updateRole(nextRole: Role) {
    setRole(nextRole);
    setPermissions(roleDefaults(nextRole));
  }

  function submit(event: FormEvent) {
    event.preventDefault();
    onSave({
      id: account?.id ?? crypto.randomUUID(),
      fullName,
      email,
      role,
      status: account?.status ?? "Invited",
      twoFactor: twoFactorEnforced ? "Enforced" : "Missing",
      passwordExpiration: passwordPolicy,
      accountLockout: account?.accountLockout ?? "No lockout",
      company: role === "Platform Owner" || role === "MSP Partner" ? "All recursively" : company,
      partner: role === "Platform Owner" ? "Menagenix" : "Northstar MSP",
      permissions,
    });
  }

  const showCompanyAssignment = role !== "Platform Owner" && role !== "MSP Partner";

  return (
    <div className="modalBackdrop" role="presentation">
      <form className="accountModal" onSubmit={submit}>
        <header>
          <div>
            <span><UserCog size={16} /> {account ? "Edit Account" : "Add Account"}</span>
            <h2>{account ? account.fullName : "New Aetherix user"}</h2>
          </div>
          <button className="btnIcon" type="button" onClick={onClose} aria-label="Close"><X size={16} /></button>
        </header>

        <div className="formGrid2">
          <div className="formRow"><label htmlFor="fullName">Full Name</label><input id="fullName" required value={fullName} onChange={(event) => setFullName(event.target.value)} /></div>
          <div className="formRow"><label htmlFor="email">Email</label><input id="email" required type="email" value={email} onChange={(event) => setEmail(event.target.value)} /></div>
        </div>
        <div className="formGrid2">
          <div className="formRow"><label htmlFor="role">Role</label><select id="role" value={role} onChange={(event) => updateRole(event.target.value as Role)}>{ROLE_MATRIX.map((item) => <option key={item.role}>{item.role}</option>)}</select></div>
          {showCompanyAssignment ? <div className="formRow"><label htmlFor="company">Company assignment</label><select id="company" value={company} onChange={(event) => setCompany(event.target.value)}>{companies.map((item) => <option key={item}>{item}</option>)}</select></div> : <div className="formRow"><label>Scope</label><input value="All recursively" readOnly /></div>}
        </div>

        <section className="permissionEditor" aria-label="Module permissions">
          {MODULES.map((moduleName) => (
            <label key={moduleName}>
              <span>{moduleName}</span>
              <select value={permissions[moduleName]} onChange={(event) => setPermissions((current) => ({ ...current, [moduleName]: event.target.value as PermissionLevel }))}>
                <option>Manage</option><option>Edit</option><option>View</option><option>None</option>
              </select>
            </label>
          ))}
        </section>

        <div className="policyControls">
          <label className="toggleRow"><input type="checkbox" checked={twoFactorEnforced} onChange={(event) => setTwoFactorEnforced(event.target.checked)} /> Enforce 2FA</label>
          <label><KeyRound size={16} /> Password policy <select value={passwordPolicy} onChange={(event) => setPasswordPolicy(event.target.value)}><option>90 days</option><option>180 days</option><option>Never</option></select></label>
        </div>

        <div className="formActions">
          <button className="btnSecondary" type="button" onClick={onClose}>Cancel</button>
          <button className="btnPrimary" type="submit">Save Account</button>
        </div>
      </form>
    </div>
  );
}