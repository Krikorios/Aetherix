import { FormEvent, useCallback, useEffect, useState } from "react";
import { Building2, KeyRound, Layers, ShieldCheck, UserCog } from "lucide-react";

import { apiGet, getAccountId, setAccountId, type MeResponse } from "../api";
import { ErrorBanner, PageHeader, SuccessBanner } from "../components";

export function LandingPage({
  onNavigate,
}: {
  onNavigate: (page: "companies" | "accounts" | "enrollment") => void;
}) {
  const [accountInput, setAccountInput] = useState(getAccountId() ?? "");
  const [me, setMe] = useState<MeResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const loadMe = useCallback(async () => {
    const accountId = getAccountId();
    if (!accountId) {
      setMe(null);
      setError(null);
      return;
    }
    setLoading(true);
    try {
      const response = await apiGet<MeResponse>("/me");
      setMe(response);
      setError(null);
    } catch (err) {
      setMe(null);
      setError(err instanceof Error ? err.message : "Failed to load account context");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadMe();
    function onAccountChanged() {
      setAccountInput(getAccountId() ?? "");
      void loadMe();
    }
    window.addEventListener("aetherix:account-changed", onAccountChanged);
    window.addEventListener("storage", onAccountChanged);
    return () => {
      window.removeEventListener("aetherix:account-changed", onAccountChanged);
      window.removeEventListener("storage", onAccountChanged);
    };
  }, [loadMe]);

  async function handleSignIn(event: FormEvent) {
    event.preventDefault();
    const trimmed = accountInput.trim();
    if (!trimmed) return;
    setAccountId(trimmed);
    setSuccess("Signed in. You can now open Companies to test subcompany scopes.");
    await loadMe();
  }

  async function handleSignOut() {
    setAccountId(null);
    setAccountInput("");
    setMe(null);
    setError(null);
    setSuccess("Signed out. Enter a different account ID to test another scope.");
  }

  return (
    <>
      <PageHeader
        eyebrow="Access control"
        title="Landing + Sign-in"
        subtitle="Use this page to switch account scope quickly while testing partner and subcompany behavior."
      />
      {error ? <ErrorBanner message={error} /> : null}
      {success ? <SuccessBanner message={success} /> : null}

      <section className="landingGrid">
        <article className="panel">
          <div className="panelHeader">
            <div>
              <h2>Session authentication</h2>
              <span>Paste any account UUID (platform owner, partner, or company account).</span>
            </div>
            <KeyRound size={18} />
          </div>
          <form className="formStack" onSubmit={handleSignIn}>
            <div className="formRow">
              <label htmlFor="landingAccountId">Account ID</label>
              <input
                id="landingAccountId"
                placeholder="00000000-0000-0000-0000-000000000000"
                value={accountInput}
                onChange={(event) => setAccountInput(event.target.value)}
              />
            </div>
            <div className="formActions">
              <button type="submit" className="btnPrimary" disabled={!accountInput.trim() || loading}>
                Sign in
              </button>
              <button type="button" className="btnGhost" onClick={() => void handleSignOut()}>
                Sign out
              </button>
            </div>
          </form>
        </article>

        <article className="panel">
          <div className="panelHeader">
            <div>
              <h2>Current scope</h2>
              <span>Verify your role visibility before testing data isolation flows.</span>
            </div>
            <ShieldCheck size={18} />
          </div>
          {loading ? <p className="muted">Loading scope…</p> : null}
          {!loading && !me ? <p className="muted">No active account selected.</p> : null}
          {!loading && me ? (
            <dl className="kvList">
              <div>
                <dt>Account</dt>
                <dd>{me.account.email}</dd>
              </div>
              <div>
                <dt>Status</dt>
                <dd>{me.account.status}</dd>
              </div>
              <div>
                <dt>Platform owner</dt>
                <dd>{me.scope.is_platform ? "Yes" : "No"}</dd>
              </div>
              <div>
                <dt>Partner scopes</dt>
                <dd>{me.scope.partner_ids.length}</dd>
              </div>
              <div>
                <dt>Customer scopes</dt>
                <dd>{me.scope.customer_ids.length}</dd>
              </div>
            </dl>
          ) : null}
        </article>
      </section>

      <section className="panel">
        <div className="panelHeader">
          <div>
            <h2>Testing shortcuts</h2>
            <span>Jump directly to the modules you use to validate subcompany behavior.</span>
          </div>
          <Layers size={18} />
        </div>
        <div className="landingActions">
          <button type="button" className="btnPrimary" onClick={() => onNavigate("companies")}>
            <Building2 size={16} /> Open Companies
          </button>
          <button type="button" className="btnGhost" onClick={() => onNavigate("accounts")}>
            <UserCog size={16} /> Open Accounts
          </button>
          <button type="button" className="btnGhost" onClick={() => onNavigate("enrollment")}>
            <ShieldCheck size={16} /> Open Installers
          </button>
        </div>
      </section>
    </>
  );
}
