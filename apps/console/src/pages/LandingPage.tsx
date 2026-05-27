import { useCallback, useEffect, useState } from "react";
import { Building2, Layers, ShieldCheck, UserCog } from "lucide-react";

import { apiGet, getAccessToken, logout, type MeResponse } from "../api";
import { ErrorBanner, PageHeader, SuccessBanner } from "../components";

export function LandingPage({
  onNavigate,
}: {
  onNavigate: (page: "companies" | "accounts" | "enrollment") => void;
}) {
  const [me, setMe] = useState<MeResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const loadMe = useCallback(async () => {
    if (!getAccessToken()) {
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
    function onAuthChanged() {
      void loadMe();
    }
    window.addEventListener("aetherix:auth-changed", onAuthChanged);
    window.addEventListener("storage", onAuthChanged);
    return () => {
      window.removeEventListener("aetherix:auth-changed", onAuthChanged);
      window.removeEventListener("storage", onAuthChanged);
    };
  }, [loadMe]);

  function handleSignOut() {
    logout();
    setMe(null);
    setError(null);
    setSuccess("Signed out.");
  }

  return (
    <>
      <PageHeader
        eyebrow="Access control"
        title="Landing + Sign-in"
        subtitle="Use this page to validate signed-in scope while testing partner and company behavior."
      />
      {error ? <ErrorBanner message={error} /> : null}
      {success ? <SuccessBanner message={success} /> : null}

      <section className="landingGrid">
        <article className="panel">
          <div className="panelHeader">
            <div>
              <h2>Session authentication</h2>
              <span>Session identity is derived from the bearer token.</span>
            </div>
            <ShieldCheck size={18} />
          </div>
          <div className="formStack">
            <p className="muted" style={{ margin: 0 }}>
              {me ? `Signed in as ${me.account.email}.` : "No active session. Use the login flow to sign in."}
            </p>
            <div className="formActions">
              <button type="button" className="btnGhost" onClick={handleSignOut} disabled={!me && !getAccessToken()}>
                Sign out
              </button>
            </div>
          </div>
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
