import { FormEvent, useState } from "react";
import { KeyRound, ShieldCheck } from "lucide-react";

import { apiPost, type Account, type InviteAcceptPayload } from "../api";

export function SetupAccountPage({ token }: { token: string }) {
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [fullName, setFullName] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [completed, setCompleted] = useState<Account | null>(null);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    if (password.length < 8) {
      setError("Password must be at least 8 characters.");
      return;
    }
    if (password !== confirm) {
      setError("Passwords do not match.");
      return;
    }
    setSubmitting(true);
    try {
      const payload: InviteAcceptPayload = {
        token,
        password,
        full_name: fullName.trim() || null,
      };
      const account = await apiPost<Account>("/auth/accept-invite", payload);
      setCompleted(account);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not complete setup.");
    } finally {
      setSubmitting(false);
    }
  }

  function goToSignIn() {
    // Clear the hash so the app falls back to its normal sign-in flow.
    window.location.hash = "";
    window.location.reload();
  }

  return (
    <main className="loginShell">
      <section className="loginCard" aria-labelledby="setupHeading">
        <header className="loginHeader">
          <ShieldCheck className="loginLogo" aria-hidden="true" />
          <div>
            <h1 id="setupHeading">Set up your account</h1>
            <p>Choose a password to activate your Aetherix account.</p>
          </div>
        </header>

        {completed ? (
          <div className="loginForm">
            <p>
              Your account <strong>{completed.email}</strong> is now active.
            </p>
            <button type="button" className="btnPrimary loginSubmit" onClick={goToSignIn}>
              Continue to sign in
            </button>
          </div>
        ) : (
          <form className="loginForm" onSubmit={handleSubmit} noValidate>
            <label className="loginField">
              <span>Full name (optional)</span>
              <div className="loginInput">
                <input
                  type="text"
                  autoComplete="name"
                  value={fullName}
                  onChange={(event) => setFullName(event.target.value)}
                />
              </div>
            </label>
            <label className="loginField">
              <span>New password</span>
              <div className="loginInput">
                <KeyRound size={16} aria-hidden="true" />
                <input
                  type="password"
                  autoComplete="new-password"
                  minLength={8}
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  required
                  autoFocus
                />
              </div>
            </label>
            <label className="loginField">
              <span>Confirm password</span>
              <div className="loginInput">
                <KeyRound size={16} aria-hidden="true" />
                <input
                  type="password"
                  autoComplete="new-password"
                  minLength={8}
                  value={confirm}
                  onChange={(event) => setConfirm(event.target.value)}
                  required
                />
              </div>
            </label>

            {error ? (
              <div className="loginError" role="alert">
                {error}
              </div>
            ) : null}

            <button
              type="submit"
              className="btnPrimary loginSubmit"
              disabled={submitting || !password || !confirm}
            >
              {submitting ? "Activating…" : "Activate account"}
            </button>
          </form>
        )}

        <footer className="loginFooter">
          <p>This one-time link expires after first use. Contact your administrator if it no longer works.</p>
        </footer>
      </section>
    </main>
  );
}
