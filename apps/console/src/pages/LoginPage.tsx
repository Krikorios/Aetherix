import { FormEvent, useEffect, useState } from "react";
import { KeyRound, Mail, ShieldCheck } from "lucide-react";
import QRCode from "qrcode";

import { apiGet, apiPost, setAccessToken, type MeResponse } from "../api";

const DEFAULT_TAGLINE = "Sign in to your workspace";

type TotpChallenge = {
  status: "totp_setup_required" | "totp_required";
  challenge_id: string;
  email: string;
  otpauth_url?: string | null;
  secret?: string | null;
  issuer?: string | null;
};

type LoginResult = {
  access_token: string;
  token_type: "Bearer";
  expires_at: string;
  me: MeResponse;
};

type Step = "credentials" | "totp";

export function LoginPage({
  onAuthenticated,
}: {
  onAuthenticated: (me: MeResponse) => void;
}) {
  const [step, setStep] = useState<Step>("credentials");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [challenge, setChallenge] = useState<TotpChallenge | null>(null);
  const [qrDataUrl, setQrDataUrl] = useState<string | null>(null);
  const [qrError, setQrError] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    const uri = challenge?.status === "totp_setup_required" ? challenge.otpauth_url : null;
    if (!uri) {
      setQrDataUrl(null);
      setQrError(null);
      return;
    }

    let cancelled = false;
    setQrDataUrl(null);
    setQrError(null);
    QRCode.toDataURL(uri, {
      errorCorrectionLevel: "M",
      margin: 2,
      width: 192,
      color: {
        dark: "#111827",
        light: "#ffffff",
      },
    })
      .then((dataUrl) => {
        if (!cancelled) setQrDataUrl(dataUrl);
      })
      .catch(() => {
        if (!cancelled) setQrError("QR code failed to render. Enter the secret manually instead.");
      });

    return () => {
      cancelled = true;
    };
  }, [challenge]);

  async function handleCredentials(event: FormEvent) {
    event.preventDefault();
    setError(null);
    const trimmedEmail = email.trim();
    if (!trimmedEmail || !password) return;
    setSubmitting(true);
    try {
      // /auth/login is unauthenticated — clear any stale credentials.
      setAccessToken(null);
      const result = await apiPost<TotpChallenge>("/auth/login", {
        email: trimmedEmail,
        password,
      });
      setChallenge(result);
      setStep("totp");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Sign-in failed");
    } finally {
      setSubmitting(false);
    }
  }

  async function handleTotp(event: FormEvent) {
    event.preventDefault();
    setError(null);
    if (!challenge) return;
    const trimmedCode = code.trim();
    if (!trimmedCode) return;
    setSubmitting(true);
    try {
      const result = await apiPost<LoginResult>("/auth/totp/verify", {
        challenge_id: challenge.challenge_id,
        code: trimmedCode,
      });
      // Persist the bearer token first so the follow-up /me call is
      // authenticated.
      setAccessToken(result.access_token);
      // Confirm the session is usable end-to-end before transitioning.
      try {
        await apiGet<MeResponse>("/me");
      } catch {
        // Non-fatal — the verify response is authoritative.
      }
      onAuthenticated(result.me);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Verification failed");
    } finally {
      setSubmitting(false);
    }
  }

  function handleBack() {
    setStep("credentials");
    setChallenge(null);
    setCode("");
    setError(null);
  }

  return (
    <main className="loginShell">
      <section className="loginCard" aria-labelledby="loginHeading">
        <header className="loginHeader">
          <ShieldCheck className="loginLogo" aria-hidden="true" />
          <div>
            <h1 id="loginHeading">Aetherix</h1>
            <p>{DEFAULT_TAGLINE}</p>
          </div>
        </header>

        {step === "credentials" ? (
          <form className="loginForm" onSubmit={handleCredentials} noValidate>
            <label className="loginField">
              <span>Email</span>
              <div className="loginInput">
                <Mail size={16} aria-hidden="true" />
                <input
                  type="email"
                  autoComplete="username"
                  placeholder="you@example.com"
                  value={email}
                  onChange={(event) => setEmail(event.target.value)}
                  required
                  autoFocus
                />
              </div>
            </label>

            <label className="loginField">
              <span>Password</span>
              <div className="loginInput">
                <KeyRound size={16} aria-hidden="true" />
                <input
                  type="password"
                  autoComplete="current-password"
                  placeholder="••••••••"
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
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
              disabled={submitting || !email.trim() || !password}
            >
              {submitting ? "Signing in…" : "Sign in"}
            </button>
          </form>
        ) : (
          <form className="loginForm" onSubmit={handleTotp} noValidate>
            <p className="loginFooter" style={{ marginTop: 0 }}>
              {challenge?.status === "totp_setup_required"
                ? "Scan the setup code with your authenticator app, then enter the 6-digit code to finish enrollment."
                : `Enter the 6-digit code from your authenticator app for ${challenge?.email}.`}
            </p>

            {challenge?.status === "totp_setup_required" && challenge.otpauth_url ? (
              <div className="totpSetup">
                <div className="totpQr" aria-label="Authenticator QR code">
                  {qrDataUrl ? (
                    <img src={qrDataUrl} alt="Scan this QR code with your authenticator app" />
                  ) : (
                    <span className="totpQrPlaceholder">Generating QR…</span>
                  )}
                </div>
                <div className="totpSecret">
                  <span className="totpSecretLabel">Manual setup key</span>
                  {challenge.secret ? (
                    <code className="totpSecretValue">{challenge.secret}</code>
                  ) : null}
                  <span className="totpSecretHint">
                    Scan the QR code. If scanning fails, add an account manually using this setup key.
                  </span>
                  {qrError ? <span className="totpSecretHint">{qrError}</span> : null}
                </div>
              </div>
            ) : null}

            <label className="loginField">
              <span>Verification code</span>
              <div className="loginInput">
                <KeyRound size={16} aria-hidden="true" />
                <input
                  type="text"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  placeholder="123456"
                  value={code}
                  onChange={(event) => setCode(event.target.value.replace(/\s+/g, ""))}
                  required
                  autoFocus
                  minLength={6}
                  maxLength={8}
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
              disabled={submitting || code.trim().length < 6}
            >
              {submitting ? "Verifying…" : "Verify and sign in"}
            </button>
            <button
              type="button"
              className="btnGhost"
              onClick={handleBack}
              disabled={submitting}
            >
              Back
            </button>
          </form>
        )}

        <footer className="loginFooter">
          <p>
            Sign in with your Aetherix user account. New users receive an invitation
            email to set their password before first sign-in.
          </p>
        </footer>
      </section>
    </main>
  );
}
