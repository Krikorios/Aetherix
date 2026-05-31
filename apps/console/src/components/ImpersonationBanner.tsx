import { useEffect, useState } from "react";
import { ShieldAlert, X } from "lucide-react";
import { endImpersonation, getActiveImpersonation, type ImpersonationSession } from "../api";

/**
 * Persistent banner shown to operators while an impersonation session is
 * active. Always visible while a scoped session is live, with a one-click
 * "End impersonation" affordance that:
 *   - calls `POST /auth/impersonation/{id}/end` (server emits an
 *     `impersonation_ended` evidence event),
 *   - clears the scoped bearer token and reloads the page back to the
 *     operator's own identity.
 *
 * If the server has not yet implemented `/auth/impersonation/active`, the
 * fetch fails silently and the banner stays hidden — no broken UI.
 */
export function ImpersonationBanner() {
  const [session, setSession] = useState<ImpersonationSession | null>(null);
  const [working, setWorking] = useState(false);

  useEffect(() => {
    let cancelled = false;
    getActiveImpersonation()
      .then((s) => {
        if (!cancelled) setSession(s);
      })
      .catch(() => {
        if (!cancelled) setSession(null);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (!session) return null;

  const handleEnd = async () => {
    setWorking(true);
    try {
      await endImpersonation(session.id);
    } catch {
      // Even if the server call fails we still tear down the session
      // locally to avoid a stuck-impersonation state.
    } finally {
      // Force a full reload so the App reissues /me with the operator's own
      // bearer token (the server already invalidated the scoped one).
      window.location.reload();
    }
  };

  return (
    <div className="impersonationBanner" role="status" aria-live="polite">
      <ShieldAlert size={14} aria-hidden="true" />
      <span>
        Acting as <strong>{session.subject_account_id}</strong>
        {session.scope.customer_id ? <> · customer <code>{session.scope.customer_id}</code></> : null}
        {session.scope.partner_id ? <> · partner <code>{session.scope.partner_id}</code></> : null}
        {" · "}
        <span className="impersonationReason">{session.reason}</span>
        {" · "}
        <span className="impersonationEvidence">evidence {session.evidence_event_id}</span>
      </span>
      <button
        type="button"
        className="impersonationEndButton"
        onClick={handleEnd}
        disabled={working}
        aria-label="End impersonation session"
      >
        <X size={12} aria-hidden="true" />
        {working ? "Ending…" : "End impersonation"}
      </button>
    </div>
  );
}
