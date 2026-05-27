import { LoaderCircle, X } from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";
import type { RiskBand } from "./api";

export function LoadingRow({ label = "Loading…" }: { label?: string }) {
  return (
    <article className="loadingRow">
      <LoaderCircle aria-hidden="true" />
      <span>{label}</span>
    </article>
  );
}

export function EmptyState({ children }: { children: ReactNode }) {
  return <p className="emptyState">{children}</p>;
}

export function ConfirmModal({
  open,
  title,
  message,
  confirmLabel = "Confirm",
  onConfirm,
  onCancel,
  isDanger = false,
  isBusy = false,
  requireReason = false,
}: {
  open: boolean;
  title: string;
  message: ReactNode;
  confirmLabel?: string;
  onConfirm: (reason?: string) => void;
  onCancel: () => void;
  isDanger?: boolean;
  isBusy?: boolean;
  requireReason?: boolean;
}) {
  const [reason, setReason] = useState("");

  if (!open) return null;

  return (
    <div
      className="modalOverlay"
      style={{
        position: "fixed",
        inset: 0,
        backgroundColor: "rgba(11, 18, 32, 0.45)",
        backdropFilter: "blur(2px)",
        zIndex: 1000,
        display: "grid",
        placeItems: "center",
        padding: "20px",
      }}
      onClick={onCancel}
    >
      <div
        className="modalContent"
        style={{
          background: "var(--panel)",
          border: "1px solid var(--line)",
          borderRadius: "12px",
          width: "100%",
          maxWidth: "440px",
          padding: "24px",
          boxShadow: "0 24px 60px -28px rgba(15, 90, 110, 0.35)",
          display: "flex",
          flexDirection: "column",
          gap: "16px",
        }}
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
      >
        <h2 style={{ margin: 0, fontSize: "18px", color: "var(--ink)" }}>{title}</h2>
        <div style={{ color: "var(--muted)", fontSize: "14px", lineHeight: 1.5 }}>
          {message}
        </div>
        {requireReason && (
          <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
            <label htmlFor="deleteReason" style={{ fontSize: "13px", fontWeight: 600, color: "var(--ink)" }}>Reason for deletion</label>
            <input
              id="deleteReason"
              type="text"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="Provide a clear reason..."
              style={{
                width: "100%",
                minHeight: "38px",
                border: "1px solid var(--line)",
                borderRadius: "8px",
                padding: "0 10px",
                background: "#fffef9",
                color: "var(--ink)",
              }}
            />
          </div>
        )}
        <div style={{ display: "flex", justifyContent: "flex-end", gap: "10px", marginTop: "8px" }}>
          <button type="button" className="btnGhost" onClick={onCancel} disabled={isBusy}>
            Cancel
          </button>
          <button
            type="button"
            className={isDanger ? "btnDanger" : "btnPrimary"}
            onClick={() => onConfirm(requireReason ? reason : undefined)}
            disabled={isBusy || (requireReason && !reason.trim())}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}

export function ErrorBanner({ message }: { message: string }) {
  return <div className="banner" role="alert">{message}</div>;
}

export function SuccessBanner({ message }: { message: string }) {
  return <div className="successBanner" role="status">{message}</div>;
}

export function ConsolePage({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <main className={["consolePage", className].filter(Boolean).join(" ")}>{children}</main>;
}

export type MetricGridItem = {
  label: string;
  value: ReactNode;
  icon?: ReactNode;
  color?: string;
};

export function MetricGrid({ ariaLabel, items }: { ariaLabel: string; items: MetricGridItem[] }) {
  return (
    <section className="statGrid" aria-label={ariaLabel}>
      {items.map(({ label, value, icon, color }) => (
        <article key={label} className="statCard">
          {icon ? <div className="statIcon" style={{ color }}>{icon}</div> : null}
          <div>
            <div className="statLabel">{label}</div>
            <strong className="statValue">{value}</strong>
          </div>
        </article>
      ))}
    </section>
  );
}

export function SeverityBadge({ severity }: { severity: "low" | "medium" | "high" }) {
  return <span className={`sevBadge ${severity}`}>{severity}</span>;
}

export function RiskBadge({ band }: { band: RiskBand }) {
  return <span className={`badge band-${band}`}>{band}</span>;
}

export function ActionBadge({ action }: { action: "allow" | "review" | "block" }) {
  const cls = action === "allow" ? "band-low" : action === "review" ? "band-medium" : "band-high";
  return <span className={`badge ${cls}`}>{action}</span>;
}

export function PageHeader({
  eyebrow,
  title,
  subtitle,
}: {
  eyebrow: string;
  title: string;
  subtitle?: string;
}) {
  return (
    <header className="pageHeader">
      <p>{eyebrow}</p>
      <h1>{title}</h1>
      {subtitle ? <span>{subtitle}</span> : null}
    </header>
  );
}

export function SideSheet({
  open,
  onClose,
  title,
  subtitle,
  children,
  width = 720,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  subtitle?: string;
  children: ReactNode;
  width?: number;
}) {
  useEffect(() => {
    if (!open) return;
    function onKey(event: KeyboardEvent) {
      if (event.key === "Escape") onClose();
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  if (!open) return null;
  return (
    <div className="sideSheetOverlay" onClick={onClose} role="presentation">
      <aside
        className="sideSheet"
        style={{ width }}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        onClick={(event) => event.stopPropagation()}
      >
        <header className="sideSheetHead">
          <div>
            <h2>{title}</h2>
            {subtitle ? <span>{subtitle}</span> : null}
          </div>
          <button type="button" className="iconBtn" onClick={onClose} aria-label="Close">
            <X size={18} />
          </button>
        </header>
        <div className="sideSheetBody">{children}</div>
      </aside>
    </div>
  );
}
