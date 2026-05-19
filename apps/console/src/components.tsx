import { LoaderCircle, X } from "lucide-react";
import { useEffect, type ReactNode } from "react";
import type { RiskBand } from "./api";

export function LoadingRow({ label = "Loading…" }: { label?: string }) {
  return (
    <article className="loadingRow">
      <LoaderCircle aria-hidden="true" />
      <span>{label}</span>
    </article>
  );
}

export function EmptyState({ children }: { children: string }) {
  return <p className="emptyState">{children}</p>;
}

export function ErrorBanner({ message }: { message: string }) {
  return <div className="banner" role="alert">{message}</div>;
}

export function SuccessBanner({ message }: { message: string }) {
  return <div className="successBanner" role="status">{message}</div>;
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
