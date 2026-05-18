import { LoaderCircle } from "lucide-react";
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
