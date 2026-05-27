import React from "react";
import { Clock, CheckCircle2, AlertTriangle, ShieldCheck } from "lucide-react";
import type { ActionStatus } from "./types";

interface StagedActionBadgeProps {
  status: ActionStatus;
  /**
   * When true, the action has been confirmed by the agent (i.e. the
   * deterministic enforcement loop reported it actually ran on the
   * endpoint). Anything that lives only in the console (`queued`,
   * `awaiting_approval`, `approved`) is rendered as STAGED.
   *
   * The badge intentionally distinguishes these two states so operators
   * cannot mistake a staged-but-not-yet-executed action for one that has
   * already touched a host. The visual treatment is the same on every
   * protection module page.
   */
  confirmedExecuted?: boolean;
}

function classify(status: ActionStatus, confirmedExecuted: boolean) {
  if (status === "failed") {
    return { kind: "failed" as const, label: "FAILED", icon: AlertTriangle };
  }
  if (confirmedExecuted || status === "executed") {
    return { kind: "executed" as const, label: "EXECUTED", icon: ShieldCheck };
  }
  if (status === "awaiting_approval") {
    return { kind: "awaiting" as const, label: "AWAITING APPROVAL", icon: Clock };
  }
  if (status === "approved") {
    return { kind: "staged" as const, label: "STAGED (APPROVED)", icon: CheckCircle2 };
  }
  return { kind: "staged" as const, label: "STAGED", icon: Clock };
}

const STYLE_BY_KIND: Record<
  "staged" | "awaiting" | "executed" | "failed",
  React.CSSProperties
> = {
  staged: {
    color: "var(--accent)",
    borderColor: "var(--accent)",
    background: "rgba(11, 107, 87, 0.06)",
  },
  awaiting: {
    color: "var(--warning, #b45018)",
    borderColor: "var(--warning, #b45018)",
    background: "rgba(180, 80, 24, 0.07)",
  },
  executed: {
    color: "var(--healthy, #1d6b40)",
    borderColor: "var(--healthy, #1d6b40)",
    background: "rgba(29, 107, 64, 0.09)",
  },
  failed: {
    color: "var(--danger, #b3261e)",
    borderColor: "var(--danger, #b3261e)",
    background: "rgba(179, 38, 30, 0.08)",
  },
};

export function StagedActionBadge({ status, confirmedExecuted = false }: StagedActionBadgeProps) {
  const { kind, label, icon: Icon } = classify(status, confirmedExecuted);
  const base = STYLE_BY_KIND[kind];
  return (
    <span
      data-testid={`staged-action-badge-${kind}`}
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: "4px",
        padding: "2px 8px",
        borderRadius: "999px",
        border: `1px solid ${base.borderColor}`,
        background: base.background,
        color: base.color,
        fontSize: "10px",
        fontWeight: 700,
        textTransform: "uppercase",
        letterSpacing: "0.04em",
      }}
    >
      <Icon size={11} />
      {label}
    </span>
  );
}
