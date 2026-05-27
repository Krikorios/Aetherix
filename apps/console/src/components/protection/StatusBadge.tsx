import React from "react";
import { Shield, ShieldAlert, ShieldOff, Calendar } from "lucide-react";
import { ModuleStatus } from "./types";

interface StatusBadgeProps {
  status: ModuleStatus;
  size?: number;
}

const STATUS_STYLES: Record<ModuleStatus, { bg: string; text: string; border: string }> = {
  protected: { bg: "#ecfdf5", text: "#065f46", border: "#a7f3d0" },
  review_needed: { bg: "#fef3c7", text: "#92400e", border: "#fde68a" },
  disabled: { bg: "#ffe4e6", text: "#9f1239", border: "#fecdd3" },
  planned: { bg: "#cffafe", text: "#155e75", border: "#a5f3fc" },
};

const STATUS_ICONS: Record<ModuleStatus, typeof Shield> = {
  protected: Shield,
  review_needed: ShieldAlert,
  disabled: ShieldOff,
  planned: Calendar,
};

const STATUS_LABELS: Record<ModuleStatus, string> = {
  protected: "Protected",
  review_needed: "Review Needed",
  disabled: "Disabled",
  planned: "Planned",
};

export function StatusBadge({ status, size = 16 }: StatusBadgeProps) {
  const colors = STATUS_STYLES[status];
  const Icon = STATUS_ICONS[status];
  const label = STATUS_LABELS[status];

  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: "6px",
        padding: "4px 10px",
        borderRadius: "9999px",
        fontSize: "12px",
        fontWeight: 600,
        textTransform: "capitalize",
        background: colors.bg,
        color: colors.text,
        border: `1px solid ${colors.border}`,
      }}
    >
      <Icon size={size} />
      {label}
    </span>
  );
}
