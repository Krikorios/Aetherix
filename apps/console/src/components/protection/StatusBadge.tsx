import React from "react";
import { Shield, ShieldAlert, ShieldOff, Calendar } from "lucide-react";
import { ModuleStatus } from "./types";

interface StatusBadgeProps {
  status: ModuleStatus;
  size?: number;
}

export function StatusBadge({ status, size = 16 }: StatusBadgeProps) {
  let bgClass = "bg-green-50 text-green-700 border-green-250";
  let label = "Protected";
  let Icon = Shield;

  switch (status) {
    case "protected":
      bgClass = "bg-green-100 text-emerald-800 border-green-300";
      label = "Protected";
      Icon = Shield;
      break;
    case "review_needed":
      bgClass = "bg-amber-100 text-amber-800 border-amber-300";
      label = "Review Needed";
      Icon = ShieldAlert;
      break;
    case "disabled":
      bgClass = "bg-rose-100 text-rose-800 border-rose-300";
      label = "Disabled";
      Icon = ShieldOff;
      break;
    case "planned":
      bgClass = "bg-cyan-100 text-cyan-800 border-cyan-300";
      label = "Planned";
      Icon = Calendar;
      break;
  }

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-semibold rounded-full border ${bgClass}`}
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: "6px",
        padding: "4px 10px",
        borderRadius: "9999px",
        fontSize: "12px",
        fontWeight: 600,
        textTransform: "capitalize",
      }}
    >
      <Icon size={size} />
      {label}
    </span>
  );
}
