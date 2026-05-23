import React from "react";
import { LucideIcon } from "lucide-react";
import { ModuleStatus } from "./types";
import { StatusBadge } from "./StatusBadge";
import { PolicySyncBanner } from "./PolicySyncBanner";

interface QuickAction {
  label: string;
  icon: LucideIcon;
  onClick: () => void;
  disabled?: boolean;
  variant?: "primary" | "secondary";
}

interface ModuleHeaderProps {
  title: string;
  eyebrow?: string;
  icon?: LucideIcon;
  status: ModuleStatus;
  policyVersion: string;
  policyLastSynced: string;
  quickActions?: QuickAction[];
  onRefresh?: () => void;
  isRefreshing?: boolean;
}

export function ModuleHeader({
  title,
  eyebrow = "Protection & Risk",
  icon: Icon,
  status,
  policyVersion,
  policyLastSynced,
  quickActions = [],
  onRefresh,
  isRefreshing = false,
}: ModuleHeaderProps) {
  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        gap: "16px",
        marginBottom: "24px",
      }}
    >
      {/* Top Row: Info & Badges, then Buttons */}
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "flex-start",
          flexWrap: "wrap",
          gap: "16px",
        }}
      >
        <div style={{ display: "flex", alignContent: "center", gap: "12px" }}>
          {Icon && (
            <div
              style={{
                width: "48px",
                height: "48px",
                borderRadius: "10px",
                background: "rgba(11, 107, 87, 0.08)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                color: "var(--accent)",
              }}
            >
              <Icon size={24} />
            </div>
          )}
          <div>
            <span
              style={{
                fontSize: "12px",
                textTransform: "uppercase",
                letterSpacing: "0.05em",
                color: "var(--muted)",
                fontWeight: 600,
              }}
            >
              {eyebrow}
            </span>
            <div style={{ display: "flex", alignItems: "center", gap: "10px", marginTop: "2px" }}>
              <h1 style={{ margin: 0, fontSize: "24px", fontWeight: 700, color: "var(--ink)" }}>{title}</h1>
              <StatusBadge status={status} />
            </div>
          </div>
        </div>

        {/* Buttons / Actions */}
        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
          {quickActions.map((action, idx) => {
            const ButtonIcon = action.icon;
            const isPrimary = action.variant !== "secondary";
            return (
              <button
                key={idx}
                type="button"
                onClick={action.onClick}
                disabled={action.disabled}
                className={isPrimary ? "btnPrimary" : "btnSecondary"}
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  gap: "6px",
                  fontSize: "14px",
                  fontWeight: 600,
                  cursor: "pointer",
                }}
              >
                <ButtonIcon size={16} />
                {action.label}
              </button>
            );
          })}
        </div>
      </div>

      {/* Sync banner below title row */}
      <PolicySyncBanner
        version={policyVersion}
        lastSynced={policyLastSynced}
        onRefresh={onRefresh}
        isRefreshing={isRefreshing}
      />
    </div>
  );
}
