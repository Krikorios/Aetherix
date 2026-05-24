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
    <header className="moduleHeader">
      {/* Top Row: Info & Badges, then Buttons */}
      <div className="moduleHeaderTop">
        <div className="moduleHeaderTitleBlock">
          {Icon && (
            <div className="moduleHeaderIcon">
              <Icon size={24} />
            </div>
          )}
          <div>
            <span className="moduleHeaderEyebrow">
              {eyebrow}
            </span>
            <div className="moduleHeaderTitleRow">
              <h1>{title}</h1>
              <StatusBadge status={status} />
            </div>
          </div>
        </div>

        {/* Buttons / Actions */}
        <div className="moduleHeaderActions">
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
    </header>
  );
}
