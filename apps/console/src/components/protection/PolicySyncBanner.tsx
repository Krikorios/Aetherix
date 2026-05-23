import React from "react";
import { RefreshCw } from "lucide-react";

interface PolicySyncBannerProps {
  version: string;
  lastSynced: string;
  onRefresh?: () => void;
  isRefreshing?: boolean;
}

export function PolicySyncBanner({ version, lastSynced, onRefresh, isRefreshing }: PolicySyncBannerProps) {
  return (
    <div
      className="policySyncBanner"
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        gap: "12px",
        padding: "8px 16px",
        borderRadius: "8px",
        background: "rgba(251, 252, 247, 0.95)",
        border: "1px solid var(--line)",
        fontSize: "13px",
        color: "var(--muted)",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
        <span style={{ fontWeight: 600, color: "var(--ink)" }}>Policy Version:</span>
        <code style={{ background: "rgba(11, 107, 87, 0.08)", padding: "2px 6px", borderRadius: "4px" }}>
          {version}
        </code>
        <span style={{ margin: "0 4px", color: "var(--line)" }}>|</span>
        <span>Synced: {lastSynced}</span>
      </div>
      {onRefresh && (
        <button
          type="button"
          onClick={onRefresh}
          disabled={isRefreshing}
          className="iconBtn"
          style={{
            display: "flex",
            alignItems: "center",
            gap: "6px",
            background: "transparent",
            border: "none",
            color: "var(--accent)",
            fontSize: "12px",
            fontWeight: 500,
            cursor: "pointer",
          }}
        >
          <RefreshCw size={14} className={isRefreshing ? "spinIcon" : ""} style={{ animation: isRefreshing ? "spin 1s linear infinite" : "none" }} />
          Sync Now
        </button>
      )}
    </div>
  );
}
