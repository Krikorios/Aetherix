import React from "react";
import { Inbox, LoaderCircle } from "lucide-react";

interface EmptyStateProps {
  title?: string;
  message: string;
  icon?: React.ComponentType<{ size?: number; className?: string }>;
}

export function EmptyState({ title = "No Data Available", message, icon: Icon = Inbox }: EmptyStateProps) {
  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        padding: "48px 24px",
        textAlign: "center",
        background: "var(--panel)",
        border: "1px dashed var(--line)",
        borderRadius: "12px",
      }}
    >
      <Icon style={{ color: "var(--muted)", marginBottom: "16px" }} size={40} />
      <h3 style={{ margin: "0 0 8px 0", fontSize: "16px", fontWeight: 600, color: "var(--ink)" }}>{title}</h3>
      <p style={{ margin: 0, fontSize: "14px", color: "var(--muted)", maxWidth: "320px" }}>{message}</p>
    </div>
  );
}

interface LoadingStateProps {
  message?: string;
}

export function LoadingState({ message = "Loading module data..." }: LoadingStateProps) {
  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        padding: "48px 24px",
        textAlign: "center",
      }}
    >
      <LoaderCircle
        style={{
          color: "var(--accent)",
          marginBottom: "16px",
          animation: "spin 1s linear infinite",
        }}
        size={36}
      />
      <p style={{ margin: 0, fontSize: "14px", color: "var(--muted)" }}>{message}</p>
    </div>
  );
}
