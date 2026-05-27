import React from "react";
import { Inbox } from "lucide-react";
import { LoadingRow } from "../../components";

interface EmptyStateProps {
  title?: string;
  message: string;
  icon?: React.ComponentType<{ size?: number; className?: string }>;
}

export function EmptyState({ title = "No Data Available", message, icon: Icon = Inbox }: EmptyStateProps) {
  return (
    <div className="emptyStateCard">
      <div className="emptyStateIconWrap">
        <Icon size={40} />
      </div>
      <h3 className="emptyStateTitle">{title}</h3>
      <p className="emptyStateMessage">{message}</p>
    </div>
  );
}

export function LoadingState({ message = "Loading module data..." }: { message?: string }) {
  return <LoadingRow label={message} />;
}
