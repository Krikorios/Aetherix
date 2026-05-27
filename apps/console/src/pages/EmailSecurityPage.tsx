import { Mail } from "lucide-react";
import type { MeResponse } from "../api";
import { AddOnPage } from "../components/AddOnPage";

export function EmailSecurityPage({ me }: { me: MeResponse }) {
  return (
    <AddOnPage
      me={me}
      icon={Mail}
      title="Email Security"
      description="Deep inspection of inbound and outbound email. Detects phishing, BEC, malicious attachments, and data leakage — with inline blocking, quarantine workflows, and executive impersonation protection."
      features={[
        "Phishing and BEC detection with LLM-assisted scoring",
        "Malicious attachment sandboxing",
        "Outbound DLP with quarantine and approval gate",
        "Executive impersonation protection",
        "Microsoft 365 and Google Workspace integration",
      ]}
      licenceName="Email Security"
    />
  );
}
