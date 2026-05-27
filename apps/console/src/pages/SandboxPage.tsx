import { Box } from "lucide-react";
import type { MeResponse } from "../api";
import { AddOnPage } from "../components/AddOnPage";

export function SandboxPage({ me }: { me: MeResponse }) {
  return (
    <AddOnPage
      me={me}
      icon={Box}
      title="Threat Sandbox"
      description="Detonation-based analysis for suspicious files and URLs. Submits artefacts to an isolated cloud sandbox, captures full execution traces, network IOCs, and generates a verdict with confidence score."
      features={[
        "Automated file and URL detonation",
        "Full execution trace with MITRE ATT&CK mapping",
        "Network IOC capture and enrichment",
        "Verdict-to-policy feedback loop",
      ]}
      licenceName="Threat Sandbox"
    />
  );
}
