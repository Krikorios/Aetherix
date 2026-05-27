import { Smartphone } from "lucide-react";
import type { MeResponse } from "../api";
import { AddOnPage } from "../components/AddOnPage";

export function MobileSecurityPage({ me }: { me: MeResponse }) {
  return (
    <AddOnPage
      me={me}
      icon={Smartphone}
      title="Mobile Security"
      description="Mobile Threat Defense for iOS and Android. Detects device-level risks, rogue apps, and network-based attacks. Integrates with MDM platforms to enforce compliance and trigger automated responses."
      features={[
        "iOS and Android threat detection agent",
        "Rogue app and sideload detection",
        "On-device network attack protection",
        "MDM integration (Intune, Jamf, MobileIron)",
        "Risk-based conditional access enforcement",
      ]}
      licenceName="Mobile Security"
    />
  );
}
