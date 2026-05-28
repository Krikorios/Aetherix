import { useState } from "react";
import { Activity, Globe2 } from "lucide-react";
import { EASMPage } from "./EASMPage";
import { EndpointHealthPage } from "./EndpointHealthPage";
import type { MeResponse } from "../api";

type Tab = "health" | "attackSurface";

export function HealthAttackSurfacePage({ me }: { me: MeResponse }) {
  const [activeTab, setActiveTab] = useState<Tab>("health");

  return (
    <>
      <div className="pageTabBar healthAttackSurfaceTabs" role="tablist" aria-label="Health and attack surface views">
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === "health"}
          className={`pageTab${activeTab === "health" ? " active" : ""}`}
          onClick={() => setActiveTab("health")}
        >
          <Activity size={14} />
          Endpoint Health
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === "attackSurface"}
          className={`pageTab${activeTab === "attackSurface" ? " active" : ""}`}
          onClick={() => setActiveTab("attackSurface")}
        >
          <Globe2 size={14} />
          External Attack Surface
        </button>
      </div>

      {activeTab === "health" ? <EndpointHealthPage me={me} embedded /> : <EASMPage me={me} embedded />}
    </>
  );
}
