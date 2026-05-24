import React from "react";
import { Box, Lock, CheckCircle, ArrowRight } from "lucide-react";
import type { MeResponse } from "../api";
import { ConsolePage } from "../components";

export function SandboxPage({ me: _me }: { me: MeResponse }) {
  return (
    <ConsolePage className="addOnPage">
      <div className="addOnPanel">
        <div
          style={{
            width: "72px", height: "72px", borderRadius: "18px",
            background: "rgba(var(--accent-rgb),0.1)",
            display: "flex", alignItems: "center", justifyContent: "center",
          }}
        >
          <Box size={34} style={{ color: "var(--accent)" }} />
        </div>
        <div>
          <div style={{ fontSize: "11px", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.1em", color: "var(--muted)", marginBottom: "8px" }}>
            Add-on Module
          </div>
          <h1 style={{ margin: "0 0 10px 0", fontSize: "24px", fontWeight: 700 }}>Threat Sandbox</h1>
          <p style={{ margin: 0, fontSize: "13px", color: "var(--muted)", lineHeight: 1.7 }}>
            Detonation-based analysis for suspicious files and URLs. Submits artefacts to an isolated cloud sandbox, captures full execution traces, network IOCs, and generates a verdict with confidence score.
          </p>
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: "8px", width: "100%", textAlign: "left" }}>
          {[
            "Automated file and URL detonation",
            "Full execution trace with MITRE ATT&CK mapping",
            "Network IOC capture and enrichment",
            "Verdict-to-policy feedback loop",
          ].map((f) => (
            <div key={f} style={{ display: "flex", gap: "8px", alignItems: "center", fontSize: "13px", color: "var(--muted)" }}>
              <CheckCircle size={14} style={{ color: "var(--accent)", flexShrink: 0 }} />
              {f}
            </div>
          ))}
        </div>
        <div
          style={{
            background: "rgba(var(--accent-rgb),0.06)",
            border: "1px solid rgba(var(--accent-rgb),0.18)",
            borderRadius: "10px",
            padding: "16px 20px",
            display: "flex",
            gap: "12px",
            alignItems: "center",
            width: "100%",
            textAlign: "left",
          }}
        >
          <Lock size={18} style={{ color: "var(--accent)", flexShrink: 0 }} />
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: "13px", fontWeight: 600 }}>This module requires an add-on licence</div>
            <div style={{ fontSize: "12px", color: "var(--muted)" }}>Contact your Aetherix account manager to enable Threat Sandbox.</div>
          </div>
          <button className="btn btnPrimary" style={{ flexShrink: 0 }}>
            Contact Us <ArrowRight size={12} />
          </button>
        </div>
      </div>
    </ConsolePage>
  );
}
