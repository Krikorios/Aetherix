import React from "react";
import { Mail, Lock, CheckCircle, ArrowRight } from "lucide-react";
import type { MeResponse } from "../api";
import { ConsolePage } from "../components";

export function EmailSecurityPage({ me: _me }: { me: MeResponse }) {
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
          <Mail size={34} style={{ color: "var(--accent)" }} />
        </div>
        <div>
          <div style={{ fontSize: "11px", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.1em", color: "var(--muted)", marginBottom: "8px" }}>
            Add-on Module
          </div>
          <h1 style={{ margin: "0 0 10px 0", fontSize: "24px", fontWeight: 700 }}>Email Security</h1>
          <p style={{ margin: 0, fontSize: "13px", color: "var(--muted)", lineHeight: 1.7 }}>
            Deep inspection of inbound and outbound email. Detects phishing, BEC, malicious attachments, and data leakage — with inline blocking, quarantine workflows, and executive impersonation protection.
          </p>
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: "8px", width: "100%", textAlign: "left" }}>
          {[
            "Phishing and BEC detection with LLM-assisted scoring",
            "Malicious attachment sandboxing",
            "Outbound DLP with quarantine and approval gate",
            "Executive impersonation protection",
            "Microsoft 365 and Google Workspace integration",
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
            <div style={{ fontSize: "12px", color: "var(--muted)" }}>Contact your Aetherix account manager to enable Email Security.</div>
          </div>
          <button className="btn btnPrimary" style={{ flexShrink: 0 }}>
            Contact Us <ArrowRight size={12} />
          </button>
        </div>
      </div>
    </ConsolePage>
  );
}
