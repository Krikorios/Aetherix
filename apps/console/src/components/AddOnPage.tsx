import React from "react";
import { Lock, CheckCircle, ArrowRight, type LucideIcon } from "lucide-react";
import type { MeResponse } from "../api";
import { ConsolePage } from "../components";

interface AddOnPageProps {
  me: MeResponse;
  icon: LucideIcon;
  title: string;
  description: string;
  features: string[];
  licenceName: string;
}

export function AddOnPage({ me: _me, icon: Icon, title, description, features, licenceName }: AddOnPageProps) {
  return (
    <ConsolePage className="addOnPage">
      <div className="addOnPanel">
        <div className="addOnIconBox">
          <Icon size={34} />
        </div>
        <div>
          <div className="addOnEyebrow">Add-on Module</div>
          <h1 className="addOnTitle">{title}</h1>
          <p className="addOnDescription">{description}</p>
        </div>
        <div className="addOnFeatures">
          {features.map((f) => (
            <div key={f} className="addOnFeatureRow">
              <CheckCircle size={14} className="addOnFeatureIcon" />
              {f}
            </div>
          ))}
        </div>
        <div className="addOnCta">
          <Lock size={18} className="addOnCtaIcon" />
          <div className="addOnCtaText">
            <div className="addOnCtaTitle">This module requires an add-on licence</div>
            <div className="addOnCtaSub">Contact your Aetherix account manager to enable {licenceName}.</div>
          </div>
          <button className="btn btnPrimary addOnCtaBtn">
            Contact Us <ArrowRight size={12} />
          </button>
        </div>
      </div>
    </ConsolePage>
  );
}
