import React, { useState, useEffect } from "react";
import {
  Save,
  RefreshCw,
  Palette,
  Mail,
  Phone,
  Link,
  AlertTriangle,
  CheckCircle,
  Eye,
  EyeOff,
  Building2,
} from "lucide-react";
import { ConsolePage, ErrorBanner, PageHeader, SuccessBanner } from "../components";
import { apiDelete, apiGet, apiPatch, apiPost, type MeResponse, type SystemBanner, type SystemBannerCreate, type SystemBannerSeverity } from "../api";

export interface BrandingConfig {
  product_name: string;
  tagline: string;
  primary_color: string;
  accent_color: string;
  logo_url: string;
  favicon_url: string;
  support_email: string;
  support_url: string;
  support_phone: string;
  footer_note: string;
}

const DEFAULT_BRANDING: BrandingConfig = {
  product_name: "Aetherix",
  tagline: "Intelligent Security for Modern MSPs",
  primary_color: "#0f172a",
  accent_color: "#3b82f6",
  logo_url: "",
  favicon_url: "",
  support_email: "support@aetherix-msp.com",
  support_url: "https://help.aetherix-msp.com",
  support_phone: "",
  footer_note: "© 2026 Aetherix MSP Platform. All rights reserved.",
};

export function ConfigurationPage({ me }: { me: MeResponse }) {
  const [isLoading, setIsLoading] = useState(true);
  const [isSaving, setIsSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [branding, setBranding] = useState<BrandingConfig>(DEFAULT_BRANDING);
  const [draft, setDraft] = useState<BrandingConfig>(DEFAULT_BRANDING);
  const [banners, setBanners] = useState<SystemBanner[]>([]);
  const [bannerDraft, setBannerDraft] = useState<SystemBannerCreate>({
    message: "Due to a scheduled update, Control Center will be unavailable on June 9, 2026 from 09:00 AM GMT+03:00 to 02:00 PM GMT+03:00.",
    link_label: "Release Notes",
    link_url: "https://example.com/release-notes",
    severity: "warning",
  });
  const [isDirty, setIsDirty] = useState(false);
  const [previewMode, setPreviewMode] = useState(false);
  const isPlatformOwner = me.account.roles.some((role) => role.role_code === "platform_owner");

  // Live branding from /me scope
  useEffect(() => {
    const meB = me.branding;
    if (meB) {
      const loaded: BrandingConfig = {
        product_name: meB.product_name ?? DEFAULT_BRANDING.product_name,
        tagline: meB.tagline ?? DEFAULT_BRANDING.tagline,
        primary_color: meB.primary_color ?? DEFAULT_BRANDING.primary_color,
        accent_color: meB.accent_color ?? DEFAULT_BRANDING.accent_color,
        logo_url: meB.logo_url ?? DEFAULT_BRANDING.logo_url,
        favicon_url: DEFAULT_BRANDING.favicon_url,
        support_email: meB.support_email ?? DEFAULT_BRANDING.support_email,
        support_url: meB.support_url ?? DEFAULT_BRANDING.support_url,
        support_phone: DEFAULT_BRANDING.support_phone,
        footer_note: meB.footer_note ?? DEFAULT_BRANDING.footer_note,
      };
      setBranding(loaded);
      setDraft(loaded);
    }
    setIsLoading(false);
  }, [me]);

  useEffect(() => {
    if (!isPlatformOwner) return;
    apiGet<SystemBanner[]>("/system/banners/all")
      .then(setBanners)
      .catch(() => setBanners([]));
  }, [isPlatformOwner]);

  const handleChange = (field: keyof BrandingConfig, value: string) => {
    setDraft((prev) => ({ ...prev, [field]: value }));
    setIsDirty(true);
  };

  const handleSave = async () => {
    setIsSaving(true);
    setError(null);
    try {
      await apiPatch<MeResponse>("/branding", {
        product_name: draft.product_name,
        tagline: draft.tagline,
        primary_color: draft.primary_color,
        accent_color: draft.accent_color,
        logo_url: draft.logo_url || null,
        support_email: draft.support_email || null,
        support_url: draft.support_url || null,
        footer_note: draft.footer_note || null,
      });
      setBranding(draft);
      setIsDirty(false);
      setSuccess("Branding configuration saved.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to save branding configuration.");
    } finally {
      setIsSaving(false);
    }
  };

  const handleReset = () => {
    setDraft(branding);
    setIsDirty(false);
  };

  const handleCreateBanner = async () => {
    if (!bannerDraft.message?.trim()) {
      setError("Banner message is required.");
      return;
    }
    setIsSaving(true);
    setError(null);
    try {
      const created = await apiPost<SystemBanner>("/system/banners", {
        ...bannerDraft,
        link_label: bannerDraft.link_label?.trim() || null,
        link_url: bannerDraft.link_url?.trim() || null,
      });
      setBanners((current) => [created, ...current]);
      setSuccess("System banner published.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to publish banner.");
    } finally {
      setIsSaving(false);
    }
  };

  const handleDisableBanner = async (id: string) => {
    setError(null);
    try {
      await apiDelete(`/system/banners/${id}`);
      setBanners((current) => current.map((banner) => banner.id === id ? { ...banner, active: false } : banner));
      setSuccess("System banner disabled.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to disable banner.");
    }
  };

  if (isLoading) {
    return (
      <div style={{ padding: "40px", width: "100%", display: "flex", alignItems: "center", gap: "12px", color: "var(--muted)", fontSize: "13px" }}>
        <RefreshCw size={16} className="spin" /> Loading configuration…
      </div>
    );
  }

  const fieldStyle: React.CSSProperties = {
    display: "flex",
    flexDirection: "column",
    gap: "5px",
    fontSize: "12px",
    color: "var(--muted)",
  };

  const previewBranding = previewMode ? draft : branding;

  return (
    <ConsolePage>
      {/* Header */}
      <div style={{ marginBottom: "24px" }}>
        <PageHeader eyebrow="Platform Settings" title="Configuration" subtitle="MSP white-label branding, support contacts, and global defaults." />
        <div style={{ display: "flex", gap: "8px" }}>
            <button className="btn" onClick={() => setPreviewMode(!previewMode)}>
              {previewMode ? <EyeOff size={14} /> : <Eye size={14} />}
              {previewMode ? "Stop Preview" : "Preview Changes"}
            </button>
            {isDirty && (
              <button className="btn" onClick={handleReset}>
                <RefreshCw size={14} /> Discard
              </button>
            )}
            <button className="btn btnPrimary" onClick={handleSave} disabled={isSaving || !isDirty}>
              <Save size={14} />
              {isSaving ? "Saving…" : "Save Changes"}
            </button>
          </div>
        </div>
        {isDirty && (
          <div style={{ marginTop: "8px", fontSize: "12px", color: "var(--warning)", display: "flex", alignItems: "center", gap: "6px" }}>
            <AlertTriangle size={13} /> Unsaved changes
          </div>
        )}

      {error && <ErrorBanner message={error} />}
      {success && <SuccessBanner message={success} />}

      <div style={{ display: "flex", gap: "20px", flex: 1, flexWrap: "wrap", alignItems: "flex-start" }}>
        {/* Left: settings form */}
        <div style={{ flex: "1 1 420px", minWidth: "320px", display: "flex", flexDirection: "column", gap: "20px" }}>
          {isPlatformOwner && (
            <div className="panel ownerBannerPanel">
              <h3><AlertTriangle size={14} /> System Banner</h3>
              <label>
                Message
                <textarea
                  className="input"
                  value={bannerDraft.message ?? ""}
                  onChange={(event) => setBannerDraft((current) => ({ ...current, message: event.target.value }))}
                  rows={3}
                />
              </label>
              <div className="ownerBannerGrid">
                <label>
                  Severity
                  <select
                    className="input"
                    value={bannerDraft.severity ?? "warning"}
                    onChange={(event) => setBannerDraft((current) => ({ ...current, severity: event.target.value as SystemBannerSeverity }))}
                  >
                    <option value="info">Info</option>
                    <option value="warning">Warning</option>
                    <option value="critical">Critical</option>
                  </select>
                </label>
                <label>
                  Ends at
                  <input
                    className="input"
                    type="datetime-local"
                    value={bannerDraft.ends_at ?? ""}
                    onChange={(event) => setBannerDraft((current) => ({ ...current, ends_at: event.target.value ? new Date(event.target.value).toISOString() : null }))}
                  />
                </label>
              </div>
              <div className="ownerBannerGrid">
                <label>
                  Link label
                  <input className="input" value={bannerDraft.link_label ?? ""} onChange={(event) => setBannerDraft((current) => ({ ...current, link_label: event.target.value }))} />
                </label>
                <label>
                  Link URL
                  <input className="input" value={bannerDraft.link_url ?? ""} onChange={(event) => setBannerDraft((current) => ({ ...current, link_url: event.target.value }))} />
                </label>
              </div>
              <button className="btn btnPrimary" type="button" onClick={handleCreateBanner} disabled={isSaving}>
                Publish Banner
              </button>
              <div className="ownerBannerList">
                {banners.length === 0 ? <span>No banners created.</span> : banners.map((banner) => (
                  <article key={banner.id} className={!banner.active ? "inactive" : ""}>
                    <strong>{banner.message}</strong>
                    <span>{banner.severity} · {banner.active ? "active" : "inactive"}</span>
                    {banner.active ? <button type="button" onClick={() => handleDisableBanner(banner.id)}>Disable</button> : null}
                  </article>
                ))}
              </div>
            </div>
          )}

          {/* Branding section */}
          <div className="panel" style={{ padding: "20px" }}>
            <h3 style={{ margin: "0 0 16px 0", fontSize: "13px", fontWeight: 600, display: "flex", alignItems: "center", gap: "6px" }}>
              <Palette size={14} /> White-Label Branding
            </h3>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "14px" }}>
              <div style={{ ...fieldStyle, gridColumn: "1 / -1" }}>
                Product Name
                <input className="input" value={draft.product_name} onChange={(e) => handleChange("product_name", e.target.value)} placeholder="Aetherix" />
              </div>
              <div style={{ ...fieldStyle, gridColumn: "1 / -1" }}>
                Tagline
                <input className="input" value={draft.tagline} onChange={(e) => handleChange("tagline", e.target.value)} placeholder="Your platform tagline" />
              </div>
              <div style={fieldStyle}>
                Primary Color
                <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
                  <input
                    type="color"
                    value={draft.primary_color}
                    onChange={(e) => handleChange("primary_color", e.target.value)}
                    style={{ width: "40px", height: "32px", padding: "2px", border: "1px solid var(--line)", borderRadius: "4px", background: "none", cursor: "pointer" }}
                  />
                  <input className="input" value={draft.primary_color} onChange={(e) => handleChange("primary_color", e.target.value)} placeholder="#0f172a" style={{ flex: 1 }} />
                </div>
              </div>
              <div style={fieldStyle}>
                Accent Color
                <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
                  <input
                    type="color"
                    value={draft.accent_color}
                    onChange={(e) => handleChange("accent_color", e.target.value)}
                    style={{ width: "40px", height: "32px", padding: "2px", border: "1px solid var(--line)", borderRadius: "4px", background: "none", cursor: "pointer" }}
                  />
                  <input className="input" value={draft.accent_color} onChange={(e) => handleChange("accent_color", e.target.value)} placeholder="#3b82f6" style={{ flex: 1 }} />
                </div>
              </div>
              <div style={{ ...fieldStyle, gridColumn: "1 / -1" }}>
                Logo URL
                <input className="input" value={draft.logo_url} onChange={(e) => handleChange("logo_url", e.target.value)} placeholder="https://cdn.example.com/logo.svg" />
              </div>
              <div style={{ ...fieldStyle, gridColumn: "1 / -1" }}>
                Footer Note
                <input className="input" value={draft.footer_note} onChange={(e) => handleChange("footer_note", e.target.value)} placeholder="© Your Company 2026" />
              </div>
            </div>
          </div>

          {/* Support contacts */}
          <div className="panel" style={{ padding: "20px" }}>
            <h3 style={{ margin: "0 0 16px 0", fontSize: "13px", fontWeight: 600, display: "flex", alignItems: "center", gap: "6px" }}>
              <Mail size={14} /> Support Contacts
            </h3>
            <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
              <div style={fieldStyle}>
                Support Email
                <div style={{ position: "relative" }}>
                  <Mail size={13} style={{ position: "absolute", left: "10px", top: "50%", transform: "translateY(-50%)", color: "var(--muted)", pointerEvents: "none" }} />
                  <input
                    className="input"
                    type="email"
                    value={draft.support_email}
                    onChange={(e) => handleChange("support_email", e.target.value)}
                    placeholder="support@yourcompany.com"
                    style={{ paddingLeft: "30px" }}
                  />
                </div>
              </div>
              <div style={fieldStyle}>
                Support URL
                <div style={{ position: "relative" }}>
                  <Link size={13} style={{ position: "absolute", left: "10px", top: "50%", transform: "translateY(-50%)", color: "var(--muted)", pointerEvents: "none" }} />
                  <input
                    className="input"
                    value={draft.support_url}
                    onChange={(e) => handleChange("support_url", e.target.value)}
                    placeholder="https://help.yourcompany.com"
                    style={{ paddingLeft: "30px" }}
                  />
                </div>
              </div>
              <div style={fieldStyle}>
                Support Phone (optional)
                <div style={{ position: "relative" }}>
                  <Phone size={13} style={{ position: "absolute", left: "10px", top: "50%", transform: "translateY(-50%)", color: "var(--muted)", pointerEvents: "none" }} />
                  <input
                    className="input"
                    value={draft.support_phone}
                    onChange={(e) => handleChange("support_phone", e.target.value)}
                    placeholder="+1 (555) 000-0000"
                    style={{ paddingLeft: "30px" }}
                  />
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Right: live preview */}
        <div style={{ flex: "1 1 320px", minWidth: "280px" }}>
          <div className="panel" style={{ padding: "20px" }}>
            <h3 style={{ margin: "0 0 14px 0", fontSize: "13px", fontWeight: 600, display: "flex", alignItems: "center", gap: "6px" }}>
              <Eye size={14} /> Brand Preview
            </h3>
            <div
              style={{
                border: "1px solid var(--line)",
                borderRadius: "8px",
                overflow: "hidden",
                background: previewBranding.primary_color,
              }}
            >
              {/* Sidebar header preview */}
              <div style={{ padding: "16px", borderBottom: "1px solid rgba(255,255,255,0.08)" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                  {previewBranding.logo_url ? (
                    <img
                      src={previewBranding.logo_url}
                      alt="Logo"
                      style={{ width: "28px", height: "28px", objectFit: "contain" }}
                      onError={(e) => { (e.target as HTMLImageElement).style.display = "none"; }}
                    />
                  ) : (
                    <div style={{ width: "28px", height: "28px", borderRadius: "6px", background: previewBranding.accent_color, display: "flex", alignItems: "center", justifyContent: "center" }}>
                      <Building2 size={14} color="#fff" />
                    </div>
                  )}
                  <div>
                    <div style={{ color: "#f8fafc", fontWeight: 700, fontSize: "13px", lineHeight: 1.2 }}>{previewBranding.product_name || "Product"}</div>
                    <div style={{ color: "rgba(248,250,252,0.5)", fontSize: "10px" }}>{previewBranding.tagline}</div>
                  </div>
                </div>
              </div>
              {/* Navigation item preview */}
              <div style={{ padding: "10px 12px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "8px", padding: "8px 10px", borderRadius: "6px", background: previewBranding.accent_color + "22" }}>
                  <div style={{ width: "10px", height: "10px", borderRadius: "2px", background: previewBranding.accent_color }} />
                  <span style={{ color: previewBranding.accent_color, fontSize: "12px", fontWeight: 600 }}>Alerts</span>
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: "8px", padding: "8px 10px", marginTop: "2px" }}>
                  <div style={{ width: "10px", height: "10px", borderRadius: "2px", background: "rgba(248,250,252,0.3)" }} />
                  <span style={{ color: "rgba(248,250,252,0.5)", fontSize: "12px" }}>Dashboard</span>
                </div>
              </div>
              {/* Footer */}
              <div style={{ padding: "10px 12px", borderTop: "1px solid rgba(255,255,255,0.08)" }}>
                <div style={{ color: "rgba(248,250,252,0.35)", fontSize: "10px" }}>{previewBranding.footer_note}</div>
              </div>
            </div>
            <div style={{ marginTop: "14px", fontSize: "11px", color: "var(--muted)", display: "flex", flexDirection: "column", gap: "4px" }}>
              <div style={{ display: "flex", gap: "6px", alignItems: "center" }}>
                <Mail size={11} />
                <span>{previewBranding.support_email || "—"}</span>
              </div>
              <div style={{ display: "flex", gap: "6px", alignItems: "center" }}>
                <Link size={11} />
                <span>{previewBranding.support_url || "—"}</span>
              </div>
              {previewBranding.support_phone && (
                <div style={{ display: "flex", gap: "6px", alignItems: "center" }}>
                  <Phone size={11} />
                  <span>{previewBranding.support_phone}</span>
                </div>
              )}
            </div>
          </div>

          {/* Current effective branding note */}
          <div className="panel" style={{ padding: "14px 16px", marginTop: "14px" }}>
            <div style={{ fontSize: "11px", color: "var(--muted)", display: "flex", alignItems: "center", gap: "6px" }}>
              <CheckCircle size={12} style={{ color: "var(--success)" }} />
              Branding settings are applied live to the accent colour, product name, and sidebar on each session.
            </div>
          </div>
        </div>
      </div>
    </ConsolePage>
  );
}
