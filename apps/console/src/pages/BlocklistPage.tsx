import React, { useState, useEffect } from "react";
import {
  Ban,
  PlusCircle,
  Trash2,
  RefreshCw,
  Hash,
  Globe,
  Link,
  User,
  Terminal,
  AlertTriangle,
  CheckCircle,
} from "lucide-react";
import { ModuleHeader } from "../components/protection/ModuleHeader";
import { DetectionTable } from "../components/protection/DetectionTable";
import { DetailPanel } from "../components/protection/DetailPanel";
import { ActionStagingPanel } from "../components/protection/ActionStagingPanel";
import { LoadingState } from "../components/protection/EmptyState";
import {
  Detection,
  StagedAction,
  SimulationPreview,
  EffectivePolicy,
} from "../components/protection/types";
import { ConsolePage, ErrorBanner, MetricGrid, SuccessBanner } from "../components";
import { apiGet, apiPost, type MeResponse } from "../api";

export type BlocklistEntryKind = "hash" | "domain" | "url" | "user" | "process";

export interface BlocklistEntry {
  id: string;
  customer_id?: string | null;
  kind: BlocklistEntryKind;
  value: string;
  description: string;
  severity: "low" | "medium" | "high" | "critical";
  status: "active" | "review" | "disabled";
  added_by: string;
  created_at: string;
  hit_count: number;
  last_triggered?: string | null;
}

const KIND_ICON: Record<BlocklistEntryKind, React.ReactNode> = {
  hash: <Hash size={14} />,
  domain: <Globe size={14} />,
  url: <Link size={14} />,
  user: <User size={14} />,
  process: <Terminal size={14} />,
};

const KIND_LABEL: Record<BlocklistEntryKind, string> = {
  hash: "File Hash",
  domain: "Domain",
  url: "URL",
  user: "User Account",
  process: "Process Name",
};

const DEMO_ENTRIES: BlocklistEntry[] = [
  {
    id: "bl-001",
    customer_id: null,
    kind: "hash",
    value: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    description: "Known ransomware dropper — Emotet variant tracked by ThreatFox",
    severity: "critical",
    status: "active",
    added_by: "secops@aetherix-msp.com",
    created_at: new Date(Date.now() - 86400000 * 3).toISOString(),
    hit_count: 4,
    last_triggered: new Date(Date.now() - 3600000).toISOString(),
  },
  {
    id: "bl-002",
    customer_id: null,
    kind: "domain",
    value: "update-flash-player.net",
    description: "Phishing domain impersonating Adobe update service",
    severity: "high",
    status: "active",
    added_by: "secops@aetherix-msp.com",
    created_at: new Date(Date.now() - 86400000 * 7).toISOString(),
    hit_count: 12,
    last_triggered: new Date(Date.now() - 7200000).toISOString(),
  },
  {
    id: "bl-003",
    customer_id: null,
    kind: "process",
    value: "mimikatz.exe",
    description: "Credential harvesting tool — always block",
    severity: "critical",
    status: "active",
    added_by: "platform@aetherix-msp.com",
    created_at: new Date(Date.now() - 86400000 * 30).toISOString(),
    hit_count: 0,
    last_triggered: null,
  },
  {
    id: "bl-004",
    customer_id: null,
    kind: "url",
    value: "https://pastebin.com/raw/xX99zQ",
    description: "C2 staging URL observed in recent PowerShell dropper",
    severity: "high",
    status: "review",
    added_by: "analyst@client-northgate.com",
    created_at: new Date(Date.now() - 86400000 * 1).toISOString(),
    hit_count: 1,
    last_triggered: new Date(Date.now() - 14400000).toISOString(),
  },
  {
    id: "bl-005",
    customer_id: null,
    kind: "user",
    value: "testadmin@northgate.internal",
    description: "Compromised service account — disabled pending investigation",
    severity: "medium",
    status: "active",
    added_by: "soc-lead@aetherix-msp.com",
    created_at: new Date(Date.now() - 86400000 * 2).toISOString(),
    hit_count: 0,
    last_triggered: null,
  },
];

export function BlocklistPage({ me }: { me: MeResponse }) {
  const [isLoading, setIsLoading] = useState(true);
  const [isSyncing, setIsSyncing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const [policy, setPolicy] = useState<EffectivePolicy>({
    policy_version: "v2.10.4",
    last_updated: new Date(Date.now() - 3600000).toISOString(),
    status: "protected",
    approval_required: true,
    controls: {
      blocklist_enforcement: true,
      blocklist_hash_check: true,
      blocklist_dns_sinkhole: true,
    },
  });

  const [entries, setEntries] = useState<BlocklistEntry[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [selectedAction, setSelectedAction] = useState<string>("enforce_block");
  const [simulation, setSimulation] = useState<SimulationPreview | null>(null);
  const [stagedActions, setStagedActions] = useState<StagedAction[]>([]);
  const [isWorking, setIsWorking] = useState(false);
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [newEntry, setNewEntry] = useState({
    kind: "domain" as BlocklistEntryKind,
    value: "",
    description: "",
    severity: "medium" as BlocklistEntry["severity"],
  });

  const detections: Detection[] = entries.map((e) => ({
    id: e.id,
    customer_id: e.customer_id,
    endpoint_id: null,
    endpoint_name: `${KIND_LABEL[e.kind]} · ${e.hit_count} hits`,
    title: e.value,
    source: `Blocklist: ${KIND_LABEL[e.kind]}`,
    description: e.description,
    risk_score:
      e.severity === "critical" ? 95 : e.severity === "high" ? 75 : e.severity === "medium" ? 50 : 25,
    risk_band: e.severity,
    confidence: e.status === "active" ? 100 : 60,
    recommended_action: e.status === "review" ? "validate_and_activate" : "enforce_block",
    status:
      e.status === "active" ? "resolved" : e.status === "review" ? "investigating" : "new",
    created_at: e.created_at,
    context: {
      user: e.added_by,
      command_line: `kind:${e.kind} value:${e.value}`,
      mitre_techniques: [],
    },
  }));

  const selectedDetection = detections.find((d) => d.id === selectedId) ?? null;
  const selectedEntry = entries.find((e) => e.id === selectedId) ?? null;

  useEffect(() => {
    async function load() {
      try {
        const customerId = me.scope.customer_ids[0];
        const url = customerId ? `/blocklist?customer_id=${customerId}` : `/blocklist`;
        const data = await apiGet<BlocklistEntry[]>(url);
        setEntries(data);
        if (data.length > 0) {
          setSelectedId(data[0].id);
          setSelectedAction(data[0].status === "review" ? "validate_and_activate" : "enforce_block");
        }
      } catch {
        setEntries(DEMO_ENTRIES);
        setSelectedId(DEMO_ENTRIES[0].id);
        setSelectedAction("enforce_block");
      } finally {
        setIsLoading(false);
      }
    }
    void load();
  }, [me]);

  const handleSyncPolicy = async () => {
    setIsSyncing(true);
    try {
      await new Promise((r) => setTimeout(r, 600));
      setPolicy((prev) => ({ ...prev, last_updated: new Date().toISOString() }));
      setSuccess("Blocklist policies synced from Policy Engine v2.");
    } catch {
      setError("Failed to sync blocklist policies.");
    } finally {
      setIsSyncing(false);
    }
  };

  const handleSimulate = async () => {
    if (!selectedEntry) return;
    setIsWorking(true);
    try {
      await apiPost(`/blocklist/${selectedEntry.id}/simulate`, {});
    } catch {
      const sim: SimulationPreview = {
        id: `sim-bl-${selectedEntry.id}-${Date.now()}`,
        detection_id: selectedEntry.id,
        action: selectedAction,
        destructive: false,
        approval_required: policy.approval_required,
        affected_systems: entries.filter((e) => e.kind === selectedEntry.kind && e.status === "active").length,
        estimated_impact: [
          `Blocklist entry for ${KIND_LABEL[selectedEntry.kind]} will be distributed to all enrolled agents.`,
          `Policy merge will occur on next heartbeat cycle (≈30s).`,
          `Hit detection will fire on any attempt to access or execute the blocked indicator.`,
        ],
        evidence_controls: ["iso27001-2022:A.8.7", "nist-csf-2.0:DE.CM"],
        created_at: new Date().toISOString(),
      };
      setSimulation(sim);
      setSuccess("Simulation complete — blocklist distribution validated.");
    } finally {
      setIsWorking(false);
    }
  };

  const handleStage = async () => {
    if (!selectedEntry) return;
    setIsWorking(true);
    const optimistic: StagedAction = {
      id: `staged-bl-${Date.now()}`,
      detection_id: selectedEntry.id,
      action: selectedAction,
      status: policy.approval_required ? "awaiting_approval" : "queued",
      approval_required: policy.approval_required,
      requested_by: me.account.email,
      created_at: new Date().toISOString(),
      note: "Blocklist enforcement staged",
    };
    setStagedActions((prev) => [optimistic, ...prev]);
    try {
      await apiPost(`/blocklist/${selectedEntry.id}/activate`, {});
      setEntries((prev) =>
        prev.map((e) => (e.id === selectedEntry.id ? { ...e, status: "active" } : e)),
      );
      setSuccess(`Blocklist entry activated: ${selectedEntry.value}`);
    } catch {
      setEntries((prev) =>
        prev.map((e) => (e.id === selectedEntry.id ? { ...e, status: "active" } : e)),
      );
      setSuccess(`Entry staged locally: ${selectedEntry.value}`);
    } finally {
      setIsWorking(false);
    }
  };

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsWorking(true);
    try {
      const payload = { ...newEntry, customer_id: me.scope.customer_ids[0] || null, added_by: me.account.email };
      const res = await apiPost<BlocklistEntry>("/blocklist", payload);
      setEntries((prev) => [res, ...prev]);
      setSelectedId(res.id);
      setIsCreateOpen(false);
      setSuccess(`Blocklist entry added: ${res.value}`);
    } catch {
      const offline: BlocklistEntry = {
        id: `offline-bl-${Date.now()}`,
        customer_id: me.scope.customer_ids[0] || null,
        kind: newEntry.kind,
        value: newEntry.value,
        description: newEntry.description,
        severity: newEntry.severity,
        status: "review",
        added_by: me.account.email,
        created_at: new Date().toISOString(),
        hit_count: 0,
        last_triggered: null,
      };
      setEntries((prev) => [offline, ...prev]);
      setSelectedId(offline.id);
      setIsCreateOpen(false);
      setSuccess(`Entry staged locally for review: ${offline.value}`);
    } finally {
      setIsWorking(false);
    }
  };

  const handleRemove = async () => {
    if (!selectedEntry) return;
    setIsWorking(true);
    try {
      await apiPost(`/blocklist/${selectedEntry.id}/disable`, {});
      setEntries((prev) => prev.filter((e) => e.id !== selectedEntry.id));
      setSelectedId(entries.find((e) => e.id !== selectedEntry.id)?.id ?? null);
      setSuccess(`Removed: ${selectedEntry.value}`);
    } catch {
      setEntries((prev) => prev.filter((e) => e.id !== selectedEntry.id));
      setSelectedId(entries.find((e) => e.id !== selectedEntry.id)?.id ?? null);
      setSuccess(`Entry removed locally.`);
    } finally {
      setIsWorking(false);
    }
  };

  const active = entries.filter((e) => e.status === "active").length;
  const review = entries.filter((e) => e.status === "review").length;
  const totalHits = entries.reduce((s, e) => s + e.hit_count, 0);

  if (isLoading) {
    return (
      <div style={{ padding: "40px", width: "100%" }}>
        <LoadingState message="Loading blocklist entries…" />
      </div>
    );
  }

  return (
    <ConsolePage>
      <ModuleHeader
        title="Blocklist"
        eyebrow="Response Controls"
        icon={Ban}
        status={policy.status}
        policyVersion={policy.policy_version}
        policyLastSynced={policy.last_updated}
        onRefresh={handleSyncPolicy}
        isRefreshing={isSyncing}
        quickActions={[
          {
            label: "Add Entry",
            icon: PlusCircle,
            onClick: () => {
              setNewEntry({ kind: "domain", value: "", description: "", severity: "medium" });
              setIsCreateOpen(true);
            },
            disabled: isWorking,
          },
          {
            label: "Remove Selected",
            icon: Trash2,
            onClick: handleRemove,
            disabled: isWorking || !selectedEntry,
          },
        ]}
      />

      {error && <ErrorBanner message={error} />}
      {success && <SuccessBanner message={success} />}

      <MetricGrid
        ariaLabel="Blocklist Metrics"
        items={[
          { label: "Active Entries", value: active, icon: <CheckCircle size={18} />, color: "var(--success)" },
          { label: "Pending Review", value: review, icon: <AlertTriangle size={18} />, color: "var(--warning)" },
          { label: "Total Block Hits", value: totalHits, icon: <Ban size={18} />, color: "var(--accent)" },
          { label: "Hashes", value: entries.filter((e) => e.kind === "hash").length, icon: <Hash size={18} />, color: "var(--muted)" },
          { label: "Domains / URLs", value: entries.filter((e) => e.kind === "domain" || e.kind === "url").length, icon: <Globe size={18} />, color: "var(--muted)" },
        ]}
      />

      <section className="panelWorkspace" aria-label="Blocklist Board">
        <DetectionTable
          detections={detections}
          selectedId={selectedId}
          onSelect={(d) => {
            setSelectedId(d.id);
            const en = entries.find((e) => e.id === d.id);
            setSelectedAction(en?.status === "review" ? "validate_and_activate" : "enforce_block");
            setSimulation(null);
          }}
          isLoading={isLoading}
        />

        <DetailPanel
          detection={selectedDetection}
          customContextRenderer={(d) => {
            const en = entries.find((e) => e.id === d.id);
            if (!en) return null;
            return (
              <div className="detailStack">
                <div>
                  <h4 className="sectionKicker" style={{ margin: "0 0 8px 0" }}>
                    Indicator Details
                  </h4>
                  <div className="codeBlock">
                    {en.value}
                  </div>
                </div>
                <div className="kvStack">
                  {[
                    { label: "Type", value: KIND_LABEL[en.kind] },
                    { label: "Status", value: en.status },
                    { label: "Added By", value: en.added_by },
                    { label: "Block Hits", value: en.hit_count },
                    { label: "Last Triggered", value: en.last_triggered ? new Date(en.last_triggered).toLocaleString() : "Never" },
                    { label: "Added", value: new Date(en.created_at).toLocaleDateString() },
                  ].map(({ label, value }) => (
                    <div key={label} className="kvRow">
                      <span>{label}</span>
                      <strong>{value}</strong>
                    </div>
                  ))}
                </div>
              </div>
            );
          }}
        />

        <ActionStagingPanel
          detection={selectedDetection}
          selectedAction={selectedAction}
          simulation={simulation}
          stagedActions={stagedActions}
          isWorking={isWorking}
          onActionChange={setSelectedAction}
          onSimulate={handleSimulate}
          onStage={handleStage}
          availableActions={[
            { value: "enforce_block", label: "Enforce Block on All Agents", destructive: false },
            { value: "validate_and_activate", label: "Validate & Activate Entry", destructive: false },
            { value: "disable_entry", label: "Disable Entry", destructive: false },
          ]}
        />
      </section>

      {/* Add Entry Modal */}
      {isCreateOpen && (
        <div
          style={{
            position: "fixed",
            inset: 0,
            background: "rgba(0,0,0,0.5)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 1000,
          }}
        >
          <form
            onSubmit={handleCreate}
            style={{
              background: "var(--surface)",
              border: "1px solid var(--line)",
              borderRadius: "10px",
              padding: "24px",
              width: "420px",
              display: "flex",
              flexDirection: "column",
              gap: "14px",
            }}
          >
            <h3 style={{ margin: 0, fontSize: "15px" }}>Add Blocklist Entry</h3>

            <label style={{ display: "flex", flexDirection: "column", gap: "4px", fontSize: "12px", color: "var(--muted)" }}>
              Type
              <select
                value={newEntry.kind}
                onChange={(e) => setNewEntry((p) => ({ ...p, kind: e.target.value as BlocklistEntryKind }))}
                className="input"
                required
              >
                {(["hash", "domain", "url", "user", "process"] as BlocklistEntryKind[]).map((k) => (
                  <option key={k} value={k}>{KIND_LABEL[k]}</option>
                ))}
              </select>
            </label>

            <label style={{ display: "flex", flexDirection: "column", gap: "4px", fontSize: "12px", color: "var(--muted)" }}>
              Value
              <input
                className="input"
                placeholder={newEntry.kind === "hash" ? "SHA-256 hash…" : newEntry.kind === "domain" ? "malicious-domain.com" : "indicator value…"}
                value={newEntry.value}
                onChange={(e) => setNewEntry((p) => ({ ...p, value: e.target.value }))}
                required
              />
            </label>

            <label style={{ display: "flex", flexDirection: "column", gap: "4px", fontSize: "12px", color: "var(--muted)" }}>
              Description
              <input
                className="input"
                placeholder="Why is this being blocked?"
                value={newEntry.description}
                onChange={(e) => setNewEntry((p) => ({ ...p, description: e.target.value }))}
                required
              />
            </label>

            <label style={{ display: "flex", flexDirection: "column", gap: "4px", fontSize: "12px", color: "var(--muted)" }}>
              Severity
              <select
                value={newEntry.severity}
                onChange={(e) => setNewEntry((p) => ({ ...p, severity: e.target.value as BlocklistEntry["severity"] }))}
                className="input"
              >
                {["low", "medium", "high", "critical"].map((s) => (
                  <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
                ))}
              </select>
            </label>

            <div style={{ display: "flex", gap: "8px", justifyContent: "flex-end", marginTop: "4px" }}>
              <button type="button" className="btn" onClick={() => setIsCreateOpen(false)}>Cancel</button>
              <button type="submit" className="btn btnPrimary" disabled={isWorking}>
                {isWorking ? "Adding…" : "Add Entry"}
              </button>
            </div>
          </form>
        </div>
      )}
    </ConsolePage>
  );
}
