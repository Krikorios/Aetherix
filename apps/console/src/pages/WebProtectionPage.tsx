import React, { useState, useEffect } from "react";
import {
  Globe,
  RefreshCw,
  ShieldAlert,
  CheckCircle,
  AlertTriangle,
  Mail,
  Ban,
  Eye,
  TrendingUp,
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

export type WebThreatCategory =
  | "phishing"
  | "malware_hosting"
  | "c2_comms"
  | "spam"
  | "adware"
  | "policy_violation"
  | "email_threat";

export interface WebThreatEvent {
  id: string;
  customer_id?: string | null;
  hostname: string;
  user: string;
  destination: string;
  category: WebThreatCategory;
  threat_name?: string | null;
  severity: "low" | "medium" | "high" | "critical";
  status: "blocked" | "alerted" | "allowed" | "review";
  action_taken: string;
  timestamp: string;
  bytes_transferred?: number | null;
  policy_rule?: string | null;
  channel: "web" | "email";
}

const CATEGORY_LABEL: Record<WebThreatCategory, string> = {
  phishing: "Phishing",
  malware_hosting: "Malware Hosting",
  c2_comms: "C2 Communication",
  spam: "Spam",
  adware: "Adware",
  policy_violation: "Policy Violation",
  email_threat: "Email Threat",
};

const DEMO_EVENTS: WebThreatEvent[] = [
  {
    id: "web-001",
    customer_id: null,
    hostname: "WIN-WORK-042",
    user: "jdoe@northgate.internal",
    destination: "http://malicious-update.ru/payload.exe",
    category: "malware_hosting",
    threat_name: "Trojan.Downloader.Generic",
    severity: "critical",
    status: "blocked",
    action_taken: "Connection blocked, alert raised",
    timestamp: new Date(Date.now() - 3600000).toISOString(),
    bytes_transferred: 0,
    policy_rule: "web:block-malware-categories",
    channel: "web",
  },
  {
    id: "web-002",
    customer_id: null,
    hostname: "WIN-WORK-017",
    user: "ksmith@northgate.internal",
    destination: "office365-login.phish-site.net",
    category: "phishing",
    threat_name: null,
    severity: "high",
    status: "blocked",
    action_taken: "DNS sinkholed — user redirected to block page",
    timestamp: new Date(Date.now() - 7200000).toISOString(),
    bytes_transferred: 0,
    policy_rule: "web:dns-sinkhole-phishing",
    channel: "web",
  },
  {
    id: "web-003",
    customer_id: null,
    hostname: "LINUX-SRV-08",
    user: "svc-monitor@northgate.internal",
    destination: "185.220.101.45:4444",
    category: "c2_comms",
    threat_name: "Cobalt Strike Beacon",
    severity: "critical",
    status: "blocked",
    action_taken: "Outbound connection blocked — incident created",
    timestamp: new Date(Date.now() - 14400000).toISOString(),
    bytes_transferred: 824,
    policy_rule: "web:block-known-c2",
    channel: "web",
  },
  {
    id: "web-004",
    customer_id: null,
    hostname: "WIN-WORK-001",
    user: "mwilson@northgate.internal",
    destination: "Sender: prize@lottery-alert.email",
    category: "spam",
    threat_name: "SpamHaus DBL hit",
    severity: "low",
    status: "alerted",
    action_taken: "Moved to spam folder, user notified",
    timestamp: new Date(Date.now() - 86400000).toISOString(),
    bytes_transferred: null,
    policy_rule: "mail:quarantine-spam",
    channel: "email",
  },
  {
    id: "web-005",
    customer_id: null,
    hostname: "WIN-WORK-042",
    user: "jdoe@northgate.internal",
    destination: "dropbox.com/personal-backup",
    category: "policy_violation",
    threat_name: null,
    severity: "medium",
    status: "alerted",
    action_taken: "Policy alert triggered — personal cloud storage access",
    timestamp: new Date(Date.now() - 86400000 * 2).toISOString(),
    bytes_transferred: 15728640,
    policy_rule: "web:data-exfiltration-monitoring",
    channel: "web",
  },
];

export function WebProtectionPage({ me }: { me: MeResponse }) {
  const [isLoading, setIsLoading] = useState(true);
  const [isSyncing, setIsSyncing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const [policy, setPolicy] = useState<EffectivePolicy>({
    policy_version: "v2.10.4",
    last_updated: new Date(Date.now() - 3600000).toISOString(),
    status: "protected",
    approval_required: false,
    controls: {
      web_filtering: true,
      dns_sinkhole: true,
      email_scanning: true,
      ssl_inspection: false,
    },
  });

  const [events, setEvents] = useState<WebThreatEvent[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [selectedAction, setSelectedAction] = useState<string>("confirm_block");
  const [simulation, setSimulation] = useState<SimulationPreview | null>(null);
  const [stagedActions, setStagedActions] = useState<StagedAction[]>([]);
  const [isWorking, setIsWorking] = useState(false);

  const detections: Detection[] = events.map((ev) => ({
    id: ev.id,
    customer_id: ev.customer_id,
    endpoint_id: ev.hostname,
    endpoint_name: `${ev.hostname} · ${ev.user.split("@")[0]}`,
    title: ev.destination,
    source: `${ev.channel === "email" ? "Email Protection" : "Web Filter"}: ${CATEGORY_LABEL[ev.category]}`,
    description: ev.threat_name ?? ev.action_taken,
    risk_score:
      ev.severity === "critical" ? 95 : ev.severity === "high" ? 75 : ev.severity === "medium" ? 50 : 20,
    risk_band: ev.severity,
    confidence: ev.status === "blocked" ? 95 : 70,
    recommended_action: ev.status === "review" ? "review_traffic" : ev.status === "allowed" ? "block_destination" : "confirm_block",
    status:
      ev.status === "blocked" ? "resolved" : ev.status === "alerted" ? "investigating" : ev.status === "review" ? "new" : "resolved",
    created_at: ev.timestamp,
    context: {
      user: ev.user,
      command_line: [ev.destination, ev.policy_rule].filter(Boolean).join(" | "),
      mitre_techniques: ev.category === "c2_comms"
        ? [{ id: "T1071.001", name: "Application Layer Protocol: Web Protocols", tactic: "Command and Control" }]
        : ev.category === "phishing"
        ? [{ id: "T1566.002", name: "Phishing: Spearphishing Link", tactic: "Initial Access" }]
        : [],
    },
  }));

  const selectedDetection = detections.find((d) => d.id === selectedId) ?? null;
  const selectedEvent = events.find((e) => e.id === selectedId) ?? null;

  useEffect(() => {
    async function load() {
      try {
        const customerId = me.scope.customer_ids[0];
        const url = customerId ? `/web-protection/events?customer_id=${customerId}` : `/web-protection/events`;
        const data = await apiGet<WebThreatEvent[]>(url);
        setEvents(data);
        if (data.length > 0) {
          setSelectedId(data[0].id);
          setSelectedAction(data[0].status === "review" ? "review_traffic" : "confirm_block");
        }
      } catch {
        setEvents(DEMO_EVENTS);
        setSelectedId(DEMO_EVENTS[0].id);
        setSelectedAction("confirm_block");
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
      setSuccess("Web protection policies synced.");
    } catch {
      setError("Sync failed.");
    } finally {
      setIsSyncing(false);
    }
  };

  const handleSimulate = async () => {
    if (!selectedEvent) return;
    setIsWorking(true);
    try {
      await apiPost(`/web-protection/events/${selectedEvent.id}/simulate`, { action: selectedAction });
    } catch {
      const sim: SimulationPreview = {
        id: `sim-web-${selectedEvent.id}-${Date.now()}`,
        detection_id: selectedEvent.id,
        action: selectedAction,
        destructive: false,
        approval_required: policy.approval_required,
        affected_systems: 1,
        estimated_impact: [
          selectedAction === "block_destination"
            ? `Destination "${selectedEvent.destination}" will be added to the tenant blocklist.`
            : selectedAction === "allow_exception"
            ? `An allow-exception will be created for this destination. Review before approving.`
            : `Action "${selectedAction}" will be applied to this event.`,
          `Channel: ${selectedEvent.channel === "email" ? "Email Protection" : "Web Filter"}`,
          `User: ${selectedEvent.user} on ${selectedEvent.hostname}`,
        ],
        evidence_controls: ["iso27001-2022:A.8.23", "nist-csf-2.0:PR.PS"],
        created_at: new Date().toISOString(),
      };
      setSimulation(sim);
      setSuccess("Simulation complete.");
    } finally {
      setIsWorking(false);
    }
  };

  const handleStage = async () => {
    if (!selectedEvent) return;
    setIsWorking(true);
    const optimistic: StagedAction = {
      id: `staged-web-${Date.now()}`,
      detection_id: selectedEvent.id,
      action: selectedAction,
      status: policy.approval_required ? "awaiting_approval" : "queued",
      approval_required: policy.approval_required,
      requested_by: me.account.email,
      created_at: new Date().toISOString(),
      note: `Web protection action: ${selectedAction}`,
    };
    setStagedActions((prev) => [optimistic, ...prev]);
    try {
      await apiPost(`/web-protection/events/${selectedEvent.id}/action`, { action: selectedAction });
    } catch {
      // offline fallback
    }
    setEvents((prev) =>
      prev.map((e) => (e.id === selectedEvent.id ? { ...e, status: selectedAction === "allow_exception" ? "allowed" : "blocked" } : e)),
    );
    setSuccess(`Action staged: ${selectedAction}`);
    setIsWorking(false);
  };

  const blocked = events.filter((e) => e.status === "blocked").length;
  const alerted = events.filter((e) => e.status === "alerted").length;
  const review = events.filter((e) => e.status === "review").length;
  const emailThreats = events.filter((e) => e.channel === "email").length;

  if (isLoading) {
    return (
      <div style={{ padding: "40px", width: "100%" }}>
        <LoadingState message="Loading web protection events…" />
      </div>
    );
  }

  return (
    <ConsolePage>
      <ModuleHeader
        title="Web Protection"
        eyebrow="Content and Communication"
        icon={Globe}
        status={policy.status}
        policyVersion={policy.policy_version}
        policyLastSynced={policy.last_updated}
        onRefresh={handleSyncPolicy}
        isRefreshing={isSyncing}
        quickActions={[]}
      />

      {error && <ErrorBanner message={error} />}
      {success && <SuccessBanner message={success} />}

      <MetricGrid
        ariaLabel="Web Protection Metrics"
        items={[
          { label: "Blocked", value: blocked, icon: <Ban size={18} />, color: "var(--danger)" },
          { label: "Alerted", value: alerted, icon: <AlertTriangle size={18} />, color: "var(--warning)" },
          { label: "Pending Review", value: review, icon: <Eye size={18} />, color: "var(--accent)" },
          { label: "Email Threats", value: emailThreats, icon: <Mail size={18} />, color: "var(--muted)" },
          { label: "Total Events", value: events.length, icon: <TrendingUp size={18} />, color: "var(--muted)" },
        ]}
      />

      <section className="panelWorkspace" aria-label="Web Protection Board">
        <DetectionTable
          detections={detections}
          selectedId={selectedId}
          onSelect={(d) => {
            setSelectedId(d.id);
            const ev = events.find((e) => e.id === d.id);
            setSelectedAction(ev?.status === "review" ? "review_traffic" : "confirm_block");
            setSimulation(null);
          }}
          isLoading={isLoading}
        />

        <DetailPanel
          detection={selectedDetection}
          customContextRenderer={(d) => {
            const ev = events.find((e) => e.id === d.id);
            if (!ev) return null;
            return (
              <div className="detailStack">
                <div>
                  <h4 className="sectionKicker" style={{ margin: "0 0 8px 0" }}>
                    Event Details
                  </h4>
                  <div className="kvStack">
                    {[
                      { label: "Category", value: CATEGORY_LABEL[ev.category] },
                      { label: "Channel", value: ev.channel === "email" ? "Email" : "Web" },
                      { label: "User", value: ev.user },
                      { label: "Hostname", value: ev.hostname },
                      { label: "Action Taken", value: ev.action_taken },
                      ...(ev.policy_rule ? [{ label: "Policy Rule", value: ev.policy_rule }] : []),
                      ...(ev.bytes_transferred != null
                        ? [{ label: "Bytes Transferred", value: ev.bytes_transferred === 0 ? "Blocked (0 bytes)" : `${(ev.bytes_transferred / 1024).toFixed(1)} KB` }]
                        : []),
                      { label: "Timestamp", value: new Date(ev.timestamp).toLocaleString() },
                    ].map(({ label, value }) => (
                      <div key={label} className="kvRow">
                        <span>{label}</span>
                        <strong>{value}</strong>
                      </div>
                    ))}
                  </div>
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
            { value: "confirm_block", label: "Confirm Block", destructive: false },
            { value: "review_traffic", label: "Flag for Review", destructive: false },
            { value: "block_destination", label: "Add to Blocklist", destructive: false },
            { value: "allow_exception", label: "Create Allow Exception", destructive: false },
          ]}
        />
      </section>
    </ConsolePage>
  );
}
