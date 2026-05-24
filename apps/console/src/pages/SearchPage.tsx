import { useState, useEffect, useCallback } from "react";
import { Search, Bell, Shield, Ban, TriangleAlert, LoaderCircle, Terminal } from "lucide-react";
import { apiGet, type Alert, type MeResponse } from "../api";
import { ErrorBanner, SeverityBadge, PageHeader } from "../components";
import { timeAgo } from "../utils";

type SearchEntity = "alerts" | "incidents" | "endpoints" | "blocklist";
type SearchResult = {
  id: string;
  type: SearchEntity;
  title: string;
  subtitle: string;
  severity: "low" | "medium" | "high" | "critical" | null;
  timestamp: string;
  url: string;
};

const ENTITY_LABELS: Record<SearchEntity, string> = {
  alerts: "Alerts",
  incidents: "Incidents",
  endpoints: "Endpoints",
  blocklist: "Blocklist",
};

interface Endpoint {
  id: string;
  hostname: string;
  os: string;
  status: "healthy" | "attention" | "offline";
  risk_score: number;
  last_seen: string;
  policy_version: string;
  agent_version: string;
}

interface AgentCase {
  id: string;
  title: string;
  summary: string;
  severity: string;
  created_at: string;
}

interface BlocklistEntry {
  id: string;
  kind: string;
  value: string;
  description: string;
  severity: string;
  created_at: string;
}

export function SearchPage({ me }: { me: MeResponse }) {
  const [query, setQuery] = useState("");
  const [isSearching, setIsSearching] = useState(false);
  const [results, setResults] = useState<SearchResult[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [selectedTypes, setSelectedTypes] = useState<Set<SearchEntity>>(
    new Set(["alerts", "incidents", "endpoints", "blocklist"]),
  );
  const [hasSearched, setHasSearched] = useState(false);

  const toggleType = (t: SearchEntity) => {
    setSelectedTypes((prev) => {
      const next = new Set(prev);
      if (next.has(t)) next.delete(t);
      else next.add(t);
      return next;
    });
  };

  const doSearch = useCallback(async () => {
    const q = query.trim().toLowerCase();
    if (!q || selectedTypes.size === 0) return;
    setIsSearching(true);
    setError(null);
    setHasSearched(true);

    const all: SearchResult[] = [];
    const customerId = me.scope.customer_ids[0];

    try {
      if (selectedTypes.has("alerts")) {
        const alerts = await apiGet<Alert[]>("/alerts");
        for (const a of alerts) {
          if (
            a.title.toLowerCase().includes(q) ||
            a.source.toLowerCase().includes(q) ||
            a.recommended_action.toLowerCase().includes(q) ||
            a.entity_types.some((e) => e.toLowerCase().includes(q))
          ) {
            all.push({
              id: a.id,
              type: "alerts",
              title: a.title,
              subtitle: `${a.source} · ${a.recommended_action}`,
              severity: a.severity,
              timestamp: a.created_at,
              url: "alerts",
            });
          }
        }
      }
    } catch { /* ignore */ }

    try {
      if (selectedTypes.has("incidents") && customerId) {
        const incidents = await apiGet<AgentCase[]>(`/customers/${customerId}/incidents`);
        for (const inc of incidents) {
          if (
            inc.title.toLowerCase().includes(q) ||
            (inc.summary && inc.summary.toLowerCase().includes(q))
          ) {
            all.push({
              id: inc.id,
              type: "incidents",
              title: inc.title,
              subtitle: inc.summary || "",
              severity: inc.severity as any,
              timestamp: inc.created_at,
              url: "agenticAi",
            });
          }
        }
      }
    } catch { /* ignore */ }

    try {
      if (selectedTypes.has("endpoints")) {
        const endpoints = await apiGet<Endpoint[]>("/endpoints");
        for (const ep of endpoints) {
          if (
            ep.hostname.toLowerCase().includes(q) ||
            ep.os.toLowerCase().includes(q) ||
            ep.id.toLowerCase().includes(q)
          ) {
            all.push({
              id: ep.id,
              type: "endpoints",
              title: ep.hostname,
              subtitle: `${ep.os} · ${ep.status} · v${ep.agent_version}`,
              severity: ep.status === "attention" ? "medium" : ep.status === "offline" ? "high" : "low",
              timestamp: ep.last_seen,
              url: "healthAttackSurface",
            });
          }
        }
      }
    } catch { /* ignore */ }

    try {
      if (selectedTypes.has("blocklist")) {
        const url = customerId ? `/blocklist?customer_id=${customerId}` : "/blocklist";
        const entries = await apiGet<BlocklistEntry[]>(url);
        for (const e of entries) {
          if (
            e.value.toLowerCase().includes(q) ||
            e.description.toLowerCase().includes(q) ||
            e.kind.toLowerCase().includes(q)
          ) {
            all.push({
              id: e.id,
              type: "blocklist",
              title: e.value,
              subtitle: `${e.kind} · ${e.description}`,
              severity: e.severity as any,
              timestamp: e.created_at,
              url: "blocklist",
            });
          }
        }
      }
    } catch { /* ignore */ }

    all.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
    setResults(all);
    setIsSearching(false);
  }, [query, selectedTypes, me]);

  useEffect(() => {
    if (!query.trim()) {
      setResults([]);
      setHasSearched(false);
    }
  }, [query]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter") void doSearch();
  };

  const navigateTo = (page: string) => {
    window.dispatchEvent(new CustomEvent("aetherix:navigate", { detail: { page } }));
  };

  const allTypes: SearchEntity[] = ["alerts", "incidents", "endpoints", "blocklist"];

  return (
    <div style={{ display: "flex", flexDirection: "column", flex: 1, padding: "24px", boxSizing: "border-box" }}>
      <PageHeader
        eyebrow="Incident Response"
        title="Search"
        subtitle="Search across alerts, incidents, endpoints, and blocklist entries"
      />

      {error && <ErrorBanner message={error} />}

      {/* Search bar */}
      <div style={{ display: "flex", gap: "10px", marginBottom: "16px" }}>
        <div style={{ flex: 1, position: "relative" }}>
          <Search
            size={16}
            style={{
              position: "absolute",
              left: "12px",
              top: "50%",
              transform: "translateY(-50%)",
              color: "var(--muted)",
              pointerEvents: "none",
            }}
          />
          <input
            className="input"
            style={{ paddingLeft: "36px", height: "44px", fontSize: "14px" }}
            placeholder="Search by hostname, IP, indicator, alert title…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={handleKeyDown}
            autoFocus
          />
        </div>
        <button className="btnPrimary" onClick={doSearch} disabled={isSearching || !query.trim()}>
          {isSearching ? <LoaderCircle size={16} className="spin" /> : <Search size={16} />}
          {isSearching ? "Searching…" : "Search"}
        </button>
      </div>

      {/* Entity type filters */}
      <div className="filterBar" style={{ marginBottom: "20px" }}>
        <span className="filterLabel">Search in</span>
        {allTypes.map((t) => (
          <button
            key={t}
            className={`filterChip${selectedTypes.has(t) ? " active" : ""}`}
            onClick={() => toggleType(t)}
          >
            {ENTITY_LABELS[t]}
          </button>
        ))}
      </div>

      {/* Results */}
      {isSearching && (
        <div style={{ padding: "40px", textAlign: "center", color: "var(--muted)" }}>
          <LoaderCircle size={24} className="spin" style={{ marginBottom: "8px" }} />
          <div style={{ fontSize: "13px" }}>Searching…</div>
        </div>
      )}

      {!isSearching && hasSearched && results.length === 0 && (
        <div className="panel" style={{ padding: "40px", textAlign: "center", color: "var(--muted)" }}>
          <Search size={32} style={{ marginBottom: "12px", opacity: 0.4 }} />
          <p style={{ margin: 0, fontSize: "14px" }}>No results found for "{query}"</p>
          <p style={{ margin: "6px 0 0", fontSize: "12px" }}>Try different keywords or broaden your search scope</p>
        </div>
      )}

      {!isSearching && results.length > 0 && (
        <div style={{ marginBottom: "8px", fontSize: "12px", color: "var(--muted)" }}>
          {results.length} result{results.length !== 1 ? "s" : ""} for "{query}"
        </div>
      )}

      {!isSearching && results.length > 0 && (
        <div className="panel" style={{ display: "grid", gap: 0 }}>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "24px 1fr 120px 110px 90px",
              gap: "12px",
              padding: "10px 14px",
              fontSize: "11px",
              textTransform: "uppercase",
              letterSpacing: "0.06em",
              color: "var(--muted)",
              borderBottom: "1px solid var(--line)",
            }}
          >
            <span />
            <span>Result</span>
            <span>Type</span>
            <span>Severity</span>
            <span>Time</span>
          </div>

          {results.map((r) => (
            <button
              key={`${r.type}-${r.id}`}
              onClick={() => navigateTo(r.url)}
              style={{
                display: "grid",
                gridTemplateColumns: "24px 1fr 120px 110px 90px",
                gap: "12px",
                alignItems: "center",
                padding: "12px 14px",
                border: "none",
                borderBottom: "1px solid var(--line)",
                background: "transparent",
                cursor: "pointer",
                textAlign: "left",
                width: "100%",
                minHeight: "52px",
              }}
              onMouseEnter={(e) => { e.currentTarget.style.background = "rgba(15,90,110,0.04)"; }}
              onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
            >
              <span style={{ color: "var(--muted)", display: "flex" }}>
                {r.type === "alerts" && <Bell size={14} />}
                {r.type === "incidents" && <TriangleAlert size={14} />}
                {r.type === "endpoints" && <Terminal size={14} />}
                {r.type === "blocklist" && <Ban size={14} />}
              </span>

              <div>
                <div style={{ fontSize: "13px", fontWeight: 500, lineHeight: 1.3 }}>{r.title}</div>
                <div style={{ fontSize: "11px", color: "var(--muted)", marginTop: "1px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {r.subtitle}
                </div>
              </div>

              <span style={{ fontSize: "12px", color: "var(--muted)" }}>
                {ENTITY_LABELS[r.type]}
              </span>

              <span>
                {r.severity ? (
                  <SeverityBadge severity={r.severity === "critical" ? "high" : r.severity as "low" | "medium" | "high"} />
                ) : (
                  <span style={{ fontSize: "11px", color: "var(--muted)" }}>—</span>
                )}
              </span>

              <span style={{ fontSize: "12px", color: "var(--muted)" }}>
                {timeAgo(r.timestamp)}
              </span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
