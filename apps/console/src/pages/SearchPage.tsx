import { useState, useEffect, useCallback } from "react";
import { Search, Bell, Ban, TriangleAlert, LoaderCircle, Terminal, Radio, Clock } from "lucide-react";
import { apiGet, type Alert, type MeResponse } from "../api";
import { ConsolePage, ErrorBanner, SeverityBadge, PageHeader } from "../components";
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

type LiveEventHit = {
  id: string | null;
  data_stream: string | null;
  timestamp: string | null;
  event_type: string | null;
  severity: string | null;
  payload: Record<string, unknown> | null;
  postgres_ref: string | null;
};

type EventsSearchResponse = {
  total: number | { value: number };
  returned: number;
  events: LiveEventHit[];
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
  const [activeTab, setActiveTab] = useState<"entity" | "events">("entity");

  // Entity search state
  const [query, setQuery] = useState("");
  const [isSearching, setIsSearching] = useState(false);
  const [results, setResults] = useState<SearchResult[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [selectedTypes, setSelectedTypes] = useState<Set<SearchEntity>>(
    new Set(["alerts", "incidents", "endpoints", "blocklist"]),
  );
  const [hasSearched, setHasSearched] = useState(false);

  // Events (Live Search) state
  const now = new Date();
  const defaultTo = now.toISOString().slice(0, 16);
  const defaultFrom = new Date(now.getTime() - 24 * 60 * 60 * 1000).toISOString().slice(0, 16);
  const [eventsQuery, setEventsQuery] = useState("");
  const [eventsFrom, setEventsFrom] = useState(defaultFrom);
  const [eventsTo, setEventsTo] = useState(defaultTo);
  const [eventsSize, setEventsSize] = useState(50);
  const [eventsCustomerId, setEventsCustomerId] = useState(me.scope.customer_ids[0] ?? "");
  const [eventsResults, setEventsResults] = useState<LiveEventHit[]>([]);
  const [eventsTotal, setEventsTotal] = useState<number>(0);
  const [isSearchingEvents, setIsSearchingEvents] = useState(false);
  const [eventsError, setEventsError] = useState<string | null>(null);
  const [hasSearchedEvents, setHasSearchedEvents] = useState(false);

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

  const doEventsSearch = useCallback(async () => {
    if (!eventsCustomerId) return;
    setIsSearchingEvents(true);
    setEventsError(null);
    setHasSearchedEvents(true);
    try {
      const params = new URLSearchParams({ size: String(eventsSize) });
      if (eventsQuery.trim()) params.set("q", eventsQuery.trim());
      if (eventsFrom) params.set("from_ts", new Date(eventsFrom).toISOString());
      if (eventsTo) params.set("to_ts", new Date(eventsTo).toISOString());
      const res = await apiGet<EventsSearchResponse>(
        `/customers/${eventsCustomerId}/events/search?${params.toString()}`,
      );
      setEventsResults(res.events ?? []);
      const tot = res.total;
      setEventsTotal(typeof tot === "number" ? tot : (tot as { value: number }).value ?? 0);
    } catch (err) {
      setEventsError(err instanceof Error ? err.message : "Events search failed");
    } finally {
      setIsSearchingEvents(false);
    }
  }, [eventsCustomerId, eventsQuery, eventsFrom, eventsTo, eventsSize]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter") void doSearch();
  };

  const handleEventsKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter") void doEventsSearch();
  };

  const navigateTo = (page: string) => {
    window.dispatchEvent(new CustomEvent("aetherix:navigate", { detail: { page } }));
  };

  const allTypes: SearchEntity[] = ["alerts", "incidents", "endpoints", "blocklist"];

  return (
    <ConsolePage>
      <PageHeader
        eyebrow="Incident Response"
        title="Search"
        subtitle="Search across alerts, incidents, endpoints, and blocklist entries — or search OpenSearch-backed events"
      />

      {/* Tab switcher */}
      <div className="filterBar" style={{ marginBottom: "16px" }}>
        <button
          className={`filterChip${activeTab === "entity" ? " active" : ""}`}
          onClick={() => setActiveTab("entity")}
        >
          <Search size={13} />
          Entity Search
        </button>
        <button
          className={`filterChip${activeTab === "events" ? " active" : ""}`}
          onClick={() => setActiveTab("events")}
        >
          <Radio size={13} />
          Events (Live)
        </button>
      </div>

      {activeTab === "entity" && (
        <>
          {error && <ErrorBanner message={error} />}

          <div className="searchBar">
            <div className="searchInputWrap">
              <Search size={16} className="searchInputIcon" />
              <input
                className="searchInput"
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

      <div className="filterBar">
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

      {isSearching && (
        <div className="searchLoading">
          <LoaderCircle size={24} className="spin" />
          <div className="searchLoadingText">Searching…</div>
        </div>
      )}

      {!isSearching && hasSearched && results.length === 0 && (
        <div className="panel searchEmptyPanel">
          <Search size={32} className="searchEmptyIcon" />
          <p className="searchEmptyText">No results found for "{query}"</p>
          <p className="searchEmptyHint">Try different keywords or broaden your search scope</p>
        </div>
      )}

      {!isSearching && results.length > 0 && (
        <div className="searchResultCount">
          {results.length} result{results.length !== 1 ? "s" : ""} for "{query}"
        </div>
      )}

      {!isSearching && results.length > 0 && (
        <div className="panel searchResultGrid">
          <div className="searchResultHead">
            <span />
            <span>Result</span>
            <span>Type</span>
            <span>Severity</span>
            <span>Time</span>
          </div>

          {results.map((r) => (
            <button
              key={`${r.type}-${r.id}`}
              className="searchResultRow"
              onClick={() => navigateTo(r.url)}
            >
              <span className="searchResultIcon">
                {r.type === "alerts" && <Bell size={14} />}
                {r.type === "incidents" && <TriangleAlert size={14} />}
                {r.type === "endpoints" && <Terminal size={14} />}
                {r.type === "blocklist" && <Ban size={14} />}
              </span>

              <div>
                <div className="searchResultTitle">{r.title}</div>
                <div className="searchResultSub">{r.subtitle}</div>
              </div>

              <span className="searchResultMeta">
                {ENTITY_LABELS[r.type]}
              </span>

              <span>
                {r.severity ? (
                  <SeverityBadge severity={r.severity === "critical" ? "high" : r.severity as "low" | "medium" | "high"} />
                ) : (
                  <span className="searchResultDash">&mdash;</span>
                )}
              </span>

              <span className="searchResultMeta">
                {timeAgo(r.timestamp)}
              </span>
            </button>
          ))}
        </div>
      )}
        </>
      )}

      {activeTab === "events" && (
        <>
          {eventsError && <ErrorBanner message={eventsError} />}

          {/* Controls row */}
          <div className="liveSearchControls">
            {me.scope.customer_ids.length > 1 && (
              <div className="liveSearchField">
                <label className="liveSearchLabel">Customer</label>
                <select
                  className="liveSearchSelect"
                  value={eventsCustomerId}
                  onChange={(e) => setEventsCustomerId(e.target.value)}
                >
                  {me.scope.customer_ids.map((cid) => (
                    <option key={cid} value={cid}>{cid}</option>
                  ))}
                </select>
              </div>
            )}
            <div className="liveSearchField">
              <label className="liveSearchLabel">
                <Clock size={11} style={{ verticalAlign: "middle" }} /> From
              </label>
              <input
                type="datetime-local"
                className="liveSearchInput"
                value={eventsFrom}
                onChange={(e) => setEventsFrom(e.target.value)}
              />
            </div>
            <div className="liveSearchField">
              <label className="liveSearchLabel">
                <Clock size={11} style={{ verticalAlign: "middle" }} /> To
              </label>
              <input
                type="datetime-local"
                className="liveSearchInput"
                value={eventsTo}
                onChange={(e) => setEventsTo(e.target.value)}
              />
            </div>
            <div className="liveSearchField liveSearchQueryField">
              <label className="liveSearchLabel">Query</label>
              <input
                type="text"
                className="liveSearchInput"
                placeholder='e.g. "ransomware" or process path…'
                value={eventsQuery}
                onChange={(e) => setEventsQuery(e.target.value)}
                onKeyDown={handleEventsKeyDown}
              />
            </div>
            <div className="liveSearchField">
              <label className="liveSearchLabel">Limit</label>
              <select
                className="liveSearchSelect"
                value={eventsSize}
                onChange={(e) => setEventsSize(Number(e.target.value))}
              >
                {[25, 50, 100, 200].map((n) => (
                  <option key={n} value={n}>{n}</option>
                ))}
              </select>
            </div>
            <button
              className="btnPrimary liveSearchBtn"
              onClick={() => void doEventsSearch()}
              disabled={isSearchingEvents || !eventsCustomerId}
            >
              {isSearchingEvents ? <LoaderCircle size={15} className="spin" /> : <Radio size={15} />}
              {isSearchingEvents ? "Searching…" : "Search Events"}
            </button>
          </div>

          {isSearchingEvents && (
            <div className="searchLoading">
              <LoaderCircle size={24} className="spin" />
              <div className="searchLoadingText">Querying OpenSearch…</div>
            </div>
          )}

          {!isSearchingEvents && hasSearchedEvents && eventsResults.length === 0 && (
            <div className="panel searchEmptyPanel">
              <Radio size={32} className="searchEmptyIcon" />
              <p className="searchEmptyText">No events found for this query and time range</p>
              <p className="searchEmptyHint">Widen the time range or clear the query to see all events</p>
            </div>
          )}

          {!isSearchingEvents && eventsResults.length > 0 && (
            <>
              <div className="searchResultCount">
                {eventsResults.length} of {eventsTotal} event{eventsTotal !== 1 ? "s" : ""} returned
                {" · "}
                <span style={{ color: "var(--muted)", fontSize: "12px" }}>OpenSearch data stream</span>
              </div>
              <div className="panel" style={{ overflow: "auto" }}>
                <table className="dataTable liveEventsTable">
                  <thead>
                    <tr>
                      <th>Timestamp</th>
                      <th>Event Type</th>
                      <th>Severity</th>
                      <th>Payload Preview</th>
                      <th>postgres_ref</th>
                    </tr>
                  </thead>
                  <tbody>
                    {eventsResults.map((ev, idx) => (
                      <tr key={ev.id ?? idx}>
                        <td>
                          <time dateTime={ev.timestamp ?? ""} style={{ fontSize: "12px", fontVariantNumeric: "tabular-nums", whiteSpace: "nowrap" }}>
                            {ev.timestamp ? new Date(ev.timestamp).toLocaleString() : "—"}
                          </time>
                        </td>
                        <td>
                          <span style={{ fontSize: "12px", fontWeight: 600 }}>{ev.event_type ?? "—"}</span>
                        </td>
                        <td>
                          {ev.severity ? (
                            <SeverityBadge severity={ev.severity === "critical" ? "high" : ev.severity as "low" | "medium" | "high"} />
                          ) : (
                            <span style={{ color: "var(--muted)" }}>—</span>
                          )}
                        </td>
                        <td>
                          <span style={{ fontSize: "11px", color: "var(--muted)", fontFamily: "monospace" }}>
                            {ev.payload
                              ? JSON.stringify(ev.payload).slice(0, 80) + (JSON.stringify(ev.payload).length > 80 ? "…" : "")
                              : "—"}
                          </span>
                        </td>
                        <td>
                          {ev.postgres_ref ? (
                            <code className="liveEventsRef">{ev.postgres_ref}</code>
                          ) : (
                            <span style={{ color: "var(--muted)" }}>—</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </>
      )}
    </ConsolePage>
  );
}
