import React, { useState, useMemo } from "react";
import { ArrowUpDown, Search, Filter } from "lucide-react";
import { Detection, RiskRank } from "./types";
import { RiskBadge } from "../../components";

interface DetectionTableProps {
  detections: Detection[];
  selectedId: string | null;
  onSelect: (detection: Detection) => void;
  isLoading?: boolean;
}

type SortField = "created_at" | "risk_score" | "confidence" | "title" | "endpoint_name";
type SortOrder = "asc" | "desc";

export function DetectionTable({
  detections,
  selectedId,
  onSelect,
  isLoading = false,
}: DetectionTableProps) {
  const [searchTerm, setSearchTerm] = useState("");
  const [riskFilter, setRiskFilter] = useState<string>("all");
  const [sortField, setSortField] = useState<SortField>("created_at");
  const [sortOrder, setSortOrder] = useState<SortOrder>("desc");

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortOrder(sortOrder === "asc" ? "desc" : "asc");
    } else {
      setSortField(field);
      setSortOrder("desc");
    }
  };

  const filteredDetections = useMemo(() => {
    return detections
      .filter((d) => {
        const matchesSearch =
          d.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
          d.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
          (d.endpoint_name && d.endpoint_name.toLowerCase().includes(searchTerm.toLowerCase()));
        
        const matchesRisk = riskFilter === "all" || d.risk_band === riskFilter;
        return matchesSearch && matchesRisk;
      })
      .sort((a, b) => {
        let valA = a[sortField];
        let valB = b[sortField];

        if (typeof valA === "string") valA = valA.toLowerCase();
        if (typeof valB === "string") valB = valB.toLowerCase();

        if (valA! < valB!) return sortOrder === "asc" ? -1 : 1;
        if (valA! > valB!) return sortOrder === "asc" ? 1 : -1;
        return 0;
      });
  }, [detections, searchTerm, riskFilter, sortField, sortOrder]);

  return (
    <article className="panel" style={{ flex: 1.5, display: "flex", flexDirection: "column", minWidth: "400px" }}>
      <div className="panelHeader" style={{ paddingBottom: "12px", borderBottom: "1px solid var(--line)" }}>
        <div>
          <h2 style={{ fontSize: "16px", margin: 0 }}>Detections & Rules Security Alerts</h2>
          <span style={{ fontSize: "12px", color: "var(--muted)" }}>Filtered list of active violations</span>
        </div>
      </div>

      {/* Toolbar */}
      <div
        style={{
          display: "flex",
          gap: "10px",
          padding: "12px",
          background: "rgba(11, 107, 87, 0.02)",
          borderBottom: "1px solid var(--line)",
        }}
      >
        <div style={{ position: "relative", flex: 1 }}>
          <Search
            size={14}
            style={{ position: "absolute", left: "10px", top: "50%", transform: "translateY(-50%)", color: "var(--muted)" }}
          />
          <input
            type="text"
            placeholder="Search endpoint, threat..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            style={{
              width: "100%",
              padding: "6px 10px 6px 30px",
              borderRadius: "6px",
              border: "1px solid var(--line)",
              fontSize: "13px",
              background: "#fffef9",
            }}
          />
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
          <Filter size={14} style={{ color: "var(--muted)" }} />
          <select
            value={riskFilter}
            onChange={(e) => setRiskFilter(e.target.value)}
            style={{
              padding: "5px 10px",
              borderRadius: "6px",
              border: "1px solid var(--line)",
              fontSize: "13px",
              background: "#fffef9",
            }}
          >
            <option value="all">All Risks</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
      </div>

      {/* Table grid wrapper */}
      <div style={{ overflowX: "auto", flex: 1 }}>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "13px", textAlign: "left" }}>
          <thead>
            <tr style={{ borderBottom: "1px solid var(--line)", background: "rgba(11, 107, 87, 0.04)" }}>
              <th
                onClick={() => handleSort("title")}
                style={{ cursor: "pointer", padding: "10px 12px", fontWeight: 600, color: "var(--muted)" }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: "4px" }}>
                  Alert / Rule Title <ArrowUpDown size={12} />
                </div>
              </th>
              <th
                onClick={() => handleSort("endpoint_name")}
                style={{ cursor: "pointer", padding: "10px 12px", fontWeight: 600, color: "var(--muted)" }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: "4px" }}>
                  Target <ArrowUpDown size={12} />
                </div>
              </th>
              <th
                onClick={() => handleSort("risk_score")}
                style={{ cursor: "pointer", padding: "10px 12px", fontWeight: 600, color: "var(--muted)", textAlign: "center" }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: "4px", justifyContent: "center" }}>
                  Risk <ArrowUpDown size={12} />
                </div>
              </th>
              <th
                onClick={() => handleSort("confidence")}
                style={{ cursor: "pointer", padding: "10px 12px", fontWeight: 600, color: "var(--muted)", textAlign: "center" }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: "4px", justifyContent: "center" }}>
                  Conf <ArrowUpDown size={12} />
                </div>
              </th>
              <th style={{ padding: "10px 12px", fontWeight: 600, color: "var(--muted)", textAlign: "right" }}>Status</th>
            </tr>
          </thead>
          <tbody>
            {isLoading ? (
              <tr>
                <td colSpan={5} style={{ padding: "32px", textAlign: "center", color: "var(--muted)" }}>
                  Retrieving detections...
                </td>
              </tr>
            ) : filteredDetections.length === 0 ? (
              <tr>
                <td colSpan={5} style={{ padding: "32px", textAlign: "center", color: "var(--muted)" }}>
                  No active detections found matching criteria.
                </td>
              </tr>
            ) : (
              filteredDetections.map((d) => {
                const isSelected = selectedId === d.id;
                return (
                  <tr
                    key={d.id}
                    onClick={() => onSelect(d)}
                    style={{
                      borderBottom: "1px solid var(--line)",
                      cursor: "pointer",
                      background: isSelected ? "rgba(11, 107, 87, 0.08)" : "transparent",
                    }}
                    onMouseEnter={(e) => {
                      if (!isSelected) e.currentTarget.style.background = "rgba(11, 107, 87, 0.02)";
                    }}
                    onMouseLeave={(e) => {
                      if (!isSelected) e.currentTarget.style.background = "transparent";
                    }}
                  >
                    <td style={{ padding: "12px" }}>
                      <div style={{ fontWeight: 600, color: "var(--ink)" }}>{d.title}</div>
                      <div style={{ fontSize: "11px", color: "var(--muted)", marginTop: "2px" }}>{d.source}</div>
                    </td>
                    <td style={{ padding: "12px", color: "var(--muted)" }}>
                      {d.endpoint_name || "Unknown"}
                    </td>
                    <td style={{ padding: "12px", textAlign: "center" }}>
                      <RiskBadge band={d.risk_band} />
                    </td>
                    <td style={{ padding: "12px", textAlign: "center", color: "var(--ink)", fontWeight: 500 }}>
                      {d.confidence}%
                    </td>
                    <td style={{ padding: "12px", textAlign: "right" }}>
                      <span
                        style={{
                          fontSize: "11px",
                          fontWeight: 600,
                          padding: "2px 8px",
                          borderRadius: "4px",
                          background:
                            d.status === "new"
                              ? "rgba(180, 80, 24, 0.1)"
                              : d.status === "staged"
                              ? "rgba(11, 107, 87, 0.1)"
                              : "rgba(96, 112, 104, 0.1)",
                          color:
                            d.status === "new"
                              ? "var(--warning)"
                              : d.status === "staged"
                              ? "var(--accent)"
                              : "var(--muted)",
                        }}
                      >
                        {d.status.toUpperCase()}
                      </span>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </article>
  );
}
