import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { CorrelationBanner } from "../components/protection/CorrelationBanner";
import { CorrelationEvidenceGroups } from "../components/protection/CorrelationEvidenceGroups";
import type { CorrelationResponse } from "../api";

function buildResponse(): CorrelationResponse {
  return {
    alert_id: "alert-1",
    severity: "high",
    severity_uplifted_from: "medium",
    correlations: [
      {
        id: "corr-fim-1",
        related_kind: "fim_event",
        related_id: "fim-1",
        correlation_type: "file_path_match",
        score: 0.9,
        window_seconds: 300,
        evidence: { file_path: "/etc/passwd", event_type: "modified" },
        created_at: "2026-05-30T09:00:00Z",
      },
      {
        id: "corr-sha-1",
        related_kind: "fim_event",
        related_id: "fim-2",
        correlation_type: "sha256_match",
        score: 1.0,
        window_seconds: 300,
        evidence: {
          sha256_hash: "abcdef0123456789aaaaaaaa0123456789abcdef0123456789abcdef01234567",
          file_path: "/tmp/malware.bin",
        },
        created_at: "2026-05-30T09:01:00Z",
      },
      {
        id: "corr-proc-1",
        related_kind: "edr_event",
        related_id: "edr-3",
        correlation_type: "process_path_match",
        score: 0.75,
        window_seconds: 300,
        evidence: { process_path: "/usr/bin/python3" },
        created_at: "2026-05-30T09:02:00Z",
      },
      {
        id: "corr-dlp-1",
        related_kind: "dlp_event",
        related_id: "dlp-1",
        correlation_type: "sha256_match",
        score: 0.95,
        window_seconds: 600,
        evidence: {
          sha256_hash: "ffeeddccbbaa00998877665544332211ffeeddccbbaa00998877665544332211",
          source: "presidio",
          risk_band: "high",
          action: "block",
        },
        created_at: "2026-05-30T09:03:00Z",
      },
    ],
  };
}

describe("CorrelationEvidenceGroups", () => {
  it("groups supporting signals by correlation type and shows sha256 + file path evidence", () => {
    render(<CorrelationEvidenceGroups data={buildResponse()} />);

    // Group headers are present
    expect(screen.getByText("File Path Matches")).toBeInTheDocument();
    expect(screen.getByText("SHA-256 Hash Matches")).toBeInTheDocument();
    expect(screen.getByText("Process Path Matches")).toBeInTheDocument();
    expect(screen.getByText("DLP Detection Matches")).toBeInTheDocument();

    // File path evidence appears (shortened to last 2 segments)
    expect(screen.getByText("etc/passwd")).toBeInTheDocument();

    // Short sha appears for both sha256 groups (FIM and DLP)
    expect(screen.getAllByText("abcdef01…01234567").length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText("ffeeddcc…44332211").length).toBeGreaterThanOrEqual(1);

    // Process path evidence appears (shortened to last 2 segments)
    expect(screen.getByText("bin/python3")).toBeInTheDocument();

    // DLP enrichment metadata appears
    expect(screen.getByText(/presidio · high risk · block/i)).toBeInTheDocument();
  });

  it("returns nothing when no correlations are present", () => {
    const { container } = render(
      <CorrelationEvidenceGroups
        data={{ alert_id: "x", severity: "low", severity_uplifted_from: null, correlations: [] }}
      />,
    );
    expect(container).toBeEmptyDOMElement();
  });
});

describe("CorrelationBanner", () => {
  it("renders the severity uplift headline and the grouped evidence sections together", () => {
    render(<CorrelationBanner data={buildResponse()} />);

    // Uplift headline (medium -> high)
    expect(screen.getByText(/Severity uplifted/i)).toBeInTheDocument();
    expect(screen.getByText(/medium/i)).toBeInTheDocument();
    expect(screen.getAllByText(/high/i).length).toBeGreaterThan(0);

    // Grouped evidence headers come from CorrelationEvidenceGroups
    expect(screen.getByText("File Path Matches")).toBeInTheDocument();
    expect(screen.getByText("SHA-256 Hash Matches")).toBeInTheDocument();
    expect(screen.getByText("DLP Detection Matches")).toBeInTheDocument();
  });
});
