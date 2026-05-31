import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import {
  RollbackRefusalEvidence,
  hasRollbackRefusalEvidence,
} from "../components/protection/RollbackRefusalEvidence";

describe("RollbackRefusalEvidence", () => {
  it("returns null for results without rollback signal", () => {
    const { container } = render(
      <RollbackRefusalEvidence result={{ status: "completed", restored_files_count: 3 }} />,
    );
    // No rollback-specific fields present → nothing rendered.
    expect(container.firstChild).toBeNull();
    expect(hasRollbackRefusalEvidence({ foo: "bar" })).toBe(false);
  });

  it("renders a provider refusal with unverified recovery point", () => {
    const result = {
      status: "not_applicable",
      provider: "vss",
      provider_refusal: "no matching verified recovery point found",
      refusal_reason_code: "no_verified_recovery_point",
      recovery_point_id: "vss-snap-20260530-01",
      recovery_point_verified: false,
      skipped_paths: [
        {
          path: "C:\\Work\\invoice_spreadsheet.xlsx",
          outcome: "refused_out_of_scope",
          reason: "no matching verified recovery point found",
          refusal_reason_code: "no_verified_recovery_point",
          bytes_affected: 0,
        },
      ],
    };

    expect(hasRollbackRefusalEvidence(result)).toBe(true);
    render(<RollbackRefusalEvidence result={result} />);

    expect(screen.getByText("Rollback refused")).toBeInTheDocument();
    expect(screen.getByText(/unverified \/ out of scope/i)).toBeInTheDocument();
    expect(screen.getByText("Refused Paths (1)")).toBeInTheDocument();
    expect(
      screen.getAllByText(/no matching verified recovery point found/i).length,
    ).toBeGreaterThan(0);
  });

  it("reads nested rollback_evidence and renders a successful restore", () => {
    const result = {
      rollback_evidence: {
        status: "completed",
        provider: "vss",
        recovery_point_verified: true,
        restored_paths: [
          { path: "C:\\Work\\a.docx", outcome: "restored", reason: "" },
          { path: "C:\\Work\\b.docx", outcome: "restored", reason: "" },
        ],
      },
    };

    render(<RollbackRefusalEvidence result={result} />);
    expect(screen.getByText("Rollback applied")).toBeInTheDocument();
    expect(screen.getByText(/2 files restored/i)).toBeInTheDocument();
    expect(screen.getByText("verified")).toBeInTheDocument();
  });
});
