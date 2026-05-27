import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { AttestationsList, ComplianceAttestation } from "./AttestationsList";

const { apiGetMock } = vi.hoisted(() => ({
  apiGetMock: vi.fn(),
}));

vi.mock("../../api", async () => {
  const actual = await vi.importActual<object>("../../api");
  return {
    ...actual,
    apiGet: apiGetMock,
  };
});

function mockAttestations(): ComplianceAttestation[] {
  return [
    {
      id: "att-123",
      customer_id: "cust-456",
      framework: "iso27001-2022",
      period_start: "2026-01-01",
      period_end: "2026-03-31",
      attested_by_account_id: "acc-789",
      attested_role: "CISO",
      attested_name: "Jane Doe",
      statement: "I attest that the controls are implemented effectively.",
      bundle_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      signature: "MEYCIQ...",
      signature_algo: "ecdsa-sha256",
      created_at: "2026-04-01T12:00:00Z",
    },
  ];
}

beforeEach(() => {
  apiGetMock.mockReset();
  apiGetMock.mockImplementation(async (path: string) => {
    if (path.startsWith("/compliance/attestations")) {
      return mockAttestations();
    }
    throw new Error(`unexpected apiGet path: ${path}`);
  });
});

describe("AttestationsList", () => {
  it("renders attestations and filters by framework", async () => {
    render(<AttestationsList customerId="cust-456" />);

    expect(await screen.findByText("Jane Doe")).toBeInTheDocument();
    expect(screen.getByText("CISO")).toBeInTheDocument();
    expect(screen.getByText("2026-01-01 to 2026-03-31")).toBeInTheDocument();

    // Verify API call was made
    expect(apiGetMock).toHaveBeenCalledWith(
      "/compliance/attestations?customer_id=cust-456&framework=iso27001-2022"
    );
  });

  it("opens the details modal when clicking View details", async () => {
    const user = userEvent.setup();
    render(<AttestationsList customerId="cust-456" />);

    expect(await screen.findByText("Jane Doe")).toBeInTheDocument();

    const viewDetailsBtn = screen.getByRole("button", { name: /View details/i });
    await user.click(viewDetailsBtn);

    expect(await screen.findByText("Attestation Details")).toBeInTheDocument();
    expect(screen.getByText("I attest that the controls are implemented effectively.")).toBeInTheDocument();
    expect(screen.getByText("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")).toBeInTheDocument();
    expect(screen.getByText("MEYCIQ...")).toBeInTheDocument();
    expect(screen.getByText("Algorithm: ecdsa-sha256")).toBeInTheDocument();

    const closeBtn = screen.getByText("Close", { selector: "button" });
    await user.click(closeBtn);

    await waitFor(() => {
      expect(screen.queryByText("Attestation Details")).not.toBeInTheDocument();
    });
  });

  it("handles changing the framework filter", async () => {
    const user = userEvent.setup();
    render(<AttestationsList customerId="cust-456" />);

    await screen.findByText("Jane Doe");

    const select = screen.getByRole("combobox");
    await user.selectOptions(select, "soc2-2017");

    await waitFor(() => {
      expect(apiGetMock).toHaveBeenCalledWith(
        "/compliance/attestations?customer_id=cust-456&framework=soc2-2017"
      );
    });
  });
});
