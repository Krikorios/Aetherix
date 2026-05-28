import { render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import vssFixture from "../test/fixtures/vss-smoke.json";
import { EndpointHealthPage } from "./EndpointHealthPage";

const { apiGetMock, apiPostMock } = vi.hoisted(() => ({
  apiGetMock: vi.fn(),
  apiPostMock: vi.fn(),
}));

vi.mock("../api", async () => {
  const actual = await vi.importActual<object>("../api");
  return {
    ...actual,
    apiGet: apiGetMock,
    apiPost: apiPostMock,
  };
});

const me = {
  account: { id: "account-1", email: "owner@vss.test", full_name: "VSS Owner", roles: [{ role_code: "msp_partner" }] },
  permissions: { policies: "manage", companies: "manage", incidents: "view", accounts: "manage", licensing: "view" },
  scope: { is_platform: false, partner_ids: ["partner-1"], customer_ids: ["customer-1"] },
  branding: { product_name: "Aetherix", tagline: "MSP Console", primary_color: "#0b6b57", accent_color: "#0b6b57", source: "platform" },
};

beforeEach(() => {
  apiGetMock.mockReset();
  apiPostMock.mockReset();
  apiGetMock.mockImplementation(async (path: string) => {
    if (path.startsWith("/endpoints/health")) {
      return [vssFixture.endpoint_health];
    }
    return [];
  });
});

describe("EndpointHealthPage VSS smoke", () => {
  it("renders the shared VSS readiness fixture", async () => {
    render(<EndpointHealthPage me={me as never} />);

    expect(await screen.findByText("Ransomware Rollback Readiness")).toBeInTheDocument();
    expect(screen.getByText(/vss-guard-smoke/i)).toBeInTheDocument();
    expect(screen.getByText("VSS v1.6, Writers: 2/2 ready")).toBeInTheDocument();
    expect(screen.getByText(/C:\\Users\\Alice\\Documents\\report.docx/)).toBeInTheDocument();

    await waitFor(() => {
      expect(apiGetMock).toHaveBeenCalledWith("/endpoints/health?customer_id=customer-1");
    });
  });
});