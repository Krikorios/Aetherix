import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { PolicyPage } from "./PolicyPage";


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


function policyList() {
  return {
    items: [
      {
        id: "policy-1",
        name: "Default Policy v1.01",
        status: "draft",
        latest_version: 1,
        active_version: null,
        scope: { partner_id: "partner-1", customer_id: null, group_id: null, endpoint_id: null },
        created_at: "2026-05-23T00:00:00Z",
        updated_at: "2026-05-23T00:00:00Z",
      },
    ],
    total: 1,
    limit: 50,
    offset: 0,
  };
}


function policyDetail() {
  return {
    policy: {
      id: "policy-1",
      schema_version: "2.0",
      name: "Default Policy v1.01",
      scope: { partner_id: "partner-1", customer_id: null, group_id: null, endpoint_id: null },
      lineage: { parent_policy_id: null, inheritance_mode: "inherit_with_overrides" },
      modules: {},
      white_label_names: {},
      status: "draft",
      latest_version: 1,
      active_version: null,
      created_at: "2026-05-23T00:00:00Z",
      created_by: "user-1",
      updated_at: "2026-05-23T00:00:00Z",
      updated_by: "user-1",
    },
    latest_version: {
      id: "version-1",
      policy_id: "policy-1",
      version: 1,
      status: "draft",
      payload: {
        schema_version: "2.0",
        name: "Default Policy v1.01",
        scope: { partner_id: "partner-1", customer_id: null, group_id: null, endpoint_id: null },
        lineage: { parent_policy_id: null, inheritance_mode: "inherit_with_overrides" },
        modules: {
          general: { enabled: true },
          tenant_scope: { enabled: true },
          entitlements: { enabled: true },
          deployment_profile: { enabled: true },
          antimalware: { enabled: true, response_action: "review" },
          behavior_monitoring: { enabled: true, high_confidence_action: "review" },
          anti_exploit: { enabled: true, high_confidence_action: "review" },
          ransomware_mitigation: { enabled: true, rollback_approval: "operator_required" },
          firewall: { enabled: true },
          network_protection: { enabled: true, network_attack_signature_action: "review" },
          web_protection: { enabled: true, sensitive_upload_action: "block" },
          classification_labeling: { enabled: false },
          semantic_dlp: {
            enabled: true,
            sensitivity_labels_csv: "Public, Internal, Confidential, Restricted",
            genai_destinations_csv: "copilot, claude, gemini, chatgpt, custom",
            paste_sensitive_action: "review",
            upload_restricted_action: "block",
            copy_to_genai_action: "review",
            presidio_detector: true,
            llm_semantic_detector: true,
            custom_classifiers_csv: "",
          },
          genai_guardrails: {
            enabled: true,
            destinations_csv: "copilot, claude, gemini, chatgpt, custom",
            browser_enforcement: true,
            endpoint_enforcement: true,
            paste_sensitive_action: "review",
            upload_restricted_action: "block",
            copy_to_genai_action: "review",
          },
          device_control: { enabled: true },
          siem_hids: { enabled: false },
          integrity_monitoring: { enabled: false },
          vulnerability_inventory: { enabled: false },
          digital_risk_protection: { enabled: false },
          external_attack_surface_management: { enabled: false },
          threat_intelligence: { enabled: false },
          takedown_workflows: { enabled: false },
          incident_correlation: { enabled: false },
          agentic_response: { enabled: false },
          ai_settings: { enabled: false },
          ai_reports: { enabled: false },
          compliance_evidence: { enabled: true },
          integrations: { enabled: true },
          platform_observability: { enabled: true },
          white_label: { enabled: true },
        },
        white_label_names: {},
      },
      payload_hash: "hash",
      signed_by: "tests",
      signature: "signature",
      created_at: "2026-05-23T00:00:00Z",
      created_by: "user-1",
      promoted_from_simulation_id: null,
    },
    resolved_preview: {
      schema_version: "2.0",
      name: "Default Policy v1.01",
      scope: { partner_id: "partner-1", customer_id: null, group_id: null, endpoint_id: null },
      lineage: { parent_policy_id: null, inheritance_mode: "inherit_with_overrides" },
      modules: {},
      white_label_names: {},
    },
    locked_modules: [],
  };
}


function simulationRecord() {
  return {
    id: "sim-1",
    policy_id: "policy-1",
    policy_version_id: "version-1",
    status: "completed",
    summary: {
      modules_total: 30,
      modules_enabled: 15,
      modules_with_destructive_actions: 2,
      would_block: 2,
      would_isolate: 0,
      would_rollback: 0,
      approval_required: true,
    },
    outcomes: [
      {
        module: "semantic_dlp",
        enabled: true,
        destructive_actions: ["block"],
        would_trigger_gate: true,
        notes: ["semantic_action:upload_restricted:block"],
      },
    ],
    approval_required: true,
    approved: false,
    approved_by: null,
    approval_reason: null,
    evidence_controls: ["iso27001-2022:A.5.12"],
    created_at: "2026-05-23T00:00:00Z",
    created_by: "user-1",
    approved_at: null,
  };
}


beforeEach(() => {
  apiGetMock.mockReset();
  apiPostMock.mockReset();

  apiGetMock.mockImplementation(async (path: string) => {
    if (path === "/policies" || path.startsWith("/policies?")) return policyList();
    if (path === "/companies/summary?limit=250&offset=0") {
      return {
        items: [
          {
            customer: {
              id: "customer-1",
              partner_id: "partner-1",
              customer_number: "C-001",
              company_type: "customer",
              name: "Acme Co",
              industry: null,
              country: null,
              company_size: null,
              status: "active",
              default_group_id: null,
              assigned_policy_package_id: null,
              assigned_policy_name: null,
              created_by: "tests",
              created_at: "2026-05-23T00:00:00Z",
            },
            license: {
              subscription_sku: "core",
              addons: ["semantic_dlp"],
            },
          },
        ],
        total: 1,
        limit: 250,
        offset: 0,
      };
    }
    if (path === "/endpoints") {
      return [
        {
          id: "endpoint-1",
          hostname: "eng-laptop",
          os: "macOS",
          status: "healthy",
          risk_score: 8,
          last_seen: "2026-05-23T00:00:00Z",
          policy_version: "1",
          agent_version: "0.1.0",
        },
      ];
    }
    if (path === "/subscriptions") {
      return [
        {
          id: "sub-1",
          sku: "core",
          core_features: [],
        },
      ];
    }
    if (path === "/policies/policy-1") return policyDetail();
    if (path.startsWith("/policies/effective")) {
      return {
        endpoint_id: null,
        scope: { partner_id: "partner-1", customer_id: "customer-1", group_id: null, endpoint_id: null },
        assignments_applied: [{ id: "assign-1" }],
        resolved_policy: {
          schema_version: "2.0",
          name: "Effective",
          scope: { partner_id: "partner-1", customer_id: "customer-1", group_id: null, endpoint_id: null },
          lineage: { parent_policy_id: null, inheritance_mode: "inherit_with_overrides" },
          modules: {
            semantic_dlp: { enabled: true },
            genai_guardrails: { enabled: true },
          },
          white_label_names: {},
        },
        policy_ids_applied: ["policy-1"],
        evidence_controls: ["iso27001-2022:A.5.12"],
      };
    }
    if (path === "/customers/customer-1/groups") {
      return [{ id: "group-1", customer_id: "customer-1", name: "Engineering", created_at: "2026-05-23T00:00:00Z" }];
    }
    throw new Error(`unexpected apiGet path: ${path}`);
  });

  apiPostMock.mockImplementation(async (path: string) => {
    if (path.endsWith("/simulate")) return simulationRecord();
    if (path === "/policies/assign") return { id: "assign-1" };
    if (path === "/policies") {
      return {
        policy: { id: "policy-2", name: "new", latest_version: 1 },
        version: { version: 1 },
      };
    }
    throw new Error(`unexpected apiPost path: ${path}`);
  });
});


describe("PolicyPage", () => {
  it("renders the policy catalog with API-backed rows and filters", async () => {
    render(<PolicyPage />);

    expect(screen.getByRole("heading", { name: "Policies" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Add/i })).toBeInTheDocument();
    expect(screen.getByLabelText("Filter by policy name")).toBeInTheDocument();
    expect(screen.getByLabelText("Filter by status")).toBeInTheDocument();
    expect(screen.getByLabelText("Filter by company")).toBeInTheDocument();
    expect(await screen.findByRole("button", { name: "Default Policy v1.01" })).toBeInTheDocument();
    expect(screen.getByText("1 item")).toBeInTheDocument();
  });

  it("filters catalog rows by policy name", async () => {
    const user = userEvent.setup();
    render(<PolicyPage />);

    await screen.findByRole("button", { name: "Default Policy v1.01" });
    await user.type(screen.getByLabelText("Filter by policy name"), "missing");

    await waitFor(() => {
      expect(screen.queryByRole("button", { name: "Default Policy v1.01" })).toBeNull();
    });
    expect(screen.getByText("No policies found for the current filters.")).toBeInTheDocument();
  });

  it("opens the policy editor via navigate event when Add is clicked", async () => {
    const user = userEvent.setup();
    const navHandler = vi.fn();
    window.addEventListener("aetherix:navigate", navHandler);

    render(<PolicyPage />);
    await screen.findByRole("button", { name: "Default Policy v1.01" });

    await user.click(screen.getByRole("button", { name: /Add policy/i }));

    expect(navHandler).toHaveBeenCalledTimes(1);
    const evt = navHandler.mock.calls[0][0] as CustomEvent;
    expect(evt.detail).toEqual({ page: "policyEditor", policyId: null });

    window.removeEventListener("aetherix:navigate", navHandler);
  });

  it("toggles selection and enables one-policy actions", async () => {
    const user = userEvent.setup();
    render(<PolicyPage />);

    await screen.findByRole("button", { name: "Default Policy v1.01" });

    const editButton = screen.getByRole("button", { name: "Edit policy" });
    const simulateButton = screen.getByRole("button", { name: /Simulate selected/i });
    const assignButton = screen.getByRole("button", { name: /Assign selected/i });
    expect(editButton).toBeDisabled();
    expect(simulateButton).toBeDisabled();
    expect(assignButton).toBeDisabled();

    await user.click(screen.getByLabelText("Select Default Policy v1.01"));

    expect(editButton).toBeEnabled();
    expect(simulateButton).toBeEnabled();
    expect(assignButton).toBeEnabled();
    expect(screen.getByText("1 selected")).toBeInTheDocument();
  });

  it("clicking a policy name toggles selection without navigating", async () => {
    const user = userEvent.setup();
    const navHandler = vi.fn();
    window.addEventListener("aetherix:navigate", navHandler);

    render(<PolicyPage />);
    const row = await screen.findByRole("button", { name: "Default Policy v1.01" });
    await user.click(row);

    expect(navHandler).not.toHaveBeenCalled();
    expect(screen.getByText("1 selected")).toBeInTheDocument();

    window.removeEventListener("aetherix:navigate", navHandler);
  });

  it("Edit policy dispatches a navigate event with the selected policy id", async () => {
    const user = userEvent.setup();
    const navHandler = vi.fn();
    window.addEventListener("aetherix:navigate", navHandler);

    render(<PolicyPage />);
    await screen.findByRole("button", { name: "Default Policy v1.01" });
    await user.click(screen.getByLabelText("Select Default Policy v1.01"));

    await user.click(screen.getByRole("button", { name: "Edit policy" }));

    expect(navHandler).toHaveBeenCalledTimes(1);
    const evt = navHandler.mock.calls[0][0] as CustomEvent;
    expect(evt.detail).toEqual({ page: "policyEditor", policyId: "policy-1" });

    window.removeEventListener("aetherix:navigate", navHandler);
  });

  it("Refresh re-fetches policies", async () => {
    const user = userEvent.setup();
    render(<PolicyPage />);

    await screen.findByRole("button", { name: "Default Policy v1.01" });
    apiGetMock.mockClear();

    await user.click(screen.getByRole("button", { name: /Refresh/i }));

    await waitFor(() => {
      expect(apiGetMock).toHaveBeenCalledWith("/policies");
    });
  });

  it("runs a policy simulation and surfaces the approval-gate summary", async () => {
    const user = userEvent.setup();
    render(<PolicyPage />);

    await screen.findByRole("button", { name: "Default Policy v1.01" });
    await user.click(screen.getByLabelText("Select Default Policy v1.01"));

    await user.click(screen.getByRole("button", { name: /Simulate selected/i }));

    expect(
      await screen.findByText(/Simulation complete: 2 module\(s\) trigger approval gates/i),
    ).toBeInTheDocument();
    await waitFor(() => {
      expect(apiPostMock).toHaveBeenCalledWith("/policies/policy-1/simulate", {});
    });
  });
});


