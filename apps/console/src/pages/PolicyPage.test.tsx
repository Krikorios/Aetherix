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
    if (path === "/policies/policy-1/simulate") return simulationRecord();
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

    expect(await screen.findByRole("heading", { name: "Policies" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Add/i })).toBeInTheDocument();
    expect(screen.getByLabelText("Filter by policy name")).toBeInTheDocument();
    expect(screen.getByLabelText("Filter by owner")).toBeInTheDocument();
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

  it("opens the policy details screen from Add", async () => {
    const user = userEvent.setup();
    render(<PolicyPage />);

    await screen.findByRole("button", { name: "Default Policy v1.01" });
    await user.click(screen.getByRole("button", { name: /Add/i }));

    expect(screen.getByRole("heading", { name: "Policy details" })).toBeInTheDocument();
    expect(screen.getByDisplayValue("Default policy (2)")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /Cancel/i }));
    expect(screen.getByRole("heading", { name: "Policies" })).toBeInTheDocument();
  });

  it("opens inheritance rules, agent sections, and policy engine modules from the policy shell", async () => {
    const user = userEvent.setup();
    render(<PolicyPage />);

    await user.click(await screen.findByRole("button", { name: "Default Policy v1.01" }));
    await user.click(screen.getByRole("button", { name: "Inheritance rules" }));

    expect(screen.getByRole("heading", { name: "Inheritance rules" })).toBeInTheDocument();
    expect(screen.getByLabelText("Inheritance module")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Agent 2/3" }));
    expect(screen.getByRole("heading", { name: "Notifications" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Agent Settings" })).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Agent Communication" }));
    expect(screen.getByRole("heading", { name: "Communication" })).toBeInTheDocument();
    expect(screen.getByLabelText("Communication name")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Aetherix modules" }));
    expect(screen.getByRole("heading", { name: "Policy engine modules" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Simulate selected/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Semantic DLP/i })).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /Antimalware 4\/6/i }));
    expect(screen.getByRole("heading", { name: "On-Access Scanning" })).toBeInTheDocument();
    expect(screen.getByRole("radio", { name: /Normal/i })).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Antimalware On-Execute" }));
    expect(screen.getByRole("heading", { name: "On-Execute Scanning" })).toBeInTheDocument();
    expect(screen.getByText("Aetherix uses tenant policy, local behavior signals, and optional AI analysis to identify advanced threats with lower local overhead.")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Antimalware Hyper Detect" }));
    expect(screen.getByRole("heading", { name: "Hyper Detect" })).toBeInTheDocument();
    expect(screen.getByText("Targeted attack")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Antimalware Advanced Anti-Exploit" }));
    expect(screen.getByRole("heading", { name: "Advanced Anti-Exploit" })).toBeInTheDocument();
    expect(screen.getByText("Predefined protected applications")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Antimalware Security Servers" }));
    expect(screen.getByRole("heading", { name: "Security Servers" })).toBeInTheDocument();
    expect(screen.getByLabelText("Scan node")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Antimalware Exclusions" }));
    expect(screen.getByRole("heading", { name: "Exclusions" })).toBeInTheDocument();
    expect(screen.getByLabelText("Recommended exclusion")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Sandbox Endpoint Sensor" }));
    expect(screen.getByRole("heading", { name: "Sandbox Analyzer" })).toBeInTheDocument();
    expect(screen.getByText(/Aetherix Detonation Cloud/i)).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "Default action:" })).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Firewall General" }));
    expect(screen.getByRole("heading", { name: "Firewall" })).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "Log verbosity level:" })).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Firewall Settings" }));
    expect(screen.getByRole("heading", { name: "Settings" })).toBeInTheDocument();
    expect(screen.getByLabelText("Firewall network name")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Firewall Rules" }));
    expect(screen.getByRole("heading", { level: 1, name: "Rules" })).toBeInTheDocument();
    expect(screen.getByText("Incoming ICMP")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Network Protection General" }));
    expect(screen.getByRole("heading", { name: "Network Protection" })).toBeInTheDocument();
    expect(screen.getByText("Intercept encrypted traffic")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Network Protection Content Control" }));
    expect(screen.getByRole("heading", { name: "Web Access Control" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Open Aetherix DLP modules" })).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Network Protection Web Protection" }));
    expect(screen.getByRole("heading", { name: "Antiphishing" })).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "Default action for suspicious webpages:" })).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Network Protection Network Attacks" }));
    expect(screen.getByRole("heading", { name: "Network Attack Defense" })).toBeInTheDocument();
    expect(screen.getByText("Credential Access")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Network Protection Custom Pages" }));
    expect(screen.getByRole("heading", { name: "Custom Pages" })).toBeInTheDocument();
    expect(screen.getByLabelText("Assign custom page")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /Patch Management Off/i }));
    expect(screen.getByRole("heading", { name: "Patch Management" })).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "Maintenance window:" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Open Aetherix patch module" })).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Relay" }));
    expect(screen.getByRole("heading", { name: "Relay" })).toBeInTheDocument();
    expect(screen.getByLabelText("Allowed relay upload domain")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Relay Update" }));
    expect(screen.getByText("https://relay-updates.aetherix.local:443")).toBeInTheDocument();
  });

  it("opens add-policy lower subsection pages from the policy shell", async () => {
    const user = userEvent.setup();
    render(<PolicyPage />);

    await user.click(await screen.findByRole("button", { name: "Default Policy v1.01" }));

    await user.click(screen.getByRole("button", { name: /Device Control/i }));
    expect(screen.getByRole("heading", { name: "Device Control" })).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "Default access:" })).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /Exchange Protection/i }));
    expect(screen.getByRole("heading", { name: "User groups" })).toBeInTheDocument();
    expect(screen.getByText("Domain IP Check (Antispoofing)")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /^Risk Management (On|Off)$/i }));
    expect(screen.getByRole("heading", { name: "Risk Management" })).toBeInTheDocument();
    expect(screen.getByText("Scheduler")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Risk Management PHASR" }));
    expect(screen.getByRole("heading", { name: "PHASR" })).toBeInTheDocument();
    expect(screen.getByText(/living off the land/i)).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /Blocklist/i }));
    expect(screen.getByRole("heading", { name: "Blocklist" })).toBeInTheDocument();
    expect(screen.getByText("Application hash")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /Live Search/i }));
    expect(screen.getByRole("heading", { name: "Live Search" })).toBeInTheDocument();
    expect(screen.getByText(/OSQuery/i)).toBeInTheDocument();
  });

  it("opens the policy details screen from a policy row", async () => {
    const user = userEvent.setup();
    render(<PolicyPage />);

    await user.click(await screen.findByRole("button", { name: "Default Policy v1.01" }));

    expect(screen.getByRole("heading", { name: "Policy details" })).toBeInTheDocument();
    expect(await screen.findByDisplayValue("Default Policy v1.01")).toBeInTheDocument();
  });

  it("enables row actions from selection and refreshes policies", async () => {
    const user = userEvent.setup();
    render(<PolicyPage />);

    await screen.findByRole("button", { name: "Default Policy v1.01" });
    const cloneButton = screen.getByRole("button", { name: /Clone Policy/i });
    const deleteButton = screen.getByRole("button", { name: /Delete/i });
    expect(cloneButton).toBeDisabled();
    expect(deleteButton).toBeDisabled();

    await user.click(screen.getByLabelText("Select Default Policy v1.01"));
    expect(cloneButton).toBeEnabled();
    expect(deleteButton).toBeEnabled();

    await user.click(screen.getByRole("button", { name: /Refresh/i }));

    await waitFor(() => {
      expect(apiGetMock).toHaveBeenCalledWith("/policies");
    });
  });
});
