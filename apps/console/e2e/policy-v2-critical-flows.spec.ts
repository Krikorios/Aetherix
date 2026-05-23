import { expect, test, type Page, type Route } from "@playwright/test";


type RoleKind = "msp_partner" | "company_admin";

type PolicyRecord = {
  id: string;
  name: string;
  status: "draft" | "active";
  latest_version: number;
  active_version: number | null;
  scope: { partner_id: string | null; customer_id: string | null; group_id: string | null; endpoint_id: string | null };
  modules: Record<string, Record<string, unknown>>;
};


function defaultModules() {
  return {
    general: { enabled: true },
    tenant_scope: { enabled: true },
    entitlements: { enabled: true },
    deployment_profile: { enabled: true },
    antimalware: { enabled: true, response_action: "review" },
    behavior_monitoring: { enabled: true },
    anti_exploit: { enabled: true },
    ransomware_mitigation: { enabled: true, rollback_approval: "operator_required" },
    firewall: { enabled: true },
    network_protection: { enabled: true, network_attack_signature_action: "review" },
    web_protection: { enabled: true, sensitive_upload_action: "block" },
    classification_labeling: { enabled: true },
    semantic_dlp: {
      enabled: true,
      sensitivity_labels_csv: "Public, Internal, Confidential, Restricted",
      genai_destinations_csv: "copilot, claude, gemini, chatgpt, custom",
      paste_sensitive_action: "review",
      upload_restricted_action: "block",
      copy_to_genai_action: "review",
      presidio_detector: true,
      llm_semantic_detector: true,
      custom_classifiers_csv: "finance, source_code",
      actions: {
        paste_sensitive: "review",
        upload_restricted: "block",
        copy_to_genai: "review",
      },
      detectors: {
        presidio: true,
        llm_semantic: true,
        custom_classifiers: ["finance", "source_code"],
      },
    },
    genai_guardrails: {
      enabled: true,
      destinations_csv: "copilot, claude, gemini, chatgpt, custom",
      browser_enforcement: true,
      endpoint_enforcement: true,
      paste_sensitive_action: "review",
      upload_restricted_action: "block",
      copy_to_genai_action: "review",
      actions: {
        paste_sensitive: "review",
        upload_restricted: "block",
        copy_to_genai: "review",
      },
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
  };
}


async function fulfill(route: Route, payload: unknown, status = 200) {
  await route.fulfill({ status, contentType: "application/json", body: JSON.stringify(payload) });
}


async function installPolicyApiMocks(page: Page, role: RoleKind) {
  const state: {
    policies: PolicyRecord[];
    lastSimulationId: string | null;
    assignments: Array<{ id: string; policy_id: string; customer_id: string | null; group_id: string | null; endpoint_id: string | null }>;
  } = {
    policies: [
      {
        id: "policy-1",
        name: "Inherited Base",
        status: "active",
        latest_version: 2,
        active_version: 2,
        scope: { partner_id: "partner-1", customer_id: "customer-1", group_id: null, endpoint_id: null },
        modules: defaultModules(),
      },
    ],
    lastSimulationId: null,
    assignments: [],
  };

  await page.route("**/*", async (route) => {
    const url = new URL(route.request().url());
    const method = route.request().method();

    if (!url.pathname.startsWith("/") || !url.pathname.match(/^\/(me|policies|companies|endpoints|subscriptions|customers|agent)\b/)) {
      await route.fallback();
      return;
    }

    if (url.pathname === "/me" && method === "GET") {
      const isAdmin = role === "company_admin";
      await fulfill(route, {
        account: {
          id: "account-1",
          email: isAdmin ? "admin@acme.test" : "msp@partner.test",
          full_name: isAdmin ? "Company Admin" : "MSP Partner",
          roles: [{ role_code: role }],
        },
        permissions: {
          policies: isAdmin ? "manage" : "manage",
          companies: isAdmin ? "view" : "manage",
          incidents: "view",
          accounts: isAdmin ? "none" : "manage",
          licensing: "view",
        },
        scope: {
          is_platform: false,
          partner_ids: ["partner-1"],
          customer_ids: ["customer-1"],
        },
        branding: {
          product_name: "Aetherix",
          tagline: "MSP Console",
          primary_color: "#0b6b57",
          accent_color: "#0b6b57",
          source: "platform",
        },
      });
      return;
    }

    if (url.pathname === "/policies" && method === "GET") {
      await fulfill(route, state.policies.map((p) => ({
        id: p.id,
        name: p.name,
        status: p.status,
        latest_version: p.latest_version,
        active_version: p.active_version,
        scope: p.scope,
        created_at: "2026-05-23T00:00:00Z",
        updated_at: "2026-05-23T00:00:00Z",
      })));
      return;
    }

    if (url.pathname === "/policies" && method === "POST") {
      const body = route.request().postDataJSON() as any;
      const nextId = `policy-${state.policies.length + 1}`;
      const record: PolicyRecord = {
        id: nextId,
        name: body.name,
        status: "draft",
        latest_version: 1,
        active_version: null,
        scope: body.scope,
        modules: body.modules,
      };
      state.policies.unshift(record);
      await fulfill(route, {
        policy: {
          id: nextId,
          schema_version: "2.0",
          name: body.name,
          scope: body.scope,
          lineage: body.lineage,
          modules: body.modules,
          white_label_names: {},
          status: "draft",
          latest_version: 1,
          active_version: null,
          created_at: "2026-05-23T00:00:00Z",
          created_by: "account-1",
          updated_at: "2026-05-23T00:00:00Z",
          updated_by: "account-1",
        },
        version: {
          id: `version-${nextId}`,
          policy_id: nextId,
          version: 1,
          status: "draft",
          payload: body,
          payload_hash: "hash",
          signed_by: "tests",
          signature: "sig",
          created_at: "2026-05-23T00:00:00Z",
          created_by: "account-1",
          promoted_from_simulation_id: null,
        },
      }, 201);
      return;
    }

    if (url.pathname.startsWith("/policies/") && method === "GET") {
      const policyId = url.pathname.split("/")[2];
      const policy = state.policies.find((p) => p.id === policyId);
      if (!policy) {
        await fulfill(route, { detail: "policy not found" }, 404);
        return;
      }
      await fulfill(route, {
        policy: {
          id: policy.id,
          schema_version: "2.0",
          name: policy.name,
          scope: policy.scope,
          lineage: { parent_policy_id: null, inheritance_mode: "inherit_with_overrides" },
          modules: policy.modules,
          white_label_names: {},
          status: policy.status,
          latest_version: policy.latest_version,
          active_version: policy.active_version,
          created_at: "2026-05-23T00:00:00Z",
          created_by: "account-1",
          updated_at: "2026-05-23T00:00:00Z",
          updated_by: "account-1",
        },
        latest_version: {
          id: `version-${policy.id}`,
          policy_id: policy.id,
          version: policy.latest_version,
          status: policy.status,
          payload: {
            schema_version: "2.0",
            name: policy.name,
            scope: policy.scope,
            lineage: { parent_policy_id: null, inheritance_mode: "inherit_with_overrides" },
            modules: policy.modules,
            white_label_names: {},
          },
          payload_hash: "hash",
          signed_by: "tests",
          signature: "sig",
          created_at: "2026-05-23T00:00:00Z",
          created_by: "account-1",
          promoted_from_simulation_id: null,
        },
        resolved_preview: {
          schema_version: "2.0",
          name: policy.name,
          scope: policy.scope,
          lineage: { parent_policy_id: null, inheritance_mode: "inherit_with_overrides" },
          modules: policy.modules,
          white_label_names: {},
        },
        locked_modules: [],
      });
      return;
    }

    if (url.pathname.match(/^\/policies\/[^/]+\/simulate$/) && method === "POST") {
      const id = `sim-${Date.now()}`;
      state.lastSimulationId = id;
      await fulfill(route, {
        id,
        policy_id: url.pathname.split("/")[2],
        policy_version_id: "version-1",
        status: "completed",
        summary: {
          modules_total: 30,
          modules_enabled: 17,
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
        created_by: "account-1",
        approved_at: null,
      });
      return;
    }

    if (url.pathname.match(/^\/policies\/[^/]+\/promote$/) && method === "POST") {
      const body = route.request().postDataJSON() as any;
      if (!state.lastSimulationId || body.simulation_id !== state.lastSimulationId) {
        await fulfill(route, { detail: "simulation not found for policy" }, 400);
        return;
      }
      if (!body.operator_approved) {
        await fulfill(route, { detail: "operator approval is required for destructive actions" }, 400);
        return;
      }
      const policyId = url.pathname.split("/")[2];
      const policy = state.policies.find((p) => p.id === policyId);
      if (policy) {
        policy.status = "active";
        policy.latest_version += 1;
        policy.active_version = policy.latest_version;
      }
      await fulfill(route, {
        id: `version-${policyId}-${Date.now()}`,
        policy_id: policyId,
        version: policy?.latest_version ?? 2,
        status: "active",
      });
      return;
    }

    if (url.pathname === "/policies/assign" && method === "POST") {
      const body = route.request().postDataJSON() as any;
      const assignment = {
        id: `assign-${Date.now()}`,
        policy_id: body.policy_id,
        customer_id: body.customer_id ?? null,
        group_id: body.group_id ?? null,
        endpoint_id: body.endpoint_id ?? null,
      };
      state.assignments.push(assignment);
      await fulfill(route, assignment, 201);
      return;
    }

    if (url.pathname === "/policies/effective" && method === "GET") {
      await fulfill(route, {
        endpoint_id: url.searchParams.get("endpoint_id"),
        scope: {
          partner_id: "partner-1",
          customer_id: url.searchParams.get("customer_id") ?? "customer-1",
          group_id: url.searchParams.get("group_id"),
          endpoint_id: url.searchParams.get("endpoint_id"),
        },
        assignments_applied: state.assignments,
        resolved_policy: {
          schema_version: "2.0",
          name: "Effective",
          scope: { partner_id: "partner-1", customer_id: "customer-1", group_id: null, endpoint_id: null },
          lineage: { parent_policy_id: null, inheritance_mode: "inherit_with_overrides" },
          modules: {
            semantic_dlp: { enabled: true },
            genai_guardrails: { enabled: true, actions: { copy_to_genai: "block" } },
          },
          white_label_names: {},
        },
        policy_ids_applied: state.assignments.map((item) => item.policy_id),
        evidence_controls: ["iso27001-2022:A.8.16"],
      });
      return;
    }

    if (url.pathname === "/companies/summary" && method === "GET") {
      await fulfill(route, {
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
              created_by: "tests",
              created_at: "2026-05-23T00:00:00Z",
              default_group_id: "group-1",
              assigned_policy_package_id: null,
              assigned_policy_name: null,
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
      });
      return;
    }

    if (url.pathname === "/endpoints" && method === "GET") {
      await fulfill(route, [
        {
          id: "endpoint-1",
          hostname: "eng-laptop",
          os: "macOS",
          status: "healthy",
          risk_score: 20,
          last_seen: "2026-05-23T00:00:00Z",
          policy_version: "2",
          agent_version: "0.1.0",
        },
      ]);
      return;
    }

    if (url.pathname === "/subscriptions" && method === "GET") {
      await fulfill(route, [{ id: "sub-1", sku: "core", core_features: [] }]);
      return;
    }

    if (url.pathname === "/customers/customer-1/groups" && method === "GET") {
      await fulfill(route, [{ id: "group-1", customer_id: "customer-1", name: "Engineering", created_at: "2026-05-23T00:00:00Z" }]);
      return;
    }

    if (url.pathname === "/agent/policy" && method === "GET") {
      await fulfill(route, {
        endpoint_id: url.searchParams.get("endpoint_id"),
        policy_version_hash: "hash",
        resolved_policy: {
          schema_version: "2.0",
          name: "Agent effective",
          scope: { partner_id: "partner-1", customer_id: "customer-1", group_id: "group-1", endpoint_id: "endpoint-1" },
          lineage: { parent_policy_id: null, inheritance_mode: "inherit_with_overrides" },
          modules: {
            semantic_dlp: { enabled: true },
            genai_guardrails: { enabled: true },
            digital_risk_protection: { enabled: false, locked: true },
          },
          white_label_names: {},
        },
        evidence_controls: ["iso27001-2022:A.8.16"],
      });
      return;
    }

    await fulfill(route, { detail: `Unhandled mock route ${method} ${url.pathname}` }, 404);
  });

  await page.addInitScript(() => {
    window.localStorage.setItem("aetherix.account_id", "account-1");
  });
}


test("Flow A: MSP creates, simulates, promotes, assigns policy", async ({ page }) => {
  await installPolicyApiMocks(page, "msp_partner");
  await page.goto("/");

  await page.getByRole("button", { name: "Policies" }).click();
  await page.getByLabel("Policy name").fill("Flow A Policy");
  await page.getByRole("button", { name: "Save draft" }).click();
  await expect(page.getByText(/Created draft/i)).toBeVisible();

  await page.getByRole("button", { name: "Simulate selected" }).click();
  await expect(page.getByText(/Approval gate active/i)).toBeVisible();

  await page.getByRole("button", { name: "Promote selected" }).click();
  await expect(page.getByText("Policy promoted successfully.")).toBeVisible();

  await page.getByRole("button", { name: "Assign selected" }).click();
  const assignDialog = page.getByRole("dialog", { name: "Assign policy" });
  await assignDialog.getByLabel("Company").selectOption("customer-1");
  await page.getByRole("button", { name: "Assign policy" }).click();
  await expect(page.getByText("Policy assigned successfully.")).toBeVisible();
});


test("Flow B: Company Admin creates group override and preview resolves inheritance", async ({ page }) => {
  await installPolicyApiMocks(page, "company_admin");
  await page.goto("/");

  await page.getByRole("button", { name: "Policies" }).click();
  await page.getByLabel("Policy name").fill("Flow B Group Override");
  await page.getByLabel("Parent policy").selectOption("policy-1");

  await page.getByRole("button", { name: "Save draft" }).click();
  await page.getByRole("button", { name: "Simulate selected" }).click();
  await page.getByRole("button", { name: "Promote selected" }).click();

  await page.getByRole("button", { name: "Assign selected" }).click();
  const assignDialog = page.getByRole("dialog", { name: "Assign policy" });
  await page.getByRole("button", { name: "group" }).click();
  await assignDialog.getByLabel("Company").selectOption("customer-1");
  await assignDialog.getByLabel("Group").selectOption("group-1");
  await page.getByRole("button", { name: "Assign policy" }).click();
  await expect(page.getByText("Policy assigned successfully.")).toBeVisible();
});


test("Flow C: Agent fetch includes semantic/genai modules and entitlement filtering", async ({ page }) => {
  await installPolicyApiMocks(page, "msp_partner");
  await page.goto("/");

  await page.getByRole("button", { name: "Policies" }).click();
  await page.getByRole("button", { name: "Assign selected" }).click();
  await page.getByRole("button", { name: "endpoint" }).click();
  await page.getByLabel("Endpoint").selectOption("endpoint-1");
  await page.getByRole("button", { name: "Assign policy" }).click();
  await expect(page.getByText("Policy assigned successfully.")).toBeVisible();

  const body = await page.evaluate(async () => {
    const res = await fetch("http://127.0.0.1:8000/agent/policy?endpoint_id=endpoint-1&token=agent-token");
    if (!res.ok) {
      throw new Error(`agent fetch failed with ${res.status}`);
    }
    return res.json();
  });
  expect(body.resolved_policy.modules.semantic_dlp.enabled).toBeTruthy();
  expect(body.resolved_policy.modules.genai_guardrails.enabled).toBeTruthy();
  expect(body.resolved_policy.modules.digital_risk_protection.locked).toBeTruthy();
});


test("Flow D: Destructive gate rejects promotion before simulation, then accepts with approval", async ({ page }) => {
  await installPolicyApiMocks(page, "msp_partner");
  await page.goto("/");

  const deniedStatus = await page.evaluate(async () => {
    const denied = await fetch("http://127.0.0.1:8000/policies/policy-1/promote", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        simulation_id: "missing-simulation",
        operator_approved: true,
        approval_reason: "manual",
      }),
    });
    return denied.status;
  });
  expect(deniedStatus).toBe(400);

  await page.getByRole("button", { name: "Policies" }).click();
  await page.getByRole("button", { name: "Simulate selected" }).click();
  await page.getByRole("button", { name: "Promote selected" }).click();
  await expect(page.getByText("Policy promoted successfully.")).toBeVisible();
});
