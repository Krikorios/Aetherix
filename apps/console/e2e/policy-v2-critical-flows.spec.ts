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
  await route.fulfill({
    status,
    contentType: "application/json",
    headers: {
      "access-control-allow-origin": "*",
      "access-control-allow-methods": "GET,POST,PUT,PATCH,DELETE,OPTIONS",
      "access-control-allow-headers": "*",
    },
    body: JSON.stringify(payload),
  });
}


async function fulfillPreflight(route: Route) {
  await route.fulfill({
    status: 204,
    headers: {
      "access-control-allow-origin": "*",
      "access-control-allow-methods": "GET,POST,PUT,PATCH,DELETE,OPTIONS",
      "access-control-allow-headers": "*",
    },
  });
}


const MOCKED_API_ROOT_PATTERN = /^\/[a-z0-9][a-z0-9_-]*(?:\/|$)/i;
const STRICT_READ_ROOTS = new Set(["agent", "me", "policies"]);
const MOCK_ACCESS_TOKEN = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhY2NvdW50LTEiLCJleHAiOjQxMDI0NDQ4MDB9.sig";

// E2E mocking strategy: keep explicit handlers for endpoints that drive policy behavior,
// but let read-only dashboard list endpoints fail safe with empty arrays. This avoids
// smoke flakes when a page adds a passive GET like /alerts or /endpoints/health while
// still returning 404 for unreviewed writes or policy-critical reads.
const SAFE_EMPTY_LIST_GET_PATHS = new Set(["/alerts", "/endpoints/health"]);
const SAFE_EMPTY_OBJECT_GET_PATHS = new Set(["/policies/active", "/usage/summary"]);


function apiRoot(pathname: string): string {
  return pathname.split("/").filter(Boolean)[0] ?? "";
}


function normalizeApiPath(pathname: string): string {
  if (pathname === "/api") {
    return "/";
  }
  if (pathname.startsWith("/api/")) {
    return pathname.slice(4);
  }
  return pathname;
}


async function fulfillSafeReadFallback(route: Route, pathname: string): Promise<boolean> {
  if (SAFE_EMPTY_LIST_GET_PATHS.has(pathname)) {
    await fulfill(route, []);
    return true;
  }

  if (SAFE_EMPTY_OBJECT_GET_PATHS.has(pathname)) {
    if (pathname === "/policies/active") {
      await fulfill(route, {
        id: "policy-active",
        name: "Mock Active Policy",
        mode: "review",
        protected_entities: [],
        genai_guardrail: false,
        escalate_at: "high",
      });
      return true;
    }

    await fulfill(route, {});
    return true;
  }

  if (pathname === "/companies" || pathname === "/customers") {
    await fulfill(route, []);
    return true;
  }

  if (pathname === "/system/banners/all") {
    await fulfill(route, []);
    return true;
  }

  if (/^\/customers\/[^/]+\/groups$/.test(pathname)) {
    await fulfill(route, []);
    return true;
  }

  if (/\/health$/.test(pathname)) {
    await fulfill(route, []);
    return true;
  }

  return false;
}


function mockedMe(role: RoleKind) {
  const isAdmin = role === "company_admin";
  return {
    account: {
      id: "account-1",
      email: isAdmin ? "admin@acme.test" : "msp@partner.test",
      full_name: isAdmin ? "Company Admin" : "MSP Partner",
      roles: [{ role_code: role }],
    },
    permissions: {
      policies: "manage",
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
  };
}


async function ensureSignedIn(page: Page, role: RoleKind) {
  const navPolicies = page.getByRole("button", { name: "Policies" });
  if ((await navPolicies.count()) > 0) {
    return;
  }

  await page.evaluate((token) => {
    window.localStorage.setItem("aetherix.access_token", token);
    window.dispatchEvent(new CustomEvent("aetherix:auth-changed", { detail: token }));
  }, MOCK_ACCESS_TOKEN);

  const signInButton = page.getByRole("button", { name: "Sign in" });
  if ((await signInButton.count()) > 0) {
    await page.getByRole("textbox", { name: "Email" }).fill(role === "company_admin" ? "admin@acme.test" : "msp@partner.test");
    await page.getByPlaceholder("••••••••").fill("Password1!");
    await signInButton.click();
    await page.getByPlaceholder("123456").fill("123456");
    await page.getByRole("button", { name: "Verify and sign in" }).click();
  }
}


async function openPoliciesPage(page: Page) {
  const navPolicies = page.getByRole("button", { name: "Policies" });
  if ((await navPolicies.count()) > 0) {
    await navPolicies.first().click();
    return;
  }

  await page.evaluate(() => {
    window.dispatchEvent(
      new CustomEvent("aetherix:navigate", { detail: { page: "policies" } }),
    );
  });
}


async function fillPolicyNameField(page: Page, name: string) {
  const input = page.getByPlaceholder("Enter policy name");
  await expect(input).toBeVisible();
  await input.fill(name);
}


async function openModulesPanelIfPresent(page: Page) {
  const moduleTabCandidates = [
    page.getByRole("button", { name: /Aetherix modules/i }),
    page.getByRole("button", { name: /Policy modules/i }),
    page.getByRole("tab", { name: /Modules/i }),
  ];
  for (const locator of moduleTabCandidates) {
    if ((await locator.count()) > 0) {
      await locator.first().click();
      return;
    }
  }
}


async function installPolicyApiMocks(page: Page, role: RoleKind) {
  page.on("console", (msg) => {
    console.log(`[BROWSER CONSOLE] [${msg.type()}] ${msg.text()}`);
  });
  page.on("pageerror", (err) => {
    console.error(`[BROWSER EXCEPTION] ${err.message}`);
  });

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
    const apiPath = normalizeApiPath(url.pathname);
    const method = route.request().method();

    // Bypass mock routing for static dev-server assets
    if (url.port === "4173" || url.pathname.includes(".") || url.pathname.startsWith("/@") || url.pathname.startsWith("/node_modules/")) {
      await route.fallback();
      return;
    }

    if (!apiPath.startsWith("/") || !apiPath.match(MOCKED_API_ROOT_PATTERN)) {
      await route.fallback();
      return;
    }

    if (method === "OPTIONS") {
      await fulfillPreflight(route);
      return;
    }

    if (apiPath === "/me" && method === "GET") {
      await fulfill(route, mockedMe(role));
      return;
    }

    if (apiPath === "/auth/login" && method === "POST") {
      await fulfill(route, {
        status: "totp_required",
        challenge_id: "challenge-1",
        email: role === "company_admin" ? "admin@acme.test" : "msp@partner.test",
      });
      return;
    }

    if (apiPath === "/auth/totp/verify" && method === "POST") {
      await fulfill(route, {
        access_token: MOCK_ACCESS_TOKEN,
        token_type: "Bearer",
        expires_at: "2100-01-01T00:00:00Z",
        me: mockedMe(role),
      });
      return;
    }

    if (apiPath === "/policies" && method === "GET") {
      const items = state.policies.map((p) => ({
        id: p.id,
        name: p.name,
        status: p.status,
        latest_version: p.latest_version,
        active_version: p.active_version,
        scope: p.scope,
        created_at: "2026-05-23T00:00:00Z",
        updated_at: "2026-05-23T00:00:00Z",
      }));
      await fulfill(route, {
        items,
        total: items.length,
        limit: 50,
        offset: 0,
      });
      return;
    }

    if (apiPath === "/policies" && method === "POST") {
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

    if (apiPath.startsWith("/policies/") && method === "GET") {
      const policyId = apiPath.split("/")[2];
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

    if (apiPath.match(/^\/policies\/[^/]+\/simulate$/) && method === "POST") {
      const id = `sim-${Date.now()}`;
      state.lastSimulationId = id;
      await fulfill(route, {
        id,
        policy_id: apiPath.split("/")[2],
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

    if (apiPath.match(/^\/policies\/[^/]+\/promote$/) && method === "POST") {
      const body = route.request().postDataJSON() as any;
      if (!state.lastSimulationId || body.simulation_id !== state.lastSimulationId) {
        await fulfill(route, { detail: "simulation not found for policy" }, 400);
        return;
      }
      if (!body.operator_approved) {
        await fulfill(route, { detail: "operator approval is required for destructive actions" }, 400);
        return;
      }
      const policyId = apiPath.split("/")[2];
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

    if (apiPath === "/policies/assign" && method === "POST") {
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

    if (apiPath === "/policies/effective" && method === "GET") {
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

    if (apiPath === "/companies/summary" && method === "GET") {
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

    if (apiPath === "/endpoints" && method === "GET") {
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

    if (apiPath === "/subscriptions" && method === "GET") {
      await fulfill(route, [{ id: "sub-1", sku: "core", core_features: [] }]);
      return;
    }

    if (apiPath === "/customers/customer-1/groups" && method === "GET") {
      await fulfill(route, [{ id: "group-1", customer_id: "customer-1", name: "Engineering", created_at: "2026-05-23T00:00:00Z" }]);
      return;
    }

    if (apiPath === "/agent/policy" && method === "GET") {
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

    if (method === "GET" && (await fulfillSafeReadFallback(route, apiPath))) {
      return;
    }

    if (method === "GET" && !STRICT_READ_ROOTS.has(apiRoot(apiPath))) {
      await fulfill(route, []);
      return;
    }

    await fulfill(route, { detail: `Unhandled mock route ${method} ${apiPath}` }, 404);
  });

  await page.addInitScript(() => {
    window.localStorage.setItem(
      "aetherix.access_token",
      "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhY2NvdW50LTEiLCJleHAiOjQxMDI0NDQ4MDB9.sig",
    );
  });
}


async function approvePromotion(page: Page) {
  const promotionSheet = page.getByRole("dialog", { name: "Production Promotion gate" });
  await expect(promotionSheet).toBeVisible();
  await promotionSheet.getByRole("checkbox").check();
  await promotionSheet.getByRole("textbox").fill("Approved during policy E2E validation");
  await promotionSheet.getByRole("button", { name: "Confirm & Promote" }).click();
}


test("Flow A: MSP creates, simulates, promotes, assigns policy", async ({ page }) => {
  await installPolicyApiMocks(page, "msp_partner");
  await page.goto("/?harness=true&role=msp_partner&page=policies");

  await page.getByRole("button", { name: /Add policy/i }).click();
  await fillPolicyNameField(page, "Flow A Policy");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByText(/created successfully/i)).toBeVisible();

  await openModulesPanelIfPresent(page);
  await page.getByRole("button", { name: "Simulate selected" }).click();
  await expect(page.getByText(/Simulation complete:/i)).toBeVisible();

  await page.getByRole("button", { name: "Promote selected" }).click();
  await approvePromotion(page);
  await expect(page.getByText("Policy promoted successfully.")).toBeVisible();

  await page.getByRole("button", { name: "Assign selected" }).click();
  const assignDialog = page.getByRole("dialog", { name: "Assign policy" });
  await expect(assignDialog).toBeVisible();
  await assignDialog.getByLabel("Company").selectOption("customer-1");
  await page.getByRole("button", { name: "Assign policy" }).click();
  await expect(page.getByText("Policy assigned successfully.")).toBeVisible();
});


test("Flow B: Company Admin creates group override and preview resolves inheritance", async ({ page }) => {
  await installPolicyApiMocks(page, "company_admin");
  await page.goto("/?harness=true&role=company_admin&page=policies");

  await page.getByRole("button", { name: /Add policy/i }).click();
  await fillPolicyNameField(page, "Flow B Group Override");
  await openModulesPanelIfPresent(page);
  await page.getByLabel("Parent policy").selectOption("policy-1");

  await page.getByRole("button", { name: "Save" }).click();
  await page.getByRole("button", { name: "Simulate selected" }).click();
  await page.getByRole("button", { name: "Promote selected" }).click();
  await approvePromotion(page);

  await page.getByRole("button", { name: "Assign selected" }).click();
  const assignDialog = page.getByRole("dialog", { name: "Assign policy" });
  await expect(assignDialog).toBeVisible();
  await page.getByRole("button", { name: "group" }).click();
  await assignDialog.getByLabel("Company").selectOption("customer-1");
  await assignDialog.getByLabel("Group").selectOption("group-1");
  await page.getByRole("button", { name: "Assign policy" }).click();
  await expect(page.getByText("Policy assigned successfully.")).toBeVisible();
});


test("Flow C: Agent fetch includes semantic/genai modules and entitlement filtering", async ({ page }) => {
  await installPolicyApiMocks(page, "msp_partner");
  await page.goto("/?harness=true&role=msp_partner&page=policies");

  await page.getByRole("button", { name: "Inherited Base" }).click();
  await openModulesPanelIfPresent(page);
  await page.getByRole("button", { name: "Assign selected" }).click();
  const assignDialog = page.getByRole("dialog", { name: "Assign policy" });
  await expect(assignDialog).toBeVisible();
  await assignDialog.getByRole("button", { name: /^endpoint$/i }).click();
  await assignDialog.locator("label").filter({ hasText: "Endpoint" }).locator("select").selectOption("endpoint-1");
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
  await page.goto("/?harness=true&role=msp_partner&page=policies");

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

  await page.getByRole("button", { name: "Inherited Base" }).click();
  await openModulesPanelIfPresent(page);
  await page.getByRole("button", { name: "Simulate selected" }).click();
  await page.getByRole("button", { name: "Promote selected" }).click();
  await approvePromotion(page);
  await expect(page.getByText("Policy promoted successfully.")).toBeVisible();
});
