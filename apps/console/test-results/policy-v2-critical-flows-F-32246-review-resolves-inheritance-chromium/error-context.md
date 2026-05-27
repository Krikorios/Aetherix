# Instructions

- Following Playwright test failed.
- Explain why, be concise, respect Playwright best practices.
- Provide a snippet of code with the fix, if possible.

# Test info

- Name: policy-v2-critical-flows.spec.ts >> Flow B: Company Admin creates group override and preview resolves inheritance
- Location: e2e/policy-v2-critical-flows.spec.ts:515:1

# Error details

```
Error: expect(locator).toBeVisible() failed

Locator: getByRole('dialog', { name: 'Production Promotion gate' })
Expected: visible
Timeout: 5000ms
Error: element(s) not found

Call log:
  - Expect "toBeVisible" with timeout 5000ms
  - waiting for getByRole('dialog', { name: 'Production Promotion gate' })

```

```yaml
- main:
  - complementary "Primary navigation":
    - strong: Aetherix
    - text: MSP Console
    - button "Collapse navigation"
    - navigation "OVERVIEW":
      - button "OVERVIEW" [expanded]
      - button "Dashboard"
      - button "Executive Summary"
      - button "Health & Attack Surface"
    - navigation "INCIDENTS & RESPONSE":
      - button "INCIDENTS & RESPONSE" [expanded]
      - button "Alerts"
      - button "Search"
      - button "Blocklist"
      - button "Custom Rules"
      - button "Threats Xplorer"
    - navigation "PROTECTION":
      - button "PROTECTION" [expanded]
      - button "Policies"
      - button "Policy Assignments"
      - button "Antimalware & Behavior"
      - button "Web & Email Protection"
      - button "Device Control"
    - navigation "RISK & EXTERNAL":
      - button "RISK & EXTERNAL" [expanded]
      - button "Risk Management"
      - button "Digital Risk (DRP)"
      - button "External Attack Surface (EASM)"
      - button "Reports"
      - button "Compliance Center"
    - navigation "MSP CONTROL":
      - button "MSP CONTROL" [expanded]
      - button "Network"
      - button "Companies"
    - navigation "ADD-ONS & INTEGRATIONS":
      - button "ADD-ONS & INTEGRATIONS" [expanded]
      - button "Sandbox Analyzer"
      - button "Email Security"
      - button "Mobile Security"
      - button "Data Insights"
    - text: Signed in as
    - strong: Company Admin
    - code: admin@acme.test
    - emphasis: Company Administrator
    - button "Sign out"
  - complementary "Policy settings navigation":
    - textbox "Search policy settings":
      - /placeholder: Search (min. 3 characters)
    - navigation:
      - heading "General" [level=2]:
        - button "General" [expanded]
      - button "Policy"
      - button "Inheritance rules"
      - button "Agent 2/3"
      - button "Toggle Agent Section"
      - button "Notifications On"
      - button "Agent Settings": Settings
      - button "Agent Communication": Communication
      - button "Agent Update": Update On
      - button "Security Telemetry Off"
      - button "Relay"
      - button "Toggle Relay Section"
      - button "Relay Communication": Communication
      - button "Relay Update": Update
      - button "Aetherix modules"
      - heading "Protection & Monitoring" [level=2]:
        - button "Protection & Monitoring" [expanded]
      - button "Antimalware 4/6"
      - button "Toggle Antimalware Section"
      - button "Antimalware On-Access": On-Access On
      - button "Antimalware On-Execute": On-Execute 3/4
      - button "Antimalware On-Demand": On-Demand Off
      - button "Antimalware Anti-Tampering": Anti-Tampering On
      - button "Antimalware Hyper Detect": Hyper Detect On
      - button "Antimalware Advanced Anti-Exploit": Advanced Anti-Exploit On
      - button "Antimalware Security Servers": Security Servers
      - button "Antimalware Settings": Settings
      - button "Antimalware Exclusions": Exclusions
      - button "Sandbox Analyzer Off"
      - button "Toggle Sandbox Section"
      - button "Sandbox Endpoint Sensor": Endpoint Sensor Off
      - button "Firewall On"
      - button "Toggle Firewall Section"
      - button "Firewall General": General 1/2
      - button "Firewall Settings": Settings
      - button "Firewall Rules": Rules
      - button "Network Protection 2/5"
      - button "Toggle Network Section"
      - button "Network Protection General": General On
      - button "Network Protection Content Control": Content Control Off
      - button "Network Protection Web Protection": Web Protection 2/3
      - button "Network Protection Network Attacks": Network Attacks On
      - button "Network Protection Custom Pages": Custom Pages Off
      - button "Patch Management Off"
      - button "Device Control Off"
      - button "Integrity Monitoring Off"
      - button "Exchange Protection Off"
      - button "Encryption Off"
      - button "Incidents Sensor On"
      - button "Storage Protection Off"
      - button "Risk Management Off"
      - button "Toggle Risk Management Section"
      - button "Blocklist On"
      - button "Live Search Off"
      - button "Web, DLP & GenAI 5/7"
      - button "SIEM / HIDS 2/4"
      - button "Agentic Response On"
      - button "Digital Risk & EASM Off"
      - button "Compliance Evidence On"
      - button "Integrations & Branding 2/2"
  - button "Policies"
  - text: /
  - strong: Add policy
  - text: / Aetherix /
  - strong: Aetherix modules
  - heading "Add policy" [level=1]
  - paragraph: Create a draft policy and configure its tenant scope, inheritance, and protection modules.
  - link "Get help from Support Center":
    - /url: https://support.aetherix.local
  - status: "Simulation complete: 2 module(s) trigger approval gates."
  - main:
    - region "Policy engine modules":
      - heading "Policy engine modules" [level=2]
      - paragraph: Configure the Aetherix runtime modules, entitlement locks, simulations, promotions, and assignments for this policy.
      - button "Simulate selected"
      - button "Promote selected"
      - button "Assign selected"
      - text: Company scope
      - combobox "Company scope":
        - option "Global / Partner-level" [selected]
        - option "Acme Co"
      - text: Parent policy
      - combobox "Parent policy":
        - option "None" [selected]
        - option "Flow B Group Override (v1)"
        - option "Inherited Base (v2)"
      - text: Inheritance mode
      - combobox "Inheritance mode":
        - option "Inherit with overrides" [selected]
        - option "Replace"
      - article:
        - button "General general":
          - strong: General
          - text: general
        - checkbox "Enabled" [checked]
        - text: Enabled Update channel
        - combobox "Update channel":
          - option "stable" [selected]
          - option "slow"
          - option "fast"
      - article:
        - button "Tenant Scope tenant_scope":
          - strong: Tenant Scope
          - text: tenant_scope
      - article:
        - button "Entitlements entitlements":
          - strong: Entitlements
          - text: entitlements
      - article:
        - button "Deployment Profile deployment_profile":
          - strong: Deployment Profile
          - text: deployment_profile
      - article:
        - button "Antimalware antimalware":
          - strong: Antimalware
          - text: antimalware
        - checkbox "Enabled" [checked]
        - text: Enabled Response action
        - combobox "Response action":
          - option "allow"
          - option "review" [selected]
          - option "block"
      - article:
        - button "Behavior Monitoring behavior_monitoring":
          - strong: Behavior Monitoring
          - text: behavior_monitoring
      - article:
        - button "Anti Exploit anti_exploit":
          - strong: Anti Exploit
          - text: anti_exploit
      - article:
        - button "Ransomware Mitigation ransomware_mitigation":
          - strong: Ransomware Mitigation
          - text: ransomware_mitigation
      - article:
        - button "Firewall firewall":
          - strong: Firewall
          - text: firewall
      - article:
        - button "Network Protection network_protection":
          - strong: Network Protection
          - text: network_protection
      - article:
        - button "Web Protection web_protection":
          - strong: Web Protection
          - text: web_protection
      - article:
        - button "Classification & Labeling classification_labeling":
          - strong: Classification & Labeling
          - text: classification_labeling
      - article:
        - button "Semantic DLP semantic_dlp":
          - strong: Semantic DLP
          - text: semantic_dlp
        - checkbox "Enabled"
        - text: Enabled Sensitivity labels (comma-separated)
        - textbox "Sensitivity labels (comma-separated)": Public, Internal, Confidential, Restricted
        - text: GenAI destinations (comma-separated)
        - textbox "GenAI destinations (comma-separated)": copilot, claude, gemini, chatgpt, custom
        - text: Paste sensitive action
        - combobox "Paste sensitive action":
          - option "allow"
          - option "review" [selected]
          - option "block"
        - text: Upload restricted action
        - combobox "Upload restricted action":
          - option "allow"
          - option "review"
          - option "block" [selected]
        - text: Copy to GenAI action
        - combobox "Copy to GenAI action":
          - option "allow"
          - option "review" [selected]
          - option "block"
        - checkbox "Use Presidio detector" [checked]
        - text: Use Presidio detector
        - checkbox "Use LLM semantic detector" [checked]
        - text: Use LLM semantic detector Custom classifiers (comma-separated)
        - textbox "Custom classifiers (comma-separated)"
      - article:
        - button "GenAI Guardrails genai_guardrails":
          - strong: GenAI Guardrails
          - text: genai_guardrails
      - article:
        - button "Device Control device_control":
          - strong: Device Control
          - text: device_control
      - article:
        - button "Sandbox Analyzer sandbox_analyzer":
          - strong: Sandbox Analyzer
          - text: sandbox_analyzer
      - article:
        - button "Patch Management patch_management":
          - strong: Patch Management
          - text: patch_management
      - article:
        - button "SIEM / HIDS siem_hids":
          - strong: SIEM / HIDS
          - text: siem_hids
      - article:
        - button "Integrity Monitoring integrity_monitoring":
          - strong: Integrity Monitoring
          - text: integrity_monitoring
      - article:
        - button "Vulnerability Inventory vulnerability_inventory":
          - strong: Vulnerability Inventory
          - text: vulnerability_inventory
      - article:
        - button "Digital Risk Protection digital_risk_protection":
          - strong: Digital Risk Protection
          - text: digital_risk_protection
      - article:
        - button "External Attack Surface Management external_attack_surface_management":
          - strong: External Attack Surface Management
          - text: external_attack_surface_management
      - article:
        - button "Threat Intelligence threat_intelligence":
          - strong: Threat Intelligence
          - text: threat_intelligence
      - article:
        - button "Takedown Workflows takedown_workflows":
          - strong: Takedown Workflows
          - text: takedown_workflows
      - article:
        - button "Incident Correlation incident_correlation":
          - strong: Incident Correlation
          - text: incident_correlation
      - article:
        - button "Agentic Response agentic_response":
          - strong: Agentic Response
          - text: agentic_response
      - article:
        - button "AI Settings ai_settings":
          - strong: AI Settings
          - text: ai_settings
      - article:
        - button "AI Reports ai_reports":
          - strong: AI Reports
          - text: ai_reports
      - article:
        - button "Compliance Evidence compliance_evidence":
          - strong: Compliance Evidence
          - text: compliance_evidence
      - article:
        - button "Integrations integrations":
          - strong: Integrations
          - text: integrations
      - article:
        - button "Platform Observability platform_observability":
          - strong: Platform Observability
          - text: platform_observability
      - article:
        - button "White Label white_label":
          - strong: White Label
          - text: white_label
      - heading "Simulation Center & Impact Analysis" [level=3]
      - text: Security Posture Impact -48% Risk Delta ▼ Improved
      - paragraph: Expected risk exposure reduction based on activated detection & isolation engines.
      - text: Target Surface Size 14 Endpoints queued
      - paragraph: Active devices currently assigned inside this company tenant hierarchy.
      - strong: "Total Modules:"
      - text: "30"
      - strong: "Enabled:"
      - text: "17"
      - strong: "Block Actions:"
      - text: "2"
      - strong: "Network Isolations:"
      - text: "0"
      - strong: "Rollbacks:"
      - text: 0 PROMOTION GATE ACTIVE
      - paragraph: This policy configuration implements destructive threat defense protocols. Promoting this version requires manual operator sign-off and simulation logging evidence.
      - text: semantic_dlp block
  - button "Save"
  - button "Cancel"
```

# Test source

```ts
  381 | 
  382 |     if (url.pathname === "/companies/summary" && method === "GET") {
  383 |       await fulfill(route, {
  384 |         items: [
  385 |           {
  386 |             customer: {
  387 |               id: "customer-1",
  388 |               partner_id: "partner-1",
  389 |               customer_number: "C-001",
  390 |               company_type: "customer",
  391 |               name: "Acme Co",
  392 |               industry: null,
  393 |               country: null,
  394 |               company_size: null,
  395 |               status: "active",
  396 |               created_by: "tests",
  397 |               created_at: "2026-05-23T00:00:00Z",
  398 |               default_group_id: "group-1",
  399 |               assigned_policy_package_id: null,
  400 |               assigned_policy_name: null,
  401 |             },
  402 |             license: {
  403 |               subscription_sku: "core",
  404 |               addons: ["semantic_dlp"],
  405 |             },
  406 |           },
  407 |         ],
  408 |         total: 1,
  409 |         limit: 250,
  410 |         offset: 0,
  411 |       });
  412 |       return;
  413 |     }
  414 | 
  415 |     if (url.pathname === "/endpoints" && method === "GET") {
  416 |       await fulfill(route, [
  417 |         {
  418 |           id: "endpoint-1",
  419 |           hostname: "eng-laptop",
  420 |           os: "macOS",
  421 |           status: "healthy",
  422 |           risk_score: 20,
  423 |           last_seen: "2026-05-23T00:00:00Z",
  424 |           policy_version: "2",
  425 |           agent_version: "0.1.0",
  426 |         },
  427 |       ]);
  428 |       return;
  429 |     }
  430 | 
  431 |     if (url.pathname === "/subscriptions" && method === "GET") {
  432 |       await fulfill(route, [{ id: "sub-1", sku: "core", core_features: [] }]);
  433 |       return;
  434 |     }
  435 | 
  436 |     if (url.pathname === "/customers/customer-1/groups" && method === "GET") {
  437 |       await fulfill(route, [{ id: "group-1", customer_id: "customer-1", name: "Engineering", created_at: "2026-05-23T00:00:00Z" }]);
  438 |       return;
  439 |     }
  440 | 
  441 |     if (url.pathname === "/agent/policy" && method === "GET") {
  442 |       await fulfill(route, {
  443 |         endpoint_id: url.searchParams.get("endpoint_id"),
  444 |         policy_version_hash: "hash",
  445 |         resolved_policy: {
  446 |           schema_version: "2.0",
  447 |           name: "Agent effective",
  448 |           scope: { partner_id: "partner-1", customer_id: "customer-1", group_id: "group-1", endpoint_id: "endpoint-1" },
  449 |           lineage: { parent_policy_id: null, inheritance_mode: "inherit_with_overrides" },
  450 |           modules: {
  451 |             semantic_dlp: { enabled: true },
  452 |             genai_guardrails: { enabled: true },
  453 |             digital_risk_protection: { enabled: false, locked: true },
  454 |           },
  455 |           white_label_names: {},
  456 |         },
  457 |         evidence_controls: ["iso27001-2022:A.8.16"],
  458 |       });
  459 |       return;
  460 |     }
  461 | 
  462 |     await fulfill(route, { detail: `Unhandled mock route ${method} ${url.pathname}` }, 404);
  463 |   });
  464 | 
  465 |   await page.addInitScript(() => {
  466 |     const header = btoa(JSON.stringify({ alg: "none", typ: "JWT" }))
  467 |       .replace(/\+/g, "-")
  468 |       .replace(/\//g, "_")
  469 |       .replace(/=+$/g, "");
  470 |     const payload = btoa(JSON.stringify({ sub: "account-1", exp: 4_102_444_800 }))
  471 |       .replace(/\+/g, "-")
  472 |       .replace(/\//g, "_")
  473 |       .replace(/=+$/g, "");
  474 |     window.localStorage.setItem("aetherix.access_token", `${header}.${payload}.sig`);
  475 |   });
  476 | }
  477 | 
  478 | 
  479 | async function approvePromotion(page: Page) {
  480 |   const promotionSheet = page.getByRole("dialog", { name: "Production Promotion gate" });
> 481 |   await expect(promotionSheet).toBeVisible();
      |                                ^ Error: expect(locator).toBeVisible() failed
  482 |   await promotionSheet.getByRole("checkbox").check();
  483 |   await promotionSheet.getByRole("textbox").fill("Approved during policy E2E validation");
  484 |   await promotionSheet.getByRole("button", { name: "Confirm & Promote" }).click();
  485 | }
  486 | 
  487 | 
  488 | test("Flow A: MSP creates, simulates, promotes, assigns policy", async ({ page }) => {
  489 |   await installPolicyApiMocks(page, "msp_partner");
  490 |   await page.goto("/");
  491 | 
  492 |   await page.getByRole("button", { name: "Policies" }).click();
  493 |   await page.getByRole("button", { name: /Add policy/i }).click();
  494 |   await page.locator("label.policyNameField input").fill("Flow A Policy");
  495 |   await page.getByRole("button", { name: "Save" }).click();
  496 |   await expect(page.getByText(/Created draft/i)).toBeVisible();
  497 | 
  498 |   await page.getByRole("button", { name: "Aetherix modules" }).click();
  499 |   await page.getByRole("button", { name: "Simulate selected" }).click();
  500 |   await expect(page.getByText(/Simulation complete:/i)).toBeVisible();
  501 | 
  502 |   await page.getByRole("button", { name: "Promote selected" }).click();
  503 |   await approvePromotion(page);
  504 |   await expect(page.getByText("Policy promoted successfully.")).toBeVisible();
  505 | 
  506 |   await page.getByRole("button", { name: "Assign selected" }).click();
  507 |   const assignDialog = page.getByRole("dialog", { name: "Assign policy" });
  508 |   await expect(assignDialog).toBeVisible();
  509 |   await assignDialog.getByLabel("Company").selectOption("customer-1");
  510 |   await page.getByRole("button", { name: "Assign policy" }).click();
  511 |   await expect(page.getByText("Policy assigned successfully.")).toBeVisible();
  512 | });
  513 | 
  514 | 
  515 | test("Flow B: Company Admin creates group override and preview resolves inheritance", async ({ page }) => {
  516 |   await installPolicyApiMocks(page, "company_admin");
  517 |   await page.goto("/");
  518 | 
  519 |   await page.getByRole("button", { name: "Policies" }).click();
  520 |   await page.getByRole("button", { name: /Add policy/i }).click();
  521 |   await page.locator("label.policyNameField input").fill("Flow B Group Override");
  522 |   await page.getByRole("button", { name: "Aetherix modules" }).click();
  523 |   await page.getByLabel("Parent policy").selectOption("policy-1");
  524 | 
  525 |   await page.getByRole("button", { name: "Save" }).click();
  526 |   await page.getByRole("button", { name: "Simulate selected" }).click();
  527 |   await page.getByRole("button", { name: "Promote selected" }).click();
  528 |   await approvePromotion(page);
  529 | 
  530 |   await page.getByRole("button", { name: "Assign selected" }).click();
  531 |   const assignDialog = page.getByRole("dialog", { name: "Assign policy" });
  532 |   await expect(assignDialog).toBeVisible();
  533 |   await page.getByRole("button", { name: "group" }).click();
  534 |   await assignDialog.getByLabel("Company").selectOption("customer-1");
  535 |   await assignDialog.getByLabel("Group").selectOption("group-1");
  536 |   await page.getByRole("button", { name: "Assign policy" }).click();
  537 |   await expect(page.getByText("Policy assigned successfully.")).toBeVisible();
  538 | });
  539 | 
  540 | 
  541 | test("Flow C: Agent fetch includes semantic/genai modules and entitlement filtering", async ({ page }) => {
  542 |   await installPolicyApiMocks(page, "msp_partner");
  543 |   await page.goto("/");
  544 | 
  545 |   await page.getByRole("button", { name: "Policies" }).click();
  546 |   await page.getByRole("button", { name: "Inherited Base" }).click();
  547 |   await page.getByRole("button", { name: "Aetherix modules" }).click();
  548 |   await page.getByRole("button", { name: "Assign selected" }).click();
  549 |   const assignDialog = page.getByRole("dialog", { name: "Assign policy" });
  550 |   await expect(assignDialog).toBeVisible();
  551 |   await assignDialog.getByRole("button", { name: /^endpoint$/i }).click();
  552 |   await assignDialog.locator("label").filter({ hasText: "Endpoint" }).locator("select").selectOption("endpoint-1");
  553 |   await page.getByRole("button", { name: "Assign policy" }).click();
  554 |   await expect(page.getByText("Policy assigned successfully.")).toBeVisible();
  555 | 
  556 |   const body = await page.evaluate(async () => {
  557 |     const res = await fetch("http://127.0.0.1:8000/agent/policy?endpoint_id=endpoint-1&token=agent-token");
  558 |     if (!res.ok) {
  559 |       throw new Error(`agent fetch failed with ${res.status}`);
  560 |     }
  561 |     return res.json();
  562 |   });
  563 |   expect(body.resolved_policy.modules.semantic_dlp.enabled).toBeTruthy();
  564 |   expect(body.resolved_policy.modules.genai_guardrails.enabled).toBeTruthy();
  565 |   expect(body.resolved_policy.modules.digital_risk_protection.locked).toBeTruthy();
  566 | });
  567 | 
  568 | 
  569 | test("Flow D: Destructive gate rejects promotion before simulation, then accepts with approval", async ({ page }) => {
  570 |   await installPolicyApiMocks(page, "msp_partner");
  571 |   await page.goto("/");
  572 | 
  573 |   const deniedStatus = await page.evaluate(async () => {
  574 |     const denied = await fetch("http://127.0.0.1:8000/policies/policy-1/promote", {
  575 |       method: "POST",
  576 |       headers: { "content-type": "application/json" },
  577 |       body: JSON.stringify({
  578 |         simulation_id: "missing-simulation",
  579 |         operator_approved: true,
  580 |         approval_reason: "manual",
  581 |       }),
```