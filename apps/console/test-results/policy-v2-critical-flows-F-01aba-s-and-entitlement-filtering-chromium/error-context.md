# Instructions

- Following Playwright test failed.
- Explain why, be concise, respect Playwright best practices.
- Provide a snippet of code with the fix, if possible.

# Test info

- Name: policy-v2-critical-flows.spec.ts >> Flow C: Agent fetch includes semantic/genai modules and entitlement filtering
- Location: e2e/policy-v2-critical-flows.spec.ts:541:1

# Error details

```
Error: expect(locator).toBeVisible() failed

Locator: getByRole('dialog', { name: 'Assign policy' })
Expected: visible
Timeout: 5000ms
Error: element(s) not found

Call log:
  - Expect "toBeVisible" with timeout 5000ms
  - waiting for getByRole('dialog', { name: 'Assign policy' })

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
      - button "Accounts"
      - button "Installers"
    - navigation "ADD-ONS & INTEGRATIONS":
      - button "ADD-ONS & INTEGRATIONS" [expanded]
      - button "Sandbox Analyzer"
      - button "Email Security"
      - button "Mobile Security"
      - button "Data Insights"
      - button "Integrations"
      - button "Configuration"
    - text: Signed in as
    - strong: MSP Partner
    - code: msp@partner.test
    - emphasis: MSP Partner
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
      - button "Device Control On"
      - button "Integrity Monitoring Off"
      - button "Exchange Protection Off"
      - button "Encryption Off"
      - button "Incidents Sensor On"
      - button "Storage Protection Off"
      - button "Risk Management Off"
      - button "Toggle Risk Management Section"
      - button "Blocklist Off"
      - button "Live Search Off"
      - button "Web, DLP & GenAI 5/7"
      - button "SIEM / HIDS 2/4"
      - button "Agentic Response On"
      - button "Digital Risk & EASM Off"
      - button "Compliance Evidence On"
      - button "Integrations & Branding 2/2"
  - button "Policies"
  - text: /
  - strong: Inherited Base
  - text: / Aetherix /
  - strong: Aetherix modules
  - heading "Inherited Base" [level=1]
  - paragraph: Inherited Base
  - link "Get help from Support Center":
    - /url: https://support.aetherix.local
  - main:
    - region "Policy engine modules":
      - heading "Policy engine modules" [level=2]
      - paragraph: Configure the Aetherix runtime modules, entitlement locks, simulations, promotions, and assignments for this policy.
      - button "Simulate selected"
      - button "Promote selected" [disabled]
      - button "Assign selected"
      - text: Company scope
      - combobox "Company scope":
        - option "Global / Partner-level"
        - option "Acme Co" [selected]
      - text: Parent policy
      - combobox "Parent policy":
        - option "None" [selected]
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
        - checkbox "Enabled" [checked]
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
        - textbox "Custom classifiers (comma-separated)": finance, source_code
      - article:
        - button "GenAI Guardrails genai_guardrails":
          - strong: GenAI Guardrails
          - text: genai_guardrails
      - article:
        - button "Device Control device_control":
          - strong: Device Control
          - text: device_control
      - article:
        - button "Sandbox Analyzer sandbox_analyzer Locked":
          - strong: Sandbox Analyzer
          - text: sandbox_analyzer
          - emphasis: Locked
      - article:
        - button "Patch Management patch_management Locked":
          - strong: Patch Management
          - text: patch_management
          - emphasis: Locked
      - article:
        - button "SIEM / HIDS siem_hids Locked":
          - strong: SIEM / HIDS
          - text: siem_hids
          - emphasis: Locked
      - article:
        - button "Integrity Monitoring integrity_monitoring Locked":
          - strong: Integrity Monitoring
          - text: integrity_monitoring
          - emphasis: Locked
      - article:
        - button "Vulnerability Inventory vulnerability_inventory Locked":
          - strong: Vulnerability Inventory
          - text: vulnerability_inventory
          - emphasis: Locked
      - article:
        - button "Digital Risk Protection digital_risk_protection Locked":
          - strong: Digital Risk Protection
          - text: digital_risk_protection
          - emphasis: Locked
      - article:
        - button "External Attack Surface Management external_attack_surface_management Locked":
          - strong: External Attack Surface Management
          - text: external_attack_surface_management
          - emphasis: Locked
      - article:
        - button "Threat Intelligence threat_intelligence Locked":
          - strong: Threat Intelligence
          - text: threat_intelligence
          - emphasis: Locked
      - article:
        - button "Takedown Workflows takedown_workflows Locked":
          - strong: Takedown Workflows
          - text: takedown_workflows
          - emphasis: Locked
      - article:
        - button "Incident Correlation incident_correlation Locked":
          - strong: Incident Correlation
          - text: incident_correlation
          - emphasis: Locked
      - article:
        - button "Agentic Response agentic_response Locked":
          - strong: Agentic Response
          - text: agentic_response
          - emphasis: Locked
      - article:
        - button "AI Settings ai_settings Locked":
          - strong: AI Settings
          - text: ai_settings
          - emphasis: Locked
      - article:
        - button "AI Reports ai_reports Locked":
          - strong: AI Reports
          - text: ai_reports
          - emphasis: Locked
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
      - paragraph: No active simulation has been run for this draft policy. Run a simulation to verify threat coverage and evaluate approval gates.
  - button "Save"
  - button "Cancel"
```

# Test source

```ts
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
  481 |   await expect(promotionSheet).toBeVisible();
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
> 550 |   await expect(assignDialog).toBeVisible();
      |                              ^ Error: expect(locator).toBeVisible() failed
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
  582 |     });
  583 |     return denied.status;
  584 |   });
  585 |   expect(deniedStatus).toBe(400);
  586 | 
  587 |   await page.getByRole("button", { name: "Policies" }).click();
  588 |   await page.getByRole("button", { name: "Inherited Base" }).click();
  589 |   await page.getByRole("button", { name: "Aetherix modules" }).click();
  590 |   await page.getByRole("button", { name: "Simulate selected" }).click();
  591 |   await page.getByRole("button", { name: "Promote selected" }).click();
  592 |   await approvePromotion(page);
  593 |   await expect(page.getByText("Policy promoted successfully.")).toBeVisible();
  594 | });
  595 | 
```