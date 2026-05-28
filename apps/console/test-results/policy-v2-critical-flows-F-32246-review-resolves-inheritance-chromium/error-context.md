# Instructions

- Following Playwright test failed.
- Explain why, be concise, respect Playwright best practices.
- Provide a snippet of code with the fix, if possible.

# Test info

- Name: policy-v2-critical-flows.spec.ts >> Flow B: Company Admin creates group override and preview resolves inheritance
- Location: e2e/policy-v2-critical-flows.spec.ts:716:1

# Error details

```
Test timeout of 30000ms exceeded.
```

```
Error: locator.selectOption: Test timeout of 30000ms exceeded.
Call log:
  - waiting for getByLabel('Parent policy')
    - locator resolved to <select>…</select>
  - attempting select option action
    2 × waiting for element to be visible and enabled
      - did not find some options
    - retrying select option action
    - waiting 20ms
    2 × waiting for element to be visible and enabled
      - did not find some options
    - retrying select option action
      - waiting 100ms
    56 × waiting for element to be visible and enabled
       - did not find some options
     - retrying select option action
       - waiting 500ms

```

# Page snapshot

```yaml
- main [ref=e3]:
  - complementary "Primary navigation" [ref=e4]:
    - generic [ref=e5]:
      - img [ref=e6]
      - generic [ref=e9]:
        - strong [ref=e10]: Aetherix
        - generic [ref=e11]: MSP Console
      - button "Collapse navigation" [ref=e12] [cursor=pointer]:
        - img [ref=e13]
    - navigation "OVERVIEW" [ref=e15]:
      - button "OVERVIEW" [expanded] [ref=e16] [cursor=pointer]:
        - generic [ref=e17]: OVERVIEW
        - img [ref=e18]
      - generic [ref=e20]:
        - button "Dashboard" [ref=e21] [cursor=pointer]:
          - img [ref=e22]
          - generic [ref=e27]: Dashboard
        - button "Executive Summary" [ref=e28] [cursor=pointer]:
          - img [ref=e29]
          - generic [ref=e31]: Executive Summary
        - button "Health & Attack Surface" [ref=e32] [cursor=pointer]:
          - img [ref=e33]
          - generic [ref=e35]: Health & Attack Surface
    - navigation "INCIDENTS & RESPONSE" [ref=e36]:
      - button "INCIDENTS & RESPONSE" [expanded] [ref=e37] [cursor=pointer]:
        - generic [ref=e38]: INCIDENTS & RESPONSE
        - img [ref=e39]
      - generic [ref=e41]:
        - button "Alerts" [ref=e42] [cursor=pointer]:
          - img [ref=e43]
          - generic [ref=e46]: Alerts
        - button "Search" [ref=e47] [cursor=pointer]:
          - img [ref=e48]
          - generic [ref=e51]: Search
        - button "Blocklist" [ref=e52] [cursor=pointer]:
          - img [ref=e53]
          - generic [ref=e56]: Blocklist
        - button "Custom Rules" [ref=e57] [cursor=pointer]:
          - img [ref=e58]
          - generic [ref=e61]: Custom Rules
        - button "Threats Xplorer" [ref=e62] [cursor=pointer]:
          - img [ref=e63]
          - generic [ref=e67]: Threats Xplorer
    - navigation "PROTECTION" [ref=e68]:
      - button "PROTECTION" [expanded] [ref=e69] [cursor=pointer]:
        - generic [ref=e70]: PROTECTION
        - img [ref=e71]
      - generic [ref=e73]:
        - button "Policies" [ref=e74] [cursor=pointer]:
          - img [ref=e75]
          - generic [ref=e78]: Policies
        - button "Policy Assignments" [ref=e79] [cursor=pointer]:
          - img [ref=e80]
          - generic [ref=e84]: Policy Assignments
        - button "Antimalware & Behavior" [ref=e85] [cursor=pointer]:
          - img [ref=e86]
          - generic [ref=e95]: Antimalware & Behavior
        - button "Web & Email Protection" [ref=e96] [cursor=pointer]:
          - img [ref=e97]
          - generic [ref=e100]: Web & Email Protection
        - button "Device Control" [ref=e101] [cursor=pointer]:
          - img [ref=e102]
          - generic [ref=e110]: Device Control
    - navigation "RISK & EXTERNAL" [ref=e111]:
      - button "RISK & EXTERNAL" [expanded] [ref=e112] [cursor=pointer]:
        - generic [ref=e113]: RISK & EXTERNAL
        - img [ref=e114]
      - generic [ref=e116]:
        - button "Risk Management" [ref=e117] [cursor=pointer]:
          - img [ref=e118]
          - generic [ref=e120]: Risk Management
        - button "Digital Risk (DRP)" [ref=e121] [cursor=pointer]:
          - img [ref=e122]
          - generic [ref=e125]: Digital Risk (DRP)
        - button "External Attack Surface (EASM)" [ref=e126] [cursor=pointer]:
          - img [ref=e127]
          - generic [ref=e132]: External Attack Surface (EASM)
        - button "Reports" [ref=e133] [cursor=pointer]:
          - img [ref=e134]
          - generic [ref=e137]: Reports
        - button "Compliance Center" [ref=e138] [cursor=pointer]:
          - img [ref=e139]
          - generic [ref=e143]: Compliance Center
    - navigation "MSP CONTROL" [ref=e144]:
      - button "MSP CONTROL" [expanded] [ref=e145] [cursor=pointer]:
        - generic [ref=e146]: MSP CONTROL
        - img [ref=e147]
      - generic [ref=e149]:
        - button "Network" [ref=e150] [cursor=pointer]:
          - img [ref=e151]
          - generic [ref=e156]: Network
        - button "Companies" [ref=e157] [cursor=pointer]:
          - img [ref=e158]
          - generic [ref=e162]: Companies
        - button "Queue" [ref=e163] [cursor=pointer]:
          - img [ref=e164]
          - generic [ref=e167]: Queue
    - navigation "ADD-ONS & INTEGRATIONS" [ref=e168]:
      - button "ADD-ONS & INTEGRATIONS" [expanded] [ref=e169] [cursor=pointer]:
        - generic [ref=e170]: ADD-ONS & INTEGRATIONS
        - img [ref=e171]
      - generic [ref=e173]:
        - button "Sandbox Analyzer" [ref=e174] [cursor=pointer]:
          - img [ref=e175]
          - generic [ref=e177]: Sandbox Analyzer
        - button "Email Security" [ref=e178] [cursor=pointer]:
          - img [ref=e179]
          - generic [ref=e182]: Email Security
        - button "Mobile Security" [ref=e183] [cursor=pointer]:
          - img [ref=e184]
          - generic [ref=e186]: Mobile Security
        - button "Data Insights" [ref=e187] [cursor=pointer]:
          - img [ref=e188]
          - generic [ref=e189]: Data Insights
    - generic [ref=e190]:
      - generic [ref=e191]: Signed in as
      - strong [ref=e192]: Company Admin
      - code [ref=e193]: admin@acme.test
      - emphasis [ref=e194]: Company Administrator
      - button "Sign out" [ref=e196] [cursor=pointer]:
        - img [ref=e197]
        - text: Sign out
  - generic [ref=e201]:
    - generic [ref=e202]:
      - button "Back to Policies" [ref=e203] [cursor=pointer]:
        - img [ref=e204]
        - text: Back to Policies
      - heading "Create New Policy" [level=1] [ref=e206]
    - generic [ref=e207]:
      - generic [ref=e208]:
        - generic [ref=e209]:
          - text: Policy Name *
          - textbox "Policy Name *" [active] [ref=e210]:
            - /placeholder: Enter policy name
            - text: Flow B Group Override
        - generic [ref=e211]:
          - text: Company Scope
          - combobox "Company Scope" [ref=e212]:
            - option "Global / Partner-level" [selected]
            - option "Acme Co"
        - generic [ref=e213]:
          - text: Parent Policy
          - combobox "Parent Policy" [ref=e214]:
            - option "None (Standalone)" [selected]
        - generic [ref=e215]:
          - text: Inheritance Mode
          - combobox "Inheritance Mode" [ref=e216]:
            - option "Inherit with overrides" [selected]
            - option "Replace (no inheritance)"
      - heading "Modules" [level=2] [ref=e217]
      - generic [ref=e218]:
        - article [ref=e219]:
          - button "General (general)" [ref=e220] [cursor=pointer]:
            - generic [ref=e221]:
              - strong [ref=e222]: General
              - generic [ref=e223]: (general)
            - img [ref=e225]
          - generic [ref=e228]:
            - generic [ref=e229]:
              - checkbox "Enabled" [checked] [ref=e230]
              - text: Enabled
            - generic [ref=e231]:
              - text: Update channel
              - combobox "Update channel" [ref=e232]:
                - option "stable" [selected]
                - option "slow"
                - option "fast"
        - article [ref=e233]:
          - button "Tenant Scope (tenant_scope)" [ref=e234] [cursor=pointer]:
            - generic [ref=e235]:
              - strong [ref=e236]: Tenant Scope
              - generic [ref=e237]: (tenant_scope)
            - img [ref=e239]
        - article [ref=e241]:
          - button "Entitlements (entitlements)" [ref=e242] [cursor=pointer]:
            - generic [ref=e243]:
              - strong [ref=e244]: Entitlements
              - generic [ref=e245]: (entitlements)
            - img [ref=e247]
        - article [ref=e249]:
          - button "Deployment Profile (deployment_profile)" [ref=e250] [cursor=pointer]:
            - generic [ref=e251]:
              - strong [ref=e252]: Deployment Profile
              - generic [ref=e253]: (deployment_profile)
            - img [ref=e255]
        - article [ref=e257]:
          - button "Antimalware (antimalware)" [ref=e258] [cursor=pointer]:
            - generic [ref=e259]:
              - strong [ref=e260]: Antimalware
              - generic [ref=e261]: (antimalware)
            - img [ref=e263]
          - generic [ref=e266]:
            - generic [ref=e267]:
              - checkbox "Enabled" [ref=e268]
              - text: Enabled
            - generic [ref=e269]:
              - text: Response action
              - combobox "Response action" [ref=e270]:
                - option "allow" [selected]
                - option "review"
                - option "block"
        - article [ref=e271]:
          - button "Behavior Monitoring (behavior_monitoring)" [ref=e272] [cursor=pointer]:
            - generic [ref=e273]:
              - strong [ref=e274]: Behavior Monitoring
              - generic [ref=e275]: (behavior_monitoring)
            - img [ref=e277]
        - article [ref=e279]:
          - button "Anti Exploit (anti_exploit)" [ref=e280] [cursor=pointer]:
            - generic [ref=e281]:
              - strong [ref=e282]: Anti Exploit
              - generic [ref=e283]: (anti_exploit)
            - img [ref=e285]
        - article [ref=e287]:
          - button "Ransomware Mitigation (ransomware_mitigation)" [ref=e288] [cursor=pointer]:
            - generic [ref=e289]:
              - strong [ref=e290]: Ransomware Mitigation
              - generic [ref=e291]: (ransomware_mitigation)
            - img [ref=e293]
        - article [ref=e295]:
          - button "Firewall (firewall)" [ref=e296] [cursor=pointer]:
            - generic [ref=e297]:
              - strong [ref=e298]: Firewall
              - generic [ref=e299]: (firewall)
            - img [ref=e301]
        - article [ref=e303]:
          - button "Network Protection (network_protection)" [ref=e304] [cursor=pointer]:
            - generic [ref=e305]:
              - strong [ref=e306]: Network Protection
              - generic [ref=e307]: (network_protection)
            - img [ref=e309]
        - article [ref=e311]:
          - button "Web Protection (web_protection)" [ref=e312] [cursor=pointer]:
            - generic [ref=e313]:
              - strong [ref=e314]: Web Protection
              - generic [ref=e315]: (web_protection)
            - img [ref=e317]
        - article [ref=e319]:
          - button "Classification & Labeling (classification_labeling)" [ref=e320] [cursor=pointer]:
            - generic [ref=e321]:
              - strong [ref=e322]: Classification & Labeling
              - generic [ref=e323]: (classification_labeling)
            - img [ref=e325]
        - article [ref=e327]:
          - button "Semantic DLP (semantic_dlp)" [ref=e328] [cursor=pointer]:
            - generic [ref=e329]:
              - strong [ref=e330]: Semantic DLP
              - generic [ref=e331]: (semantic_dlp)
            - img [ref=e333]
          - generic [ref=e336]:
            - generic [ref=e337]:
              - checkbox "Enabled" [ref=e338]
              - text: Enabled
            - generic [ref=e339]:
              - text: Sensitivity labels (comma-separated)
              - textbox "Sensitivity labels (comma-separated)" [ref=e340]
            - generic [ref=e341]:
              - text: GenAI destinations (comma-separated)
              - textbox "GenAI destinations (comma-separated)" [ref=e342]
            - generic [ref=e343]:
              - text: Paste sensitive action
              - combobox "Paste sensitive action" [ref=e344]:
                - option "allow" [selected]
                - option "review"
                - option "block"
            - generic [ref=e345]:
              - text: Upload restricted action
              - combobox "Upload restricted action" [ref=e346]:
                - option "allow" [selected]
                - option "review"
                - option "block"
            - generic [ref=e347]:
              - text: Copy to GenAI action
              - combobox "Copy to GenAI action" [ref=e348]:
                - option "allow" [selected]
                - option "review"
                - option "block"
            - generic [ref=e349]:
              - checkbox "Use Presidio detector" [ref=e350]
              - text: Use Presidio detector
            - generic [ref=e351]:
              - checkbox "Use LLM semantic detector" [ref=e352]
              - text: Use LLM semantic detector
            - generic [ref=e353]:
              - text: Custom classifiers (comma-separated)
              - textbox "Custom classifiers (comma-separated)" [ref=e354]
        - article [ref=e355]:
          - button "GenAI Guardrails (genai_guardrails)" [ref=e356] [cursor=pointer]:
            - generic [ref=e357]:
              - strong [ref=e358]: GenAI Guardrails
              - generic [ref=e359]: (genai_guardrails)
            - img [ref=e361]
        - article [ref=e363]:
          - button "Device Control (device_control)" [ref=e364] [cursor=pointer]:
            - generic [ref=e365]:
              - strong [ref=e366]: Device Control
              - generic [ref=e367]: (device_control)
            - img [ref=e369]
        - article [ref=e371]:
          - button "Sandbox Analyzer (sandbox_analyzer)" [ref=e372] [cursor=pointer]:
            - generic [ref=e373]:
              - strong [ref=e374]: Sandbox Analyzer
              - generic [ref=e375]: (sandbox_analyzer)
            - img [ref=e377]
        - article [ref=e379]:
          - button "Patch Management (patch_management)" [ref=e380] [cursor=pointer]:
            - generic [ref=e381]:
              - strong [ref=e382]: Patch Management
              - generic [ref=e383]: (patch_management)
            - img [ref=e385]
        - article [ref=e387]:
          - button "SIEM / HIDS (siem_hids)" [ref=e388] [cursor=pointer]:
            - generic [ref=e389]:
              - strong [ref=e390]: SIEM / HIDS
              - generic [ref=e391]: (siem_hids)
            - img [ref=e393]
        - article [ref=e395]:
          - button "Integrity Monitoring (integrity_monitoring)" [ref=e396] [cursor=pointer]:
            - generic [ref=e397]:
              - strong [ref=e398]: Integrity Monitoring
              - generic [ref=e399]: (integrity_monitoring)
            - img [ref=e401]
        - article [ref=e403]:
          - button "Vulnerability Inventory (vulnerability_inventory)" [ref=e404] [cursor=pointer]:
            - generic [ref=e405]:
              - strong [ref=e406]: Vulnerability Inventory
              - generic [ref=e407]: (vulnerability_inventory)
            - img [ref=e409]
        - article [ref=e411]:
          - button "Digital Risk Protection (digital_risk_protection)" [ref=e412] [cursor=pointer]:
            - generic [ref=e413]:
              - strong [ref=e414]: Digital Risk Protection
              - generic [ref=e415]: (digital_risk_protection)
            - img [ref=e417]
        - article [ref=e419]:
          - button "External Attack Surface Management (external_attack_surface_management)" [ref=e420] [cursor=pointer]:
            - generic [ref=e421]:
              - strong [ref=e422]: External Attack Surface Management
              - generic [ref=e423]: (external_attack_surface_management)
            - img [ref=e425]
        - article [ref=e427]:
          - button "Threat Intelligence (threat_intelligence)" [ref=e428] [cursor=pointer]:
            - generic [ref=e429]:
              - strong [ref=e430]: Threat Intelligence
              - generic [ref=e431]: (threat_intelligence)
            - img [ref=e433]
        - article [ref=e435]:
          - button "Takedown Workflows (takedown_workflows)" [ref=e436] [cursor=pointer]:
            - generic [ref=e437]:
              - strong [ref=e438]: Takedown Workflows
              - generic [ref=e439]: (takedown_workflows)
            - img [ref=e441]
        - article [ref=e443]:
          - button "Incident Correlation (incident_correlation)" [ref=e444] [cursor=pointer]:
            - generic [ref=e445]:
              - strong [ref=e446]: Incident Correlation
              - generic [ref=e447]: (incident_correlation)
            - img [ref=e449]
        - article [ref=e451]:
          - button "Agentic Response (agentic_response)" [ref=e452] [cursor=pointer]:
            - generic [ref=e453]:
              - strong [ref=e454]: Agentic Response
              - generic [ref=e455]: (agentic_response)
            - img [ref=e457]
        - article [ref=e459]:
          - button "AI Settings (ai_settings)" [ref=e460] [cursor=pointer]:
            - generic [ref=e461]:
              - strong [ref=e462]: AI Settings
              - generic [ref=e463]: (ai_settings)
            - img [ref=e465]
        - article [ref=e467]:
          - button "AI Reports (ai_reports)" [ref=e468] [cursor=pointer]:
            - generic [ref=e469]:
              - strong [ref=e470]: AI Reports
              - generic [ref=e471]: (ai_reports)
            - img [ref=e473]
        - article [ref=e475]:
          - button "Compliance Evidence (compliance_evidence)" [ref=e476] [cursor=pointer]:
            - generic [ref=e477]:
              - strong [ref=e478]: Compliance Evidence
              - generic [ref=e479]: (compliance_evidence)
            - img [ref=e481]
        - article [ref=e483]:
          - button "Integrations (integrations)" [ref=e484] [cursor=pointer]:
            - generic [ref=e485]:
              - strong [ref=e486]: Integrations
              - generic [ref=e487]: (integrations)
            - img [ref=e489]
        - article [ref=e491]:
          - button "Platform Observability (platform_observability)" [ref=e492] [cursor=pointer]:
            - generic [ref=e493]:
              - strong [ref=e494]: Platform Observability
              - generic [ref=e495]: (platform_observability)
            - img [ref=e497]
        - article [ref=e499]:
          - button "White Label (white_label)" [ref=e500] [cursor=pointer]:
            - generic [ref=e501]:
              - strong [ref=e502]: White Label
              - generic [ref=e503]: (white_label)
            - img [ref=e505]
      - generic [ref=e507]:
        - generic [ref=e508]:
          - button "Create & Save Policy" [ref=e509] [cursor=pointer]
          - button "Run Simulation & Impact Analysis" [ref=e510]
          - button "Simulate Promotion" [ref=e511] [cursor=pointer]
        - paragraph [ref=e512]: This dedicated editor will support live simulation, destructive action warnings, inheritance previews, and direct promotion — all without leaving the powerful editing experience.
```

# Test source

```ts
  623 |           agent_version: "0.1.0",
  624 |         },
  625 |       ]);
  626 |       return;
  627 |     }
  628 | 
  629 |     if (apiPath === "/subscriptions" && method === "GET") {
  630 |       await fulfill(route, [{ id: "sub-1", sku: "core", core_features: [] }]);
  631 |       return;
  632 |     }
  633 | 
  634 |     if (apiPath === "/customers/customer-1/groups" && method === "GET") {
  635 |       await fulfill(route, [{ id: "group-1", customer_id: "customer-1", name: "Engineering", created_at: "2026-05-23T00:00:00Z" }]);
  636 |       return;
  637 |     }
  638 | 
  639 |     if (apiPath === "/agent/policy" && method === "GET") {
  640 |       await fulfill(route, {
  641 |         endpoint_id: url.searchParams.get("endpoint_id"),
  642 |         policy_version_hash: "hash",
  643 |         resolved_policy: {
  644 |           schema_version: "2.0",
  645 |           name: "Agent effective",
  646 |           scope: { partner_id: "partner-1", customer_id: "customer-1", group_id: "group-1", endpoint_id: "endpoint-1" },
  647 |           lineage: { parent_policy_id: null, inheritance_mode: "inherit_with_overrides" },
  648 |           modules: {
  649 |             semantic_dlp: { enabled: true },
  650 |             genai_guardrails: { enabled: true },
  651 |             digital_risk_protection: { enabled: false, locked: true },
  652 |           },
  653 |           white_label_names: {},
  654 |         },
  655 |         evidence_controls: ["iso27001-2022:A.8.16"],
  656 |       });
  657 |       return;
  658 |     }
  659 | 
  660 |     if (method === "GET" && (await fulfillSafeReadFallback(route, apiPath))) {
  661 |       return;
  662 |     }
  663 | 
  664 |     if (method === "GET" && !STRICT_READ_ROOTS.has(apiRoot(apiPath))) {
  665 |       await fulfill(route, []);
  666 |       return;
  667 |     }
  668 | 
  669 |     await fulfill(route, { detail: `Unhandled mock route ${method} ${apiPath}` }, 404);
  670 |   });
  671 | 
  672 |   await page.addInitScript(() => {
  673 |     window.localStorage.setItem(
  674 |       "aetherix.access_token",
  675 |       "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhY2NvdW50LTEiLCJleHAiOjQxMDI0NDQ4MDB9.sig",
  676 |     );
  677 |   });
  678 | }
  679 | 
  680 | 
  681 | async function approvePromotion(page: Page) {
  682 |   const promotionSheet = page.getByRole("dialog", { name: "Production Promotion gate" });
  683 |   await expect(promotionSheet).toBeVisible();
  684 |   await promotionSheet.getByRole("checkbox").check();
  685 |   await promotionSheet.getByRole("textbox").fill("Approved during policy E2E validation");
  686 |   await promotionSheet.getByRole("button", { name: "Confirm & Promote" }).click();
  687 | }
  688 | 
  689 | 
  690 | test("Flow A: MSP creates, simulates, promotes, assigns policy", async ({ page }) => {
  691 |   await installPolicyApiMocks(page, "msp_partner");
  692 |   await page.goto("/?harness=true&role=msp_partner&page=policies");
  693 | 
  694 |   await page.getByRole("button", { name: /Add policy/i }).click();
  695 |   await fillPolicyNameField(page, "Flow A Policy");
  696 |   await page.getByRole("button", { name: "Save" }).click();
  697 |   await expect(page.getByText(/created successfully/i)).toBeVisible();
  698 | 
  699 |   await openModulesPanelIfPresent(page);
  700 |   await page.getByRole("button", { name: "Simulate selected" }).click();
  701 |   await expect(page.getByText(/Simulation complete:/i)).toBeVisible();
  702 | 
  703 |   await page.getByRole("button", { name: "Promote selected" }).click();
  704 |   await approvePromotion(page);
  705 |   await expect(page.getByText("Policy promoted successfully.")).toBeVisible();
  706 | 
  707 |   await page.getByRole("button", { name: "Assign selected" }).click();
  708 |   const assignDialog = page.getByRole("dialog", { name: "Assign policy" });
  709 |   await expect(assignDialog).toBeVisible();
  710 |   await assignDialog.getByLabel("Company").selectOption("customer-1");
  711 |   await page.getByRole("button", { name: "Assign policy" }).click();
  712 |   await expect(page.getByText("Policy assigned successfully.")).toBeVisible();
  713 | });
  714 | 
  715 | 
  716 | test("Flow B: Company Admin creates group override and preview resolves inheritance", async ({ page }) => {
  717 |   await installPolicyApiMocks(page, "company_admin");
  718 |   await page.goto("/?harness=true&role=company_admin&page=policies");
  719 | 
  720 |   await page.getByRole("button", { name: /Add policy/i }).click();
  721 |   await fillPolicyNameField(page, "Flow B Group Override");
  722 |   await openModulesPanelIfPresent(page);
> 723 |   await page.getByLabel("Parent policy").selectOption("policy-1");
      |                                          ^ Error: locator.selectOption: Test timeout of 30000ms exceeded.
  724 | 
  725 |   await page.getByRole("button", { name: "Save" }).click();
  726 |   await page.getByRole("button", { name: "Simulate selected" }).click();
  727 |   await page.getByRole("button", { name: "Promote selected" }).click();
  728 |   await approvePromotion(page);
  729 | 
  730 |   await page.getByRole("button", { name: "Assign selected" }).click();
  731 |   const assignDialog = page.getByRole("dialog", { name: "Assign policy" });
  732 |   await expect(assignDialog).toBeVisible();
  733 |   await page.getByRole("button", { name: "group" }).click();
  734 |   await assignDialog.getByLabel("Company").selectOption("customer-1");
  735 |   await assignDialog.getByLabel("Group").selectOption("group-1");
  736 |   await page.getByRole("button", { name: "Assign policy" }).click();
  737 |   await expect(page.getByText("Policy assigned successfully.")).toBeVisible();
  738 | });
  739 | 
  740 | 
  741 | test("Flow C: Agent fetch includes semantic/genai modules and entitlement filtering", async ({ page }) => {
  742 |   await installPolicyApiMocks(page, "msp_partner");
  743 |   await page.goto("/?harness=true&role=msp_partner&page=policies");
  744 | 
  745 |   await page.getByRole("button", { name: "Inherited Base" }).click();
  746 |   await openModulesPanelIfPresent(page);
  747 |   await page.getByRole("button", { name: "Assign selected" }).click();
  748 |   const assignDialog = page.getByRole("dialog", { name: "Assign policy" });
  749 |   await expect(assignDialog).toBeVisible();
  750 |   await assignDialog.getByRole("button", { name: /^endpoint$/i }).click();
  751 |   await assignDialog.locator("label").filter({ hasText: "Endpoint" }).locator("select").selectOption("endpoint-1");
  752 |   await page.getByRole("button", { name: "Assign policy" }).click();
  753 |   await expect(page.getByText("Policy assigned successfully.")).toBeVisible();
  754 | 
  755 |   const body = await page.evaluate(async () => {
  756 |     const res = await fetch("http://127.0.0.1:8000/agent/policy?endpoint_id=endpoint-1&token=agent-token");
  757 |     if (!res.ok) {
  758 |       throw new Error(`agent fetch failed with ${res.status}`);
  759 |     }
  760 |     return res.json();
  761 |   });
  762 |   expect(body.resolved_policy.modules.semantic_dlp.enabled).toBeTruthy();
  763 |   expect(body.resolved_policy.modules.genai_guardrails.enabled).toBeTruthy();
  764 |   expect(body.resolved_policy.modules.digital_risk_protection.locked).toBeTruthy();
  765 | });
  766 | 
  767 | 
  768 | test("Flow D: Destructive gate rejects promotion before simulation, then accepts with approval", async ({ page }) => {
  769 |   await installPolicyApiMocks(page, "msp_partner");
  770 |   await page.goto("/?harness=true&role=msp_partner&page=policies");
  771 | 
  772 |   const deniedStatus = await page.evaluate(async () => {
  773 |     const denied = await fetch("http://127.0.0.1:8000/policies/policy-1/promote", {
  774 |       method: "POST",
  775 |       headers: { "content-type": "application/json" },
  776 |       body: JSON.stringify({
  777 |         simulation_id: "missing-simulation",
  778 |         operator_approved: true,
  779 |         approval_reason: "manual",
  780 |       }),
  781 |     });
  782 |     return denied.status;
  783 |   });
  784 |   expect(deniedStatus).toBe(400);
  785 | 
  786 |   await page.getByRole("button", { name: "Inherited Base" }).click();
  787 |   await openModulesPanelIfPresent(page);
  788 |   await page.getByRole("button", { name: "Simulate selected" }).click();
  789 |   await page.getByRole("button", { name: "Promote selected" }).click();
  790 |   await approvePromotion(page);
  791 |   await expect(page.getByText("Policy promoted successfully.")).toBeVisible();
  792 | });
  793 | 
```