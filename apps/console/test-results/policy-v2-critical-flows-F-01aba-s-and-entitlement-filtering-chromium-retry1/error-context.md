# Instructions

- Following Playwright test failed.
- Explain why, be concise, respect Playwright best practices.
- Provide a snippet of code with the fix, if possible.

# Test info

- Name: policy-v2-critical-flows.spec.ts >> Flow C: Agent fetch includes semantic/genai modules and entitlement filtering
- Location: e2e/policy-v2-critical-flows.spec.ts:741:1

# Error details

```
Test timeout of 30000ms exceeded.
```

```
Error: locator.click: Test timeout of 30000ms exceeded.
Call log:
  - waiting for getByRole('button', { name: 'Assign selected' })

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
        - button "Accounts" [ref=e163] [cursor=pointer]:
          - img [ref=e164]
          - generic [ref=e169]: Accounts
        - button "Installers" [ref=e170] [cursor=pointer]:
          - img [ref=e171]
          - generic [ref=e175]: Installers
        - button "Queue" [ref=e176] [cursor=pointer]:
          - img [ref=e177]
          - generic [ref=e180]: Queue
    - navigation "ADD-ONS & INTEGRATIONS" [ref=e181]:
      - button "ADD-ONS & INTEGRATIONS" [expanded] [ref=e182] [cursor=pointer]:
        - generic [ref=e183]: ADD-ONS & INTEGRATIONS
        - img [ref=e184]
      - generic [ref=e186]:
        - button "Sandbox Analyzer" [ref=e187] [cursor=pointer]:
          - img [ref=e188]
          - generic [ref=e190]: Sandbox Analyzer
        - button "Email Security" [ref=e191] [cursor=pointer]:
          - img [ref=e192]
          - generic [ref=e195]: Email Security
        - button "Mobile Security" [ref=e196] [cursor=pointer]:
          - img [ref=e197]
          - generic [ref=e199]: Mobile Security
        - button "Data Insights" [ref=e200] [cursor=pointer]:
          - img [ref=e201]
          - generic [ref=e202]: Data Insights
        - button "Integrations" [ref=e203] [cursor=pointer]:
          - img [ref=e204]
          - generic [ref=e206]: Integrations
        - button "Configuration" [ref=e207] [cursor=pointer]:
          - img [ref=e208]
          - generic [ref=e211]: Configuration
    - generic [ref=e212]:
      - generic [ref=e213]: Signed in as
      - strong [ref=e214]: MSP Partner
      - code [ref=e215]: msp@partner.test
      - emphasis [ref=e216]: MSP Partner
      - button "Sign out" [ref=e218] [cursor=pointer]:
        - img [ref=e219]
        - text: Sign out
  - generic [ref=e223]:
    - generic [ref=e224]:
      - button "Back to Policies" [ref=e225] [cursor=pointer]:
        - img [ref=e226]
        - text: Back to Policies
      - heading "Edit Policy" [level=1] [ref=e228]
    - generic [ref=e229]:
      - generic [ref=e230]:
        - generic [ref=e231]:
          - text: Policy Name *
          - textbox "Policy Name *" [ref=e232]:
            - /placeholder: Enter policy name
            - text: Inherited Base
        - generic [ref=e233]:
          - text: Company Scope
          - combobox "Company Scope" [ref=e234]:
            - option "Global / Partner-level"
            - option "Acme Co" [selected]
        - generic [ref=e235]:
          - text: Parent Policy
          - combobox "Parent Policy" [ref=e236]:
            - option "None (Standalone)" [selected]
        - generic [ref=e237]:
          - text: Inheritance Mode
          - combobox "Inheritance Mode" [ref=e238]:
            - option "Inherit with overrides" [selected]
            - option "Replace (no inheritance)"
      - heading "Modules" [level=2] [ref=e239]
      - generic [ref=e240]:
        - article [ref=e241]:
          - button "General (general)" [ref=e242] [cursor=pointer]:
            - generic [ref=e243]:
              - strong [ref=e244]: General
              - generic [ref=e245]: (general)
            - img [ref=e247]
          - generic [ref=e250]:
            - generic [ref=e251]:
              - checkbox "Enabled" [checked] [ref=e252]
              - text: Enabled
            - generic [ref=e253]:
              - text: Update channel
              - combobox "Update channel" [ref=e254]:
                - option "stable" [selected]
                - option "slow"
                - option "fast"
        - article [ref=e255]:
          - button "Tenant Scope (tenant_scope)" [ref=e256] [cursor=pointer]:
            - generic [ref=e257]:
              - strong [ref=e258]: Tenant Scope
              - generic [ref=e259]: (tenant_scope)
            - img [ref=e261]
        - article [ref=e263]:
          - button "Entitlements (entitlements)" [ref=e264] [cursor=pointer]:
            - generic [ref=e265]:
              - strong [ref=e266]: Entitlements
              - generic [ref=e267]: (entitlements)
            - img [ref=e269]
        - article [ref=e271]:
          - button "Deployment Profile (deployment_profile)" [ref=e272] [cursor=pointer]:
            - generic [ref=e273]:
              - strong [ref=e274]: Deployment Profile
              - generic [ref=e275]: (deployment_profile)
            - img [ref=e277]
        - article [ref=e279]:
          - button "Antimalware (antimalware)" [ref=e280] [cursor=pointer]:
            - generic [ref=e281]:
              - strong [ref=e282]: Antimalware
              - generic [ref=e283]: (antimalware)
            - img [ref=e285]
          - generic [ref=e288]:
            - generic [ref=e289]:
              - checkbox "Enabled" [checked] [ref=e290]
              - text: Enabled
            - generic [ref=e291]:
              - text: Response action
              - combobox "Response action" [ref=e292]:
                - option "allow"
                - option "review" [selected]
                - option "block"
        - article [ref=e293]:
          - button "Behavior Monitoring (behavior_monitoring)" [ref=e294] [cursor=pointer]:
            - generic [ref=e295]:
              - strong [ref=e296]: Behavior Monitoring
              - generic [ref=e297]: (behavior_monitoring)
            - img [ref=e299]
        - article [ref=e301]:
          - button "Anti Exploit (anti_exploit)" [ref=e302] [cursor=pointer]:
            - generic [ref=e303]:
              - strong [ref=e304]: Anti Exploit
              - generic [ref=e305]: (anti_exploit)
            - img [ref=e307]
        - article [ref=e309]:
          - button "Ransomware Mitigation (ransomware_mitigation)" [ref=e310] [cursor=pointer]:
            - generic [ref=e311]:
              - strong [ref=e312]: Ransomware Mitigation
              - generic [ref=e313]: (ransomware_mitigation)
            - img [ref=e315]
        - article [ref=e317]:
          - button "Firewall (firewall)" [ref=e318] [cursor=pointer]:
            - generic [ref=e319]:
              - strong [ref=e320]: Firewall
              - generic [ref=e321]: (firewall)
            - img [ref=e323]
        - article [ref=e325]:
          - button "Network Protection (network_protection)" [ref=e326] [cursor=pointer]:
            - generic [ref=e327]:
              - strong [ref=e328]: Network Protection
              - generic [ref=e329]: (network_protection)
            - img [ref=e331]
        - article [ref=e333]:
          - button "Web Protection (web_protection)" [ref=e334] [cursor=pointer]:
            - generic [ref=e335]:
              - strong [ref=e336]: Web Protection
              - generic [ref=e337]: (web_protection)
            - img [ref=e339]
        - article [ref=e341]:
          - button "Classification & Labeling (classification_labeling)" [ref=e342] [cursor=pointer]:
            - generic [ref=e343]:
              - strong [ref=e344]: Classification & Labeling
              - generic [ref=e345]: (classification_labeling)
            - img [ref=e347]
        - article [ref=e349]:
          - button "Semantic DLP (semantic_dlp)" [ref=e350] [cursor=pointer]:
            - generic [ref=e351]:
              - strong [ref=e352]: Semantic DLP
              - generic [ref=e353]: (semantic_dlp)
            - img [ref=e355]
          - generic [ref=e358]:
            - generic [ref=e359]:
              - checkbox "Enabled" [checked] [ref=e360]
              - text: Enabled
            - generic [ref=e361]:
              - text: Sensitivity labels (comma-separated)
              - textbox "Sensitivity labels (comma-separated)" [ref=e362]: Public, Internal, Confidential, Restricted
            - generic [ref=e363]:
              - text: GenAI destinations (comma-separated)
              - textbox "GenAI destinations (comma-separated)" [ref=e364]: copilot, claude, gemini, chatgpt, custom
            - generic [ref=e365]:
              - text: Paste sensitive action
              - combobox "Paste sensitive action" [ref=e366]:
                - option "allow"
                - option "review" [selected]
                - option "block"
            - generic [ref=e367]:
              - text: Upload restricted action
              - combobox "Upload restricted action" [ref=e368]:
                - option "allow"
                - option "review"
                - option "block" [selected]
            - generic [ref=e369]:
              - text: Copy to GenAI action
              - combobox "Copy to GenAI action" [ref=e370]:
                - option "allow"
                - option "review" [selected]
                - option "block"
            - generic [ref=e371]:
              - checkbox "Use Presidio detector" [checked] [ref=e372]
              - text: Use Presidio detector
            - generic [ref=e373]:
              - checkbox "Use LLM semantic detector" [checked] [ref=e374]
              - text: Use LLM semantic detector
            - generic [ref=e375]:
              - text: Custom classifiers (comma-separated)
              - textbox "Custom classifiers (comma-separated)" [ref=e376]: finance, source_code
        - article [ref=e377]:
          - button "GenAI Guardrails (genai_guardrails)" [ref=e378] [cursor=pointer]:
            - generic [ref=e379]:
              - strong [ref=e380]: GenAI Guardrails
              - generic [ref=e381]: (genai_guardrails)
            - img [ref=e383]
        - article [ref=e385]:
          - button "Device Control (device_control)" [ref=e386] [cursor=pointer]:
            - generic [ref=e387]:
              - strong [ref=e388]: Device Control
              - generic [ref=e389]: (device_control)
            - img [ref=e391]
        - article [ref=e393]:
          - button "Sandbox Analyzer (sandbox_analyzer)" [ref=e394] [cursor=pointer]:
            - generic [ref=e395]:
              - strong [ref=e396]: Sandbox Analyzer
              - generic [ref=e397]: (sandbox_analyzer)
            - img [ref=e399]
        - article [ref=e401]:
          - button "Patch Management (patch_management)" [ref=e402] [cursor=pointer]:
            - generic [ref=e403]:
              - strong [ref=e404]: Patch Management
              - generic [ref=e405]: (patch_management)
            - img [ref=e407]
        - article [ref=e409]:
          - button "SIEM / HIDS (siem_hids)" [ref=e410] [cursor=pointer]:
            - generic [ref=e411]:
              - strong [ref=e412]: SIEM / HIDS
              - generic [ref=e413]: (siem_hids)
            - img [ref=e415]
        - article [ref=e417]:
          - button "Integrity Monitoring (integrity_monitoring)" [ref=e418] [cursor=pointer]:
            - generic [ref=e419]:
              - strong [ref=e420]: Integrity Monitoring
              - generic [ref=e421]: (integrity_monitoring)
            - img [ref=e423]
        - article [ref=e425]:
          - button "Vulnerability Inventory (vulnerability_inventory)" [ref=e426] [cursor=pointer]:
            - generic [ref=e427]:
              - strong [ref=e428]: Vulnerability Inventory
              - generic [ref=e429]: (vulnerability_inventory)
            - img [ref=e431]
        - article [ref=e433]:
          - button "Digital Risk Protection (digital_risk_protection)" [ref=e434] [cursor=pointer]:
            - generic [ref=e435]:
              - strong [ref=e436]: Digital Risk Protection
              - generic [ref=e437]: (digital_risk_protection)
            - img [ref=e439]
        - article [ref=e441]:
          - button "External Attack Surface Management (external_attack_surface_management)" [ref=e442] [cursor=pointer]:
            - generic [ref=e443]:
              - strong [ref=e444]: External Attack Surface Management
              - generic [ref=e445]: (external_attack_surface_management)
            - img [ref=e447]
        - article [ref=e449]:
          - button "Threat Intelligence (threat_intelligence)" [ref=e450] [cursor=pointer]:
            - generic [ref=e451]:
              - strong [ref=e452]: Threat Intelligence
              - generic [ref=e453]: (threat_intelligence)
            - img [ref=e455]
        - article [ref=e457]:
          - button "Takedown Workflows (takedown_workflows)" [ref=e458] [cursor=pointer]:
            - generic [ref=e459]:
              - strong [ref=e460]: Takedown Workflows
              - generic [ref=e461]: (takedown_workflows)
            - img [ref=e463]
        - article [ref=e465]:
          - button "Incident Correlation (incident_correlation)" [ref=e466] [cursor=pointer]:
            - generic [ref=e467]:
              - strong [ref=e468]: Incident Correlation
              - generic [ref=e469]: (incident_correlation)
            - img [ref=e471]
        - article [ref=e473]:
          - button "Agentic Response (agentic_response)" [ref=e474] [cursor=pointer]:
            - generic [ref=e475]:
              - strong [ref=e476]: Agentic Response
              - generic [ref=e477]: (agentic_response)
            - img [ref=e479]
        - article [ref=e481]:
          - button "AI Settings (ai_settings)" [ref=e482] [cursor=pointer]:
            - generic [ref=e483]:
              - strong [ref=e484]: AI Settings
              - generic [ref=e485]: (ai_settings)
            - img [ref=e487]
        - article [ref=e489]:
          - button "AI Reports (ai_reports)" [ref=e490] [cursor=pointer]:
            - generic [ref=e491]:
              - strong [ref=e492]: AI Reports
              - generic [ref=e493]: (ai_reports)
            - img [ref=e495]
        - article [ref=e497]:
          - button "Compliance Evidence (compliance_evidence)" [ref=e498] [cursor=pointer]:
            - generic [ref=e499]:
              - strong [ref=e500]: Compliance Evidence
              - generic [ref=e501]: (compliance_evidence)
            - img [ref=e503]
        - article [ref=e505]:
          - button "Integrations (integrations)" [ref=e506] [cursor=pointer]:
            - generic [ref=e507]:
              - strong [ref=e508]: Integrations
              - generic [ref=e509]: (integrations)
            - img [ref=e511]
        - article [ref=e513]:
          - button "Platform Observability (platform_observability)" [ref=e514] [cursor=pointer]:
            - generic [ref=e515]:
              - strong [ref=e516]: Platform Observability
              - generic [ref=e517]: (platform_observability)
            - img [ref=e519]
        - article [ref=e521]:
          - button "White Label (white_label)" [ref=e522] [cursor=pointer]:
            - generic [ref=e523]:
              - strong [ref=e524]: White Label
              - generic [ref=e525]: (white_label)
            - img [ref=e527]
      - generic [ref=e529]:
        - generic [ref=e530]:
          - button "Save Changes" [ref=e531] [cursor=pointer]
          - button "Run Simulation & Impact Analysis" [ref=e532]
          - button "Simulate Promotion" [ref=e533] [cursor=pointer]
        - paragraph [ref=e534]: This dedicated editor will support live simulation, destructive action warnings, inheritance previews, and direct promotion — all without leaving the powerful editing experience.
```

# Test source

```ts
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
  723 |   await page.getByLabel("Parent policy").selectOption("policy-1");
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
> 747 |   await page.getByRole("button", { name: "Assign selected" }).click();
      |                                                               ^ Error: locator.click: Test timeout of 30000ms exceeded.
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