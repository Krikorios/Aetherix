# Instructions

- Following Playwright test failed.
- Explain why, be concise, respect Playwright best practices.
- Provide a snippet of code with the fix, if possible.

# Test info

- Name: policy-v2-critical-flows.spec.ts >> Flow A: MSP creates, simulates, promotes, assigns policy
- Location: e2e/policy-v2-critical-flows.spec.ts:690:1

# Error details

```
Test timeout of 30000ms exceeded.
```

```
Error: locator.click: Test timeout of 30000ms exceeded.
Call log:
  - waiting for getByRole('button', { name: 'Simulate selected' })

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
      - generic [ref=e225]:
        - paragraph [ref=e226]: Protection
        - heading "Policies" [level=1] [ref=e227]
        - generic [ref=e228]: Manage tenant-scoped security policies. Edit opens the dedicated editor so changes reflect directly on assigned agents and endpoints.
      - generic "Policy actions" [ref=e229]:
        - button "Add policy" [ref=e230] [cursor=pointer]:
          - img [ref=e231]
          - text: Add policy
        - button "Refresh" [ref=e232]:
          - img [ref=e233]
          - text: Refresh
    - region "Policies table" [ref=e238]:
      - generic [ref=e239]:
        - generic [ref=e240]: Select policies for bulk actions or assignment
        - generic "Selected policy actions" [ref=e241]:
          - button "Edit policy" [disabled] [ref=e242]
          - button "Assign to agent / network" [disabled] [ref=e243]
          - button "Clone" [disabled] [ref=e244]:
            - img [ref=e245]
            - text: Clone
          - button "Delete" [disabled] [ref=e248]:
            - img [ref=e249]
            - text: Delete
        - button "Columns" [ref=e251] [cursor=pointer]:
          - img [ref=e252]
      - generic [ref=e254]:
        - generic "Select all policies" [ref=e255]:
          - checkbox "Select all policies" [ref=e256]
        - generic [ref=e257]:
          - generic [ref=e258]: Policy name
          - textbox "Filter by policy name" [ref=e259]:
            - /placeholder: Filter by name...
        - generic [ref=e260]:
          - generic [ref=e261]: Status
          - combobox "Filter by status" [ref=e262]:
            - option "All statuses" [selected]
            - option "Draft"
            - option "Simulated"
            - option "Promoted"
            - option "Active"
        - generic [ref=e263]:
          - generic [ref=e264]: Scope
          - combobox "Filter by company" [ref=e265]:
            - option "All scopes" [selected]
            - option "Global / Partner"
            - option "Acme Co"
        - generic [ref=e266]: Last modified
      - generic [ref=e267]:
        - article [ref=e268]:
          - generic "Select Flow A Policy" [ref=e269]:
            - checkbox "Select Flow A Policy" [ref=e270]
          - generic [ref=e271]:
            - button "Flow A Policy" [ref=e272] [cursor=pointer]
            - generic [ref=e273]: v1
          - generic [ref=e274]: draft
          - generic [ref=e275]: Global / Partner
          - time [ref=e276]: May 23, 03:00 AM
        - article [ref=e277]:
          - generic "Select Inherited Base" [ref=e278]:
            - checkbox "Select Inherited Base" [ref=e279]
          - generic [ref=e280]:
            - button "Inherited Base" [ref=e281] [cursor=pointer]
            - generic [ref=e282]: v2
          - generic [ref=e283]: Active
          - strong [ref=e285]: Acme Co
          - time [ref=e286]: May 23, 03:00 AM
      - generic [ref=e287]:
        - generic [ref=e288]:
          - button "First Page" [disabled] [ref=e289]
          - button "Previous page" [disabled] [ref=e290]: <
          - generic [ref=e291]: Page
          - textbox "Current page" [ref=e292]: "1"
          - generic [ref=e293]: of 1
          - button "Next page" [disabled] [ref=e294]: ">"
          - button "Last Page" [disabled] [ref=e295]
          - combobox "Rows per page" [ref=e296]:
            - option "20" [selected]
        - generic [ref=e297]: 2 items
```

# Test source

```ts
  600 |             license: {
  601 |               subscription_sku: "core",
  602 |               addons: ["semantic_dlp"],
  603 |             },
  604 |           },
  605 |         ],
  606 |         total: 1,
  607 |         limit: 250,
  608 |         offset: 0,
  609 |       });
  610 |       return;
  611 |     }
  612 | 
  613 |     if (apiPath === "/endpoints" && method === "GET") {
  614 |       await fulfill(route, [
  615 |         {
  616 |           id: "endpoint-1",
  617 |           hostname: "eng-laptop",
  618 |           os: "macOS",
  619 |           status: "healthy",
  620 |           risk_score: 20,
  621 |           last_seen: "2026-05-23T00:00:00Z",
  622 |           policy_version: "2",
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
> 700 |   await page.getByRole("button", { name: "Simulate selected" }).click();
      |                                                                 ^ Error: locator.click: Test timeout of 30000ms exceeded.
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