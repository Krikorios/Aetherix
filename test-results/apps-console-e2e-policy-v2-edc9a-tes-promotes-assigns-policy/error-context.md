# Instructions

- Following Playwright test failed.
- Explain why, be concise, respect Playwright best practices.
- Provide a snippet of code with the fix, if possible.

# Test info

- Name: apps/console/e2e/policy-v2-critical-flows.spec.ts >> Flow A: MSP creates, simulates, promotes, assigns policy
- Location: apps/console/e2e/policy-v2-critical-flows.spec.ts:488:1

# Error details

```
Error: page.goto: Protocol error (Page.navigate): Cannot navigate to invalid URL
Call log:
  - navigating to "/", waiting until "load"

```

# Test source

```ts
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
  481 |   await expect(promotionSheet).toBeVisible();
  482 |   await promotionSheet.getByRole("checkbox").check();
  483 |   await promotionSheet.getByRole("textbox").fill("Approved during policy E2E validation");
  484 |   await promotionSheet.getByRole("button", { name: "Confirm & Promote" }).click();
  485 | }
  486 | 
  487 | 
  488 | test("Flow A: MSP creates, simulates, promotes, assigns policy", async ({ page }) => {
  489 |   await installPolicyApiMocks(page, "msp_partner");
> 490 |   await page.goto("/");
      |              ^ Error: page.goto: Protocol error (Page.navigate): Cannot navigate to invalid URL
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
  582 |     });
  583 |     return denied.status;
  584 |   });
  585 |   expect(deniedStatus).toBe(400);
  586 | 
  587 |   await page.getByRole("button", { name: "Policies" }).click();
  588 |   await page.getByRole("button", { name: "Inherited Base" }).click();
  589 |   await page.getByRole("button", { name: "Aetherix modules" }).click();
  590 |   await page.getByRole("button", { name: "Simulate selected" }).click();
```