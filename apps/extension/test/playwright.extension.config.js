// Playwright config for MV3 extension E2E validation.
// Kept separate from apps/console/playwright.config.ts because extension tests
// require a persistent Chromium context with --load-extension, which is
// incompatible with the standard desktop-chrome project config.
//
// Usage:
//   npx playwright test apps/extension/test/e2e-validation.spec.js \
//     --config apps/extension/test/playwright.extension.config.js
//
// Run in CI (stub mode, no live sites):
//   SKIP_LIVE_SITES=1 npx playwright test ... --config ...

const { defineConfig } = require("@playwright/test");

module.exports = defineConfig({
  testMatch: ["**/e2e-validation.spec.js"],
  // No retries for live-site tests — flakiness should be investigated, not hidden
  retries: 0,
  workers: 1, // Extension context is global; run tests serially
  reporter: [["list"], ["json", { outputFile: "apps/extension/test-results/e2e-report.json" }]],
  timeout: 60000,
  use: {
    // headless: false is set programmatically when launching PersistentContext
    // inside the spec; this config provides reporter/timeout overrides only.
    trace: "retain-on-failure",
    video: "retain-on-failure",
  },
  // No webServer stanza — the spec starts its own bridge stub
});
