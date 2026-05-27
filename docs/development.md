# Aetherix Development Guide

Status: required local workflow for POC development, May 2026.

## Required Local Services

- macOS, Linux, or Windows with WSL.
- Docker for Postgres.
- Node.js 20 or newer.
- Python 3.12+ with `venv` support.
- Rust stable toolchain.

Start Postgres:

```bash
docker compose up -d postgres
```

The default API database URL is:

```text
postgresql://aetherix:aetherix@127.0.0.1:55432/aetherix
```

Tests use:

```text
postgresql://aetherix:aetherix@127.0.0.1:55432/aetherix_test
```

The compose init script creates `aetherix_test` automatically on a fresh volume.

## First-Time Setup

```bash
npm install

cd apps/api
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Running The App

API:

```bash
PYTHONPATH=apps/api apps/api/.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Console:

```bash
npm run dev -- --host 127.0.0.1
```

If Vite reports that `5173` is in use, use the next URL printed by the terminal.

## Validation Commands

Run these before handing off changes:

```bash
cd apps/api && .venv/bin/pytest -q
cd agent && cargo test
npm run build
```

For console-only changes, also run a targeted ESLint check on the files you touched:

```bash
cd apps/console
npx eslint src/App.tsx src/pages/AccountsPage.tsx src/pages/CompaniesPage.tsx
```

The current full console lint command also reports pre-existing `react-hooks/set-state-in-effect` issues in several older pages. Treat those as a separate cleanup unless your change touches the affected page.

For targeted backend work, prefer the smallest relevant suite first, then the full API suite. Examples:

```bash
cd apps/api && .venv/bin/pytest tests/test_customer_deployment.py -q
cd apps/api && .venv/bin/pytest tests/test_enrollment.py -q
cd apps/api && .venv/bin/pytest tests/test_policy_v2.py tests/test_policy_simulation.py -q
cd apps/api && .venv/bin/pytest tests/test_companies_licensing.py tests/test_ai_settings.py -q
```

## Multi-Agent Parallel Development Model

Aetherix is developed using three specialized AI agents working in parallel under a central Task Coordinator. This is the primary execution model for feature development, hardening, and integration work.

- See the full operating rules, roles, interaction protocol, and prompt generation process in [multi-agent-coordination-protocol.md](multi-agent-coordination-protocol.md).
- The Coordinator reviews every agent response and issues synchronized, updated prompts for all three tracks.
- When sending agent outputs for review, provide explicit references to previous work when relevant so the Coordinator can maintain coherence.

This model is designed to accelerate progress while protecting cross-track integration points (especially around ResponseEvidence, autonomous vs. operator-controlled actions, quarantine lifecycle (inventory + restore with approval gates), correlation, and console visibility via StagedActionBadge + real backend data).

**Living References** (authoritative for current state):
- [multi-agent-coordination-protocol.md](multi-agent-coordination-protocol.md) — the operating model and prompt synchronization rules.
- [current-capabilities-snapshot-2026-05-29.md](current-capabilities-snapshot-2026-05-29.md) — concise post-May 2026 snapshot of what is actually delivered and wired.
- Recent `coordination-brief-cycle-*.md` files — cycle-by-cycle detail (kept as living records, not rewritten).

See the living "Current Capabilities Snapshot" (docs/current-capabilities-snapshot-2026-05-29.md) for the post-May 2026 state of delivered features.

## Implemented API Surface

Customer and policy package flow:

```http
GET  /customers
POST /customers
POST /customers/quick-create
GET  /customers/{customer_id}
GET  /customers/{customer_id}/groups
GET  /policy-packages
POST /customers/{customer_id}/installers
POST /customers/{customer_id}/quick-deploy
GET  /quick-deploy/{link_id}?secret=...
```

Agent and endpoint flow:

```http
POST /enrollment/tokens
POST /agent/enroll
POST /agent/heartbeat
GET  /agent/{agent_id}/policy
GET  /agent/policy?endpoint_id=...&token=...
POST /agent/policy/ack?endpoint_id=...&token=...
POST /agent/dlp-evidence?endpoint_id=...&token=...
GET  /endpoints
```

DLP, policy, alerts, and audit:

```http
POST /dlp/scan
GET  /policies/active
GET  /policies/document
GET  /policies/documents
POST /policies/document
POST /policies/document/simulate
GET  /alerts
PATCH /alerts/{alert_id}/acknowledge
GET  /audit
GET  /audit/verify
GET  /compliance/export
POST /simulate/scenario
GET  /customers/{customer_id}/telemetry
GET  /customers/{customer_id}/security-alerts
GET  /customers/{customer_id}/incidents
```

Policy Engine v2:

```http
POST /policies
GET  /policies
GET  /policies/{policy_id}
PUT  /policies/{policy_id}
DELETE /policies/{policy_id}
GET  /policies/{policy_id}/versions
GET  /policies/{policy_id}/versions/{version}
POST /policies/{policy_id}/simulate
POST /policies/{policy_id}/promote
POST /policies/{policy_id}/rollback
POST /policies/assign
GET  /policies/effective
```

Accounts, companies, licensing, and AI settings:

```http
GET  /me
POST /auth/login
POST /auth/totp/verify
POST /auth/accept-invite
GET  /roles
GET  /accounts
POST /accounts
POST /accounts/bulk-delete
GET  /accounts/{account_id}
DELETE /accounts/{account_id}
POST /accounts/{account_id}/roles
DELETE /accounts/{account_id}/roles/{assignment_id}
POST /accounts/{account_id}/password
GET  /companies
GET  /companies/summary
POST /companies/bulk-status
POST /companies/bulk-delete
GET  /companies/{customer_id}
PATCH /companies/{customer_id}/status
DELETE /companies/{customer_id}
GET  /partners
GET  /subscriptions
POST /subscriptions
GET  /companies/{customer_id}/license
PUT  /companies/{customer_id}/license
GET  /ai/providers
GET  /companies/{customer_id}/ai
PUT  /companies/{customer_id}/ai
DELETE /companies/{customer_id}/ai
POST /companies/{customer_id}/ai/test
```

## Quick Deploy Smoke Test

Create a customer and installer metadata:

```bash
curl -fsS -X POST http://127.0.0.1:8000/customers/quick-create \
  -H 'content-type: application/json' \
  -d '{
        "name": "Northwind Dental",
        "industry": "Healthcare",
        "country": "US",
        "company_size": "11-50",
        "platforms": ["windows_msi", "macos_pkg"]
      }'
```

The response includes:

- `customer` with customer id and customer number.
- `assignment` with the selected policy package.
- `installers` with platform, artifact URL, SHA-256, install profile, and one-time enrollment token.
- `quick_deploy_links` with shareable links that mint a short-lived enrollment token when resolved.

## Agent Enrollment Paths

Developer token path:

```bash
TOKEN=$(curl -fsS -X POST http://127.0.0.1:8000/enrollment/tokens \
  -H 'content-type: application/json' \
  -d '{"note":"local agent","ttl_seconds":600}' \
  | python3 -c 'import json, sys; print(json.load(sys.stdin)["token"])')

AETHERIX_API_URL=http://127.0.0.1:8000 \
AETHERIX_ENROLLMENT_TOKEN="$TOKEN" \
cargo run --manifest-path agent/Cargo.toml
```

Installer profile path:

```bash
AETHERIX_INSTALL_PROFILE_PATH=/path/to/install-profile.json \
cargo run --manifest-path agent/Cargo.toml
```

The agent stores credentials at `~/.aetherix/agent-credentials.json` unless `AETHERIX_AGENT_CREDENTIALS_PATH` is set. It stores the fetched policy package at `~/.aetherix/policy-package.json` unless `AETHERIX_POLICY_PATH` is set.

## Current Data Model

Core tables are created in `apps/api/app/db.py`:

- `partners`
- `customers`
- `customer_groups`
- `policy_packages`
- `policy_assignments`
- `enrollment_tokens`
- `enrolled_agents`
- `installer_builds`
- `quick_deploy_links`
- `heartbeats`
- `alerts`
- `acknowledged_alerts`
- `policy_documents`
- `audit_log`
- `accounts`, `account_roles`, `roles`, `role_permissions`, `login_challenges`, `impersonation_sessions`
- `subscriptions`, `company_licenses`, `license_products`, `license_usage_daily`
- `policy_documents_v2`, `policy_versions`, `policy_assignments_v2`, `policy_simulations`, `policy_promotions`, `evidence_events`
- `telemetry_events`, `security_alerts`, `incident_cases`
- `compliance_controls`
- `ai_providers`, `customer_ai_settings`, `customer_ai_usage_daily`

Do not add in-memory state for new features. Add Postgres tables and tests that truncate or isolate them in `apps/api/tests/conftest.py`.

## Current Console Foundation

The React console now starts from the MSP management surface instead of a narrow operator-only dashboard.

Implemented pages and flows:

- Companies + Licensing: creates companies through `/customers/quick-create`, displays paged `/companies/summary`, edits licenses, configures/test AI providers, runs hard delete and soft lifecycle bulk actions, displays Core endpoint licensing, add-on packaging, AI Efficiency Score, white-label entry point, policy assignment, and installer generation state.
- Accounts: persists Platform Owner, MSP Partner, Company Administrator, Company Technician, and Company Viewer roles; includes API-backed list filters, bulk hard delete, add/edit modal, invitation delivery, module permissions, 2FA state, password policy, and a permission matrix.
- Policy Engine v2: creates, lists, simulates, promotes, assigns, resolves, and previews entitlement-aware modular policies.
- Antimalware & Behavior and Quarantine: present three-panel triage workspaces over live detections, effective policy, and remote endpoint state. These are now wired to real EDR collectors and remote response actions (quarantine inventory snapshots, response history, and severity-gated restore workflows with operator approval). They demonstrate both triage and production-grade operator-controlled containment.
- Full navigation: Monitoring, Incidents, Threats Xplorer, Network, Risk Management, Policies, Reports, Quarantine, Companies, Accounts, Sandbox Analyzer, Email Security, Mobile Security, Data Insights, Integrations, and Configuration.

Current implementation boundary:

- Company creation, accounts, roles, subscriptions, company licenses, AI settings, Policy Engine v2, Quick Deploy, and compliance export are backed by the API.
- The console and API use bearer session authentication (`Authorization: Bearer <jwt>`). The `X-Aetherix-Account` fallback path has been removed.
- AI Efficiency Score, white-label controls, several sidebar destinations, and default landing-page recommendations are still console foundations or placeholders until their dedicated APIs exist.
- Antimalware & Behavior and Quarantine surfaces now demonstrate live remote EDR capabilities: the agent collects process trees, ransomware canaries, YARA matches, and FIM events; the control plane surfaces per-endpoint quarantine inventory and full response-action history; the console renders live snapshots, severity-based restore staging (with dual-operator approval for high/critical), and executed/denied states driven by server evidence. These are no longer pure triage foundations.

Recommended backend order for this surface:

1. Replace dev header authentication with a production session/token boundary carrying `actor_id`, `role`, `partner_id`, optional `customer_id`, and optional impersonation session id.
2. Add recursive partner/company filters and cross-tenant denial tests to every list/detail route.
3. Finish subscription entitlement limits for module-specific policy actions and sidebar visibility.
4. Add `partner_branding` persistence and replace white-label placeholders with API reads/writes.
5. Add production impersonation start/end/action audit UX.

## Security Event Simulation

The current simulation path is `POST /simulate/scenario`. It writes telemetry,
security alerts, and incident cases for deterministic scenarios, and customer
scoped reads are exposed through:

```http
GET /customers/{customer_id}/telemetry
GET /customers/{customer_id}/security-alerts
GET /customers/{customer_id}/incidents
```

Keep future scenario endpoints additive unless there is a strong reason to split
the route family. Each scenario must continue to write tenant-scoped telemetry,
create at least one alert, audit the action, and avoid raw sensitive content in
stored payloads.

Minimum alert fields for the simulation module:

```text
id, partner_id, customer_id, endpoint_id, title, category, severity,
confidence, status, recommended_action, ai_summary, payload, created_at
```

Keep LLM calls out of the first simulation module. Use deterministic templates that are shaped like future AI output, then replace the generator after the LLM gateway exists.

## Policy Engine v2

Policy Engine v2 is implemented as raw Postgres-backed services in
`apps/api/app/services/policy_v2.py` and
`apps/api/app/services/policy_v2_runtime.py`. Keep it separate from the legacy
v1 DLP policy document routes under `/policies/document*` and `/policies/active`.

Current responsibilities:

1. Versioned modular policy documents with draft/promoted lifecycle.
2. Deterministic validation and simulation with evidence tags.
3. Promotion gates for destructive actions.
4. Customer/group/endpoint assignment.
5. Effective policy resolution for console and enrolled agents.
6. Agent DLP evidence emission into `evidence_events`.

Next hardening items: richer inheritance visualization, more default templates,
full subscription limit enforcement, policy ack observability, and broader module
coverage beyond Semantic DLP/GenAI Guardrails.

Policy Engine v2 can proceed in parallel with security event simulation as long as it preserves the existing `/policies/document` and `/policy-packages` POC flows until replacement routes are tested.

## Security Rules For Development

- Store only token hashes, never raw tokens.
- Return raw enrollment tokens only once.
- Keep installer profiles signed and short-lived.
- Audit every mutating route.
- Do not log raw DLP scan text.
- Keep AI advisory until deterministic policy and approval gates are in place.
- Add tenant/customer ids to every new operational table.
