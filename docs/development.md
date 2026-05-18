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
```

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

Do not add in-memory state for new features. Add Postgres tables and tests that truncate or isolate them in `apps/api/tests/conftest.py`.

## Current Console Foundation

The React console now starts from the MSP management surface instead of a narrow operator-only dashboard.

Implemented pages and flows:

- Companies + Licensing: creates companies through `/customers/quick-create`, displays Core endpoint licensing, add-on packaging, AI Efficiency Score, white-label entry point, policy assignment, and installer generation state.
- Accounts: models the Aetherix hierarchy with Platform Owner, MSP Partner, Company Administrator, Company Technician, and Company Viewer roles; includes list filters, bulk selection/delete, add/edit modal, module permissions, 2FA state, password policy, and a permission matrix.
- Full navigation: Monitoring, Incidents, Threats Xplorer, Network, Risk Management, Policies, Reports, Quarantine, Companies, Accounts, Sandbox Analyzer, Email Security, Mobile Security, Data Insights, Integrations, and Configuration.

Current implementation boundary:

- Company creation, policy package reads, and Quick Deploy are backed by the API.
- Accounts, subscription add-ons, AI Efficiency Score, white-label controls, and default landing-page recommendations are console foundations until the backend account, subscription, entitlement, and impersonation-audit services exist.
- Do not rely on the console-only account data for authorization. Backend RBAC and tenant scoping remain required before production or design-partner use.

Recommended backend order for this surface:

1. Add `accounts`, `account_company_assignments`, `roles`, `role_permissions`, and `impersonation_sessions` tables.
2. Add `subscriptions`, `subscription_entitlements`, and `partner_branding` tables.
3. Add authenticated request context with `actor_id`, `role`, `partner_id`, optional `customer_id`, and optional impersonation session id.
4. Enforce partner/customer filters in every list/detail route and add tests for cross-tenant isolation.
5. Replace console demo account/add-on state with API reads and writes.

## Next Module: Security Event Simulation

Build the next slice in this order:

1. Add tables: `telemetry_events`, `security_alerts`, `incident_cases`, and optional `risk_reports`.
2. Add schemas for event payloads, alerts, incident timeline entries, and simulation requests.
3. Add service module `apps/api/app/services/simulation.py`.
4. Add routes:

```http
POST /simulate/dlp/genai-paste
POST /simulate/phishing-click
POST /simulate/usb-copy
POST /simulate/process-anomaly
POST /simulate/ransomware-behavior
POST /simulate/vulnerability-scan
```

5. Each route must write telemetry, create at least one alert, audit the action, and return a deterministic response.
6. Add console customer simulation view with scenario buttons and customer-scoped alert/event output.
7. Add tests proving events and alerts are created under the correct customer and cannot bleed across customers.

Minimum alert fields for the simulation module:

```text
id, partner_id, customer_id, endpoint_id, title, category, severity,
confidence, status, recommended_action, ai_summary, payload, created_at
```

Keep LLM calls out of the first simulation module. Use deterministic templates that are shaped like future AI output, then replace the generator after the LLM gateway exists.

## Parallel Design Track: Policy Engine v2

Policy Engine v2 is specified in [docs/policy-engine.md](policy-engine.md). Do not implement it as ad hoc fields on the current v1 DLP document. The required development order is:

1. Add `subscriptions` and `subscription_entitlements` tables.
2. Add versioned `PolicyDocumentV2` schemas with module sections.
3. Add entitlement validation at create, update, assignment, promotion, and effective policy fetch time.
4. Add inheritance resolution for MSP default, customer, group, and endpoint layers.
5. Update the console policy editor to show active, available, locked, inherited, and overridden sections.
6. Add the five default SMB templates from the policy engine design.

Policy Engine v2 can proceed in parallel with security event simulation as long as it preserves the existing `/policies/document` and `/policy-packages` POC flows until replacement routes are tested.

## Security Rules For Development

- Store only token hashes, never raw tokens.
- Return raw enrollment tokens only once.
- Keep installer profiles signed and short-lived.
- Audit every mutating route.
- Do not log raw DLP scan text.
- Keep AI advisory until deterministic policy and approval gates are in place.
- Add tenant/customer ids to every new operational table.