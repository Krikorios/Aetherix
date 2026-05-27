# Aetherix Endpoint Security Platform

This repository contains the Aetherix platform: a lightweight Rust endpoint agent, a FastAPI/Postgres control plane, a React/Vite MSP console, policy simulation, tenant-aware customer onboarding, Companies + Licensing, Accounts hierarchy design, and customized installer/Quick Deploy generation.

See [docs/milestone-summary-2026-05-23.md](docs/milestone-summary-2026-05-23.md) for the latest milestone summary, including Policy Engine v2, Semantic DLP plus GenAI Guardrails, Rust agent enforcement, the MV3 browser extension, and the Antimalware & Behavior console module.

## Workspace

- `apps/api` - FastAPI service for DLP scanning, policies, enrollment, installer metadata, audit, and endpoint state.
- `apps/console` - React/Vite MSP console for operations, alerts, DLP scanning, policy editing, Companies + Licensing, Accounts, and customer Quick Deploy.
- `agent` - Rust endpoint agent skeleton for enrollment, signed heartbeats, policy pull, and local telemetry experiments.
- `docs` - Product and engineering notes, including architecture, policy engine design, development workflow, and the MVP plan.

## Quick Start

Start Postgres (the API has no SQLite or in-memory fallback — all state lives in the database):

```bash
docker compose up -d postgres
```

Install the console dependencies:

```bash
npm install
```

Create the API virtual environment and install dependencies:

```bash
cd apps/api
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Apply database migrations (recommended before starting the API):

```bash
cd apps/api
source .venv/bin/activate
alembic -c alembic.ini upgrade head
```

Run the API:

```bash
PYTHONPATH=apps/api apps/api/.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Run the console in another terminal:

```bash
npm run dev -- --host 127.0.0.1
```

The API expects `AETHERIX_DATABASE_URL` (defaults to
`postgresql://aetherix:aetherix@127.0.0.1:55432/aetherix`, which matches the
`docker-compose.yml` service — host port `55432` is used so this Postgres
instance can coexist with another local Postgres on `5432`). The schema is created on startup.

When introducing schema changes, prefer Alembic revisions over adding ad-hoc
runtime SQL in startup code.

The tenant/customer service seeds only the local demo MSP and the default `SMB Baseline Protection` policy package when `/customers` or `/policy-packages` is called. It does not seed customers, endpoints, alerts, or telemetry.

Before using `/policies/active` or `/dlp/scan`, promote a policy document:

```bash
curl -fsS -X POST http://127.0.0.1:8000/policies/document \
  -H 'content-type: application/json' \
  -d '{
        "name": "Default policy",
        "mode_default": "monitor",
        "escalate_at": "high",
        "genai_guardrail": true,
        "rules": [
          {"id":"pii.email","kind":"entity","entity_type":"EMAIL_ADDRESS","action":"review"}
        ]
      }'
```

`GET /policies/active` and `POST /dlp/scan` return **409 Conflict** until
a policy document exists.

Tests run against a separate `aetherix_test` database (created automatically
by the docker-compose init script). Override with `AETHERIX_TEST_DATABASE_URL`
when running against a different Postgres instance.

To enroll and run the Rust agent against the local API:

```bash
TOKEN=$(curl -fsS -X POST http://127.0.0.1:8000/enrollment/tokens \
	-H 'content-type: application/json' \
	-d '{"note":"local agent","ttl_seconds":600}' \
	| python3 -c 'import json, sys; print(json.load(sys.stdin)["token"])')

AETHERIX_API_URL=http://127.0.0.1:8000 \
AETHERIX_ENROLLMENT_TOKEN="$TOKEN" \
cargo run --manifest-path agent/Cargo.toml
```

The enrollment token is single-use. The agent stores its returned PoC credential at
`~/.aetherix/agent-credentials.json` by default, or at `AETHERIX_AGENT_CREDENTIALS_PATH`
when set, and reuses it for nonce-bound HMAC heartbeats. Customized installers write an install profile containing `control_plane_url`, tenant context, and a bootstrap token. The Rust agent reads it from `AETHERIX_INSTALL_PROFILE_PATH` or `/etc/aetherix/install-profile.json` on Unix-like systems.

## Current Implemented Flows

- Promote and simulate signed policy documents.
- Issue one-time enrollment tokens and enroll agents with per-agent secrets.
- Create MSP customers with default groups and policy assignment.
- Use the Companies + Licensing console foundation to create customer companies, estimate Core endpoint licensing, show subscription add-ons, display AI Efficiency Score, and launch policy-to-installer deployment.
- Use the Accounts console foundation to model Platform Owner, MSP Partner, Company Administrator, Company Technician, and Company Viewer roles with filters, account modal, module permissions, 2FA state, password policy, and the recommended permission matrix.
- Generate installer build records and signed install profiles for Windows, macOS, and Linux package targets.
- Create Quick Deploy links that mint short-lived tenant-bound enrollment tokens at download time.
- Fetch assigned policy packages from the agent with `GET /agent/{agent_id}/policy`.
- Send signed nonce-bound heartbeats and view endpoint state in the console.
- Export a signed Compliance Evidence Engine v0 bundle with `GET /compliance/export?customer_id=<id>&framework=iso27001-2022`, backed by seeded control catalogue rows and `evidence_controls` tags on audit, alert, and policy-document records.

The Accounts and Licensing screens are currently console-level foundations. The backend still needs persisted accounts, authenticated tenant scoping, subscription entitlement tables, and audit-backed impersonation before these controls are production enforcement points.

## Validation

```bash
cd apps/api && .venv/bin/pytest -q
cd agent && cargo test
npm run build
```

See [docs/development.md](docs/development.md) for the development checklist, API contracts, and next simulation modules. See [docs/policy-engine.md](docs/policy-engine.md) for the subscription-aware Policy Engine v2 design.

## First POC Goals

1. Accept text samples and detect PII with Presidio-compatible scan results.
2. Show endpoint health, alerts, and policy state in the console.
3. Keep the agent contract small enough to replace mock telemetry with OS-specific collectors later.
4. Establish the **native coverage spine**: one signed agent + one control plane covering anti-malware / EDR, SIEM / HIDS, and DLP classification + labeling + policy — wired into a built-in Compliance Evidence Engine that maps every event to ISO 27001 / SOC 2 / NIST CSF / GDPR / HIPAA controls at write time. See [docs/architecture.md §3.4.2](docs/architecture.md).

See [docs/poc-plan.md](docs/poc-plan.md) for the full platform proposal, roadmap, MSP strategy, risk register, and proof-of-concept slice. See [docs/roadmap-2026.md](docs/roadmap-2026.md) for the prioritized P0–P3 engineering backlog and go-to-market sequencing.
