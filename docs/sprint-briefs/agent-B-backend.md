# Sprint 1 Brief — Agent B (Backend)

You are working on the **Aetherix** endpoint security platform. The repo is a
monorepo: a Rust endpoint agent (`agent/`), a FastAPI/Postgres backend
(`apps/api/`), and a React/Vite console (`apps/console/`).

**You own ONLY the `apps/api/` directory.** Do not edit `agent/`, `apps/console/`,
or `docs/`.

## Rules
- Nothing is "done" without a passing test. Do not overclaim.
- Prefer Alembic migrations over ad-hoc runtime SQL (repo convention).
- Do not run git. Leave your edits in the working tree.
- Keep changes small and reviewable; match existing patterns.

## Setup
- Start Postgres: `docker compose up -d postgres` (run from repo root).
- Create venv if missing:
  `cd apps/api && python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt`
- Apply migrations: `alembic -c alembic.ini upgrade head`
- Tests run against `aetherix_test` via `pytest -q`. **Run the suite FIRST** to
  confirm a green baseline before changing anything. Do not weaken/skip existing tests.

## Tasks
1. **Persist the Accounts backend** (currently a console-only "foundation" — the
   README notes the backend still needs persisted accounts + authenticated tenant
   scoping).
   - Add an Alembic migration for an accounts table with the fields the console
     expects: full name, email, status, role, 2FA state, password expiration,
     account lockout, company assignments.
   - Inspect `apps/api/app/services/tenancy.py`, `app/schemas.py`, and the routers in
     `app/main.py` to match conventions and the role hierarchy
     (Platform Owner → MSP Partner → Company Admin/Technician/Viewer).
   - Add CRUD endpoints with proper `require(...)` permission checks and tenant
     scoping (an MSP Partner sees/manages only their own companies' accounts).
   - Write pytest integration tests for create/list/update, permission enforcement,
     and tenant isolation.
2. **Wire DLP↔EDR correlation.** `app/services/correlation.py` already does
   FIM↔EDR sha256/path/process joins with severity uplift. Extend it to correlate
   DLP events (a DLP events table reportedly exists) by sha256 / file_path /
   endpoint, emit `evidence_controls`, and add tests for the new join paths.

## Required final report (paste this back to me verbatim)
- What you added (`file:line` for each change).
- The Alembic migration name/revision.
- New endpoints and their exact permission gates.
- New tests and what each asserts.
- `pytest -q` results before and after (counts).
- Anything incomplete or risky. Be precise and honest.
