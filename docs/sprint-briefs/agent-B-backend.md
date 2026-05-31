# Sprint 2 Brief — Agent B (Backend)  [re-baselined 2026-05-31]

You own ONLY `apps/api/`. Do not edit other dirs. Do not run git.
Nothing is done without a passing test.

Setup: `docker compose up -d postgres` (host port **55432**); venv +
`pip install -r requirements.txt`. Verified baseline: **`pytest -q` = 278 passed,
1 skipped** against real Postgres. Run it first; don't weaken existing tests.

> NOTE: Accounts persistence and DLP↔EDR correlation are ALREADY DONE (verified) —
> do not re-implement them.

## Tasks (priority order)
1. **Add RLS to the two unprotected tenant tables.** `module_actions` and
   `endpoint_quarantine_inventory` have `customer_id` but **no Postgres RLS policy**
   (others use `app.current_has_tenant_access(...)` in `db.py:~1671-1770`). Add
   matching `create policy … for all using (app.current_has_tenant_access(
   p_customer_id := customer_id))` for both, enable RLS, and add a test proving a
   cross-tenant direct query is blocked at the DB layer (not just by `require()`).
2. **Reconcile schema management.** Live schema is bootstrapped by
   `db.init_schema()`, but an `alembic/` dir exists and `alembic upgrade head`
   errors against a bootstrapped DB. Decide one source of truth: either make Alembic
   authoritative (autogenerate a baseline matching `init_schema`, document the flow)
   or remove/clearly-mark Alembic as unused. Add a CI-friendly check.
3. **OAuth2: make it honest.** Either (a) implement the real flow
   (`/oauth2/authorize` → `/oauth2/callback` → code exchange → token mint) on top of
   the existing CRUD/state functions in `tenancy.py:977+`, with tests; OR (b) if out
   of scope this sprint, gate/label it so nothing presents SSO as available. State
   which you chose.

## Final report (verbatim)
file:line of each change; the RLS policies + the cross-tenant block test; the
schema-management decision + how it's enforced; OAuth2 choice; `pytest -q`
before/after counts.
