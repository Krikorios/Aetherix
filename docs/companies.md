# Companies + Licensing

The Companies page is the MSP tenant foundation: customer lifecycle, licensing
posture, seat usage, AI provider settings, and per-company deployment controls
in one place.

## Sign-in

The console uses the login + TOTP flow and stores a bearer session token in
`localStorage`. API requests are authorized with
`Authorization: Bearer <jwt>`.

## Company Hub table

Each row is a customer in the caller's scope. The hub renders licensing posture
alongside the customer record:

- `License` — type and key (or `Unlicensed`)
- `Plan` — subscription plan
- `Seats / Used` — entitlement and current consumption
- `Renewal` — next renewal date
- `Status` — active / suspended / archived

The table is backed by `GET /companies/summary`, which returns a paged response
with customer and license data together. Search, status filtering, and page size
are sent to the API as query parameters (`q`, `status`, `limit`, `offset`) so
the console does not load every company or issue one license request per row.
Bulk actions apply to checked rows on the current page unless rows remain
selected from another page.

## Bulk actions

- **Delete** — hard delete, see below. Confirms before running.
- **More actions** — Activate / Suspend / Archive (soft lifecycle changes via
  `POST /companies/bulk-status`).

Bulk delete uses `POST /companies/bulk-delete`. Both bulk endpoints return an
`ok_count` plus per-row failures so the UI can report partial success without
running one request per selected company.

## Hard delete

`DELETE /companies/{id}` purges the customer record and every row that
references it: acknowledged_alerts, alerts, heartbeats, telemetry_events,
security_alerts, incident_cases, enrolled_agents, enrollment_tokens,
installer_builds, quick_deploy_links, policy_assignments, customer_groups, and
account_roles. `company_licenses` and its children cascade automatically.

## Side-sheet

Clicking a row opens the company side-sheet with five tabs:

- **Details** — name, type, industry, status, partner scope.
- **Auth** — current account and invite state; SSO/identity-provider wiring is planned.
- **Licensing** — manage seats, renewal, products.
- **Products** — per-product activation.
- **AI** — choose disabled/hosted/BYO provider modes, store encrypted API keys, test provider reachability, and respect subscription AI tier gates.
- **Deploy** — issue new installers and quick-deploy links for the customer.

## Current boundary

Company rows, lifecycle actions, hard delete, licenses, and AI settings are API-backed. White-label branding and several product activation controls remain console foundations until dedicated persistence is added.
