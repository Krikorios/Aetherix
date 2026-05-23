# Accounts

The Accounts page is the local identity and authorization foundation for the
platform: persisted accounts, role-scoped permissions, company assignments,
invites, password setup, and delete workflows. It is API-backed, but the console
still uses the local dev account header instead of production sessions.

## Role hierarchy

Roles are seeded by the platform. Permissions merge across all role assignments
held by a single account.

| # | Role                  | Scope |
|---|-----------------------|-------|
| 1 | Platform Owner        | Creates partners, manages global settings, sees every tenant, audited impersonation. |
| 2 | MSP Partner           | Creates companies, manages licensing, users, installers, and partner branding. |
| 3 | Company Administrator | Manages one company's endpoints, policies, users, reports, and response actions. |
| 4 | Company Technician    | Works incidents, quarantine, tasks, and health queues for assigned companies. |
| 5 | Company Viewer        | Read-only access for auditors, executives, and customer managers. |

## Permission matrix

Each role grants a level (`none`, `view`, `edit`, or `manage`) per resource.
Effective permissions for an account are the maximum level across every role
assignment they hold.

| Role                  | Accounts | Policies | Companies | Incidents | Licensing | Impersonate |
|-----------------------|----------|----------|-----------|-----------|-----------|-------------|
| Company Administrator | manage   | edit     | view      | manage    | view      | none        |
| Company Technician    | none     | edit     | view      | edit      | none      | none        |
| Company Viewer        | none     | view     | view      | view      | view      | none        |
| MSP Partner           | manage   | manage   | manage    | manage    | manage    | edit        |
| Platform Owner        | manage   | manage   | manage    | manage    | manage    | manage      |

## Invitations

Account creation produces a single-use, 7-day invite token (SHA-256 hashed in
the database). Delivery is selected at create time:

- **Email** — invitation email is queued (SMTP wiring pending in dev); the URL
  is not returned to the caller.
- **Link** — the URL is returned for manual delivery. Recipients land on
  `#/invite/<token>` and set their password to activate.

## API-backed flows

- `GET /accounts`, `GET /accounts/{id}`, and `POST /accounts` drive the list,
  detail, and creation flows.
- `POST /accounts/{id}/roles` and `DELETE /accounts/{id}/roles/{assignment_id}`
  manage role assignments.
- `POST /accounts/bulk-delete` deletes multiple selected accounts and reports
  per-row failures.
- `POST /auth/login`, `POST /auth/totp/verify`, and `POST /auth/accept-invite`
  cover the current password/TOTP/invite setup path.

## Hard delete

`DELETE /accounts/{id}` permanently removes an account, its role assignments,
its login challenges, and any impersonation history. The signed-in operator
cannot delete their own account.

## Current boundary

Authorization data is persisted and tested, but production authentication,
session management, recursive MSP hierarchy filtering, and full impersonation
start/end/action UX remain hardening work.
