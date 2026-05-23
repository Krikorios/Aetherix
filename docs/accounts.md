# Accounts

The Accounts page is the identity control plane for the platform: role-scoped
access for the platform operator, MSP partners, and company users, with audited
impersonation.

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

## Hard delete

`DELETE /accounts/{id}` permanently removes an account, its role assignments,
its login challenges, and any impersonation history. The signed-in operator
cannot delete their own account.
