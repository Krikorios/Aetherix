# Installers

The Installers page is the MSP onboarding surface: create an SMB tenant, assign
a protection policy, and generate signed installers and quick-deploy links from
one workspace. Most deployments complete in under two minutes.

## Quick deploy flow

1. **Company** — name, industry, country, company size.
2. **Policy package** — picks the default group and assignment for the new
   tenant. Selecting a package previews its DLP rule count and hardening mode.
3. **Platforms** — choose any combination of Windows MSI/EXE, macOS PKG, Linux
   DEB/RPM. At least one platform must be selected.
4. **Generate** — `POST /customers/quick-create` creates the customer, the
   default group, the policy assignment, the installer artifacts, and matching
   quick-deploy links with a 24-hour TTL.

## Existing deployments

Click a deployment row to edit its company name, industry, country, size, and
assigned policy package. Saving calls `PUT /customers/{id}`. **Upgrade &
generate** saves the deployment first, then calls both
`POST /customers/{id}/installers` and `POST /customers/{id}/quick-deploy` for
the selected platforms so an MSP can refresh artifacts for an existing tenant.

## Artifacts

For every successful run, the result panel exposes:

- **Quick-deploy links** — short URLs the customer hits to download the
  appropriate installer for their platform. Each link has an explicit expiry.
- **Direct installers** — the underlying artifacts with their signing status
  and SHA-256, plus a one-time enrollment token for manual installs.

## Permissions

Generating installers requires `companies:edit` (or higher). Platform owners
see every tenant; MSP partners see only their partner-scoped customers.
