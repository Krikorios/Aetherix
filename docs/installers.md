# Installers

The Installers page is the MSP onboarding surface: create an SMB tenant, assign
a protection policy, and generate installer build records plus quick-deploy
links from one workspace.

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

## Artifacts and current boundary

For every successful run, the result panel exposes:

- **Quick-deploy links** — short URLs the customer hits to download the
  appropriate installer for their platform. Each link has an explicit expiry.
- **Direct installers** — the underlying artifacts with their signing status
  and SHA-256, plus a one-time enrollment token for manual installs.

The current implementation records installer metadata, install profiles,
artifact URLs, signing status, SHA-256 values, and one-time enrollment tokens.
It does not yet assemble signed MSI/EXE, PKG, DEB, or RPM binaries.

## Permissions

Generating installers requires `companies:edit` (or higher). Platform owners
see every tenant; MSP partners see only their partner-scoped customers.

## Signed binary release pipeline

The console-side flow above (`POST /customers/quick-create`, install
profiles, enrollment tokens) is independent from the per-release pipeline
that produces signed agent binaries. The signed pipeline lives in
`.github/workflows/release-agent.yml` and `agent/packaging/`. It is
triggered by pushing a tag `agent-v<semver>` or invoked manually via
**workflow_dispatch**.

### Per-platform jobs

| Platform | Output | Signing | Script |
|---|---|---|---|
| macOS    | `aetherix-agent-<version>.pkg` (universal: x86_64 + arm64) | Developer ID Application + Installer cert; notarized via `notarytool`; stapled with `stapler` | [agent/packaging/macos-package-and-notarize.sh](../agent/packaging/macos-package-and-notarize.sh) |
| Windows  | `aetherix-agent-<version>.msi` | WiX 4 build + `AzureSignTool` SHA-256 + RFC 3161 timestamp; certificate stored in Azure Key Vault, accessed via GitHub OIDC → Entra workload identity federation | [agent/packaging/windows-sign.ps1](../agent/packaging/windows-sign.ps1) and [agent/packaging/windows/Product.wxs](../agent/packaging/windows/Product.wxs) |
| Linux    | `aetherix-agent_<version>_amd64.deb` + systemd unit | `dpkg-sig` GPG signature with the Aetherix release key | [agent/packaging/linux-package-and-sign.sh](../agent/packaging/linux-package-and-sign.sh) |

All three scripts honour `AETHERIX_INSTALLER_DRY_RUN=1`, which skips the
signing step but still produces the package. Use this mode for local
development and CI smoke tests.

### Required GitHub secrets and variables

The workflow expects three Environments (`release-macos`, `release-windows`,
`release-linux`) so that production signing material is never reachable
from PR builds.

`release-macos` (secrets):

- `APPLE_DEVELOPER_ID_APPLICATION` — base64 of the Developer ID
  Application `.p12`
- `APPLE_DEVELOPER_ID_INSTALLER` — base64 of the Developer ID Installer
  `.p12`
- `APPLE_CERT_PASSWORD` — passphrase shared by both `.p12` bundles
- `APPLE_KEYCHAIN_PASSWORD` — random password for the throwaway runner
  keychain
- `APPLE_TEAM_ID` — 10-character Apple Team ID
- `APPLE_NOTARY_APPLE_ID` — Apple ID used by `notarytool`
- `APPLE_NOTARY_PASSWORD` — App-Specific password for that Apple ID

`release-windows` (variables, not secrets — they are not sensitive on their
own; access to the cert is gated by the GitHub-OIDC trust on the Azure
side):

- `AETHERIX_AZURE_KV_URI` — Key Vault URL (e.g. `https://aetx-signing.vault.azure.net`)
- `AETHERIX_AZURE_KV_CERT_NAME` — name of the EV/OV code-signing
  certificate in the vault
- `AETHERIX_AZURE_CLIENT_ID` — application (client) ID of the federated
  workload identity
- `AETHERIX_AZURE_TENANT_ID` — Entra tenant ID

The federated identity must hold `Key Vault Crypto User` on the vault, and
its trust policy must require `repo:aetherix/aetherix:environment:release-windows`
on the GitHub OIDC issuer.

`release-linux` (secrets):

- `AETHERIX_GPG_PRIVATE_KEY` — base64-encoded ASCII-armored GPG private key
- `AETHERIX_GPG_KEY_ID` — long form key id used by `dpkg-sig`
- `AETHERIX_GPG_PASSPHRASE` — passphrase for the key

### Verifying a release locally

After `actions/download-artifact` pulls the three packages, integrators
should reproduce the verification commands documented next to each artifact:

- macOS: `spctl -a -vv -t install aetherix-agent-<v>.pkg` and
  `pkgutil --check-signature aetherix-agent-<v>.pkg`
- Windows: `Get-AuthenticodeSignature aetherix-agent-<v>.msi` (PowerShell)
  or `signtool verify /pa /v aetherix-agent-<v>.msi`
- Linux: `dpkg-sig --verify aetherix-agent_<v>_amd64.deb`

Each verification command MUST report a valid signature with no warnings
before the release can be promoted to design-partner tenants. The
`.sha256` sidecar produced by each packaging script is published alongside
the binary so customers can pin a fingerprint independent of the signing
chain.

### Known boundary

The pipeline currently produces an MSI, PKG, and DEB only. RPM and EXE
bootstrappers are tracked in the roadmap but not yet wired into
`release-agent.yml`.

