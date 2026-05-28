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

---

## Design-partner release verification runbook

This section gives a **complete, copy-paste-ready** procedure that a design
partner (or QA engineer on a clean VM) can run after receiving a tagged
release link. Replace `<VERSION>` with the semver string from the GitHub
release page (e.g. `1.2.0`).

### Step 0 — Download artifacts and sidecars

All artifacts are published as GitHub Release assets. Download the package
_and_ its `.sha256` sidecar before verifying.

```
# macOS
curl -fLO "https://github.com/aetherix/aetherix/releases/download/agent-v<VERSION>/aetherix-agent-<VERSION>.pkg"
curl -fLO "https://github.com/aetherix/aetherix/releases/download/agent-v<VERSION>/aetherix-agent-<VERSION>.pkg.sha256"

# Windows (PowerShell)
Invoke-WebRequest -Uri "https://github.com/aetherix/aetherix/releases/download/agent-v<VERSION>/aetherix-agent-<VERSION>.msi" -OutFile "aetherix-agent-<VERSION>.msi"
Invoke-WebRequest -Uri "https://github.com/aetherix/aetherix/releases/download/agent-v<VERSION>/aetherix-agent-<VERSION>.msi.sha256" -OutFile "aetherix-agent-<VERSION>.msi.sha256"

# Linux
wget "https://github.com/aetherix/aetherix/releases/download/agent-v<VERSION>/aetherix-agent_<VERSION>_amd64.deb"
wget "https://github.com/aetherix/aetherix/releases/download/agent-v<VERSION>/aetherix-agent_<VERSION>_amd64.deb.sha256"
```

### Step 1 — Verify SHA-256 fingerprint

Confirm the downloaded file matches the published fingerprint **before**
running any signature check. A mismatch means the artifact was corrupted or
tampered in transit — do not proceed.

```
# macOS / Linux
sha256sum -c aetherix-agent-<VERSION>.pkg.sha256
# Expected output: aetherix-agent-<VERSION>.pkg: OK

sha256sum -c aetherix-agent_<VERSION>_amd64.deb.sha256
# Expected output: aetherix-agent_<VERSION>_amd64.deb: OK

# Windows (PowerShell)
$expected = (Get-Content "aetherix-agent-<VERSION>.msi.sha256" -Raw).Split(" ")[0].Trim()
$actual   = (Get-FileHash "aetherix-agent-<VERSION>.msi" -Algorithm SHA256).Hash.ToLower()
if ($expected -eq $actual) { Write-Host "SHA-256 OK" } else { Write-Error "MISMATCH — do not install" }
```

### Step 2 — Verify code signature (macOS)

Requires a Mac with Xcode command-line tools installed.

```bash
# Check Gatekeeper acceptance (must say "accepted" with no warnings)
spctl -a -vv -t install aetherix-agent-<VERSION>.pkg
# Expected: aetherix-agent-<VERSION>.pkg: accepted
#           source=Developer ID Installer: Aetherix Ltd (<TEAM_ID>)

# Inspect certificate chain
pkgutil --check-signature aetherix-agent-<VERSION>.pkg
# Expected output includes:
#   Status: signed by a developer certificate issued by Apple for distribution
#   Certificate Chain:
#     1. Developer ID Installer: Aetherix Ltd
#     2. Developer ID Certification Authority
#     3. Apple Root CA

# Verify notarization staple (ticket embedded in the pkg)
stapler validate aetherix-agent-<VERSION>.pkg
# Expected: The validate action worked!
```

If `spctl` reports `rejected` or `not signed`, **do not install** — contact
the Aetherix engineering team.

### Step 3 — Verify Authenticode signature (Windows)

Run the following in an **elevated** PowerShell session.

```powershell
# Check Authenticode signature status
$sig = Get-AuthenticodeSignature "aetherix-agent-<VERSION>.msi"
$sig | Select-Object Status, StatusMessage, SignerCertificate

# Expected:
#   Status        : Valid
#   StatusMessage : Signature verified.
#   SignerCertificate : [Subject includes "Aetherix Ltd"]

# Verify timestamp (RFC 3161) exists — ensures the signature survives cert expiry
$sig.TimeStamperCertificate
# Expected: a non-null certificate object from a recognised TSA

# Alternative: signtool (requires Windows SDK)
signtool verify /pa /v "aetherix-agent-<VERSION>.msi"
# Expected last line: Number of files successfully Verified: 1
```

### Step 4 — Verify GPG signature (Linux)

The Aetherix release GPG key must be imported once per machine.

```bash
# Import the Aetherix release public key (one-time setup)
curl -fsSL https://packages.aetherix.com/gpg/release.pub | gpg --import
# Verify the fingerprint matches the one published on the Aetherix security page

# Verify dpkg-sig signature
dpkg-sig --verify aetherix-agent_<VERSION>_amd64.deb
# Expected:
#   GOODSIG _gpgbuilder <KEY_ID> <timestamp>

# Alternative: verify detached .asc if provided
gpg --verify aetherix-agent_<VERSION>_amd64.deb.asc aetherix-agent_<VERSION>_amd64.deb
# Expected: Good signature from "Aetherix Release Signing Key <releases@aetherix.com>"
```

### Step 5 — Clean install smoke test

After successful signature verification, perform a clean install on the test VM
and confirm the agent connects to the control plane:

1. **macOS**: `sudo installer -pkg aetherix-agent-<VERSION>.pkg -target /`  
   Then: `sudo launchctl list | grep aetherix` — service should be `0` (running).

2. **Windows** (elevated cmd): `msiexec /i aetherix-agent-<VERSION>.msi /qn ENROLLMENT_TOKEN=<token>`  
   Then: `sc query AetherixAgent` — `STATE: 4 RUNNING`.

3. **Linux**: `sudo dpkg -i aetherix-agent_<VERSION>_amd64.deb`  
   Then: `systemctl is-active aetherix-agent` — should return `active`.

Within 60 seconds of install, the enrolled endpoint must appear on the
Aetherix console under **Network → Endpoints** with a green heartbeat
indicator. If it does not appear after 90 seconds, collect
`/var/log/aetherix/agent.log` (Linux/macOS) or
`%ProgramData%\Aetherix\logs\agent.log` (Windows) and file an issue.

### Step 6 — Release promotion gate

A tagged release may only be promoted to design-partner tenants once **all**
of the following have been confirmed and documented in the release PR:

| Gate | Check |
|---|---|
| SHA-256 fingerprints | All three platforms match `.sha256` sidecars |
| macOS spctl | `accepted` + notarization staple validated |
| Windows Authenticode | `Status: Valid` + RFC 3161 timestamp present |
| Linux GPG | `GOODSIG` from Aetherix release key |
| Clean install smoke | Agent heartbeat visible in console within 90 s |
| Console build | `npm run build` exits 0 with no Vite parse overlays |

### Known boundary

The pipeline currently produces an MSI, PKG, and DEB only. RPM and EXE
bootstrappers are tracked in the roadmap but not yet wired into
`release-agent.yml`.

