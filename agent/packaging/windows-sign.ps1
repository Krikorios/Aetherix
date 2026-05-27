# windows-sign.ps1
#
# Build a signed MSI for the Aetherix agent using WiX 4 + Azure Key Vault
# code-signing via AzureSignTool. Expected to run on a windows-2022 GitHub
# runner that has already produced agent\dist\windows_exe\aetherix-agent.exe.
#
# Required environment (sourced from GitHub Environments):
#   AETHERIX_VERSION                       — e.g. 0.4.1
#   AETHERIX_AZURE_KV_URI                  — https://<vault>.vault.azure.net
#   AETHERIX_AZURE_KV_CERT_NAME            — name of code-signing certificate
#   AETHERIX_AZURE_CLIENT_ID               — federated GitHub-OIDC client id
#   AETHERIX_AZURE_TENANT_ID               — Entra tenant id
#
# Auth uses GitHub OIDC → Entra workload identity federation; no long-lived
# secret stored in GitHub. The signer service account must hold the
# `Key Vault Crypto User` role on the vault.
#
# Set $env:AETHERIX_INSTALLER_DRY_RUN = "1" to skip the signing call.

$ErrorActionPreference = "Stop"

function Require-Env([string[]]$names) {
    foreach ($name in $names) {
        if (-not (Test-Path "Env:$name")) {
            throw "FATAL: missing required env var: $name"
        }
    }
}

Require-Env @("AETHERIX_VERSION")

$DryRun = ($env:AETHERIX_INSTALLER_DRY_RUN -eq "1")
if (-not $DryRun) {
    Require-Env @(
        "AETHERIX_AZURE_KV_URI",
        "AETHERIX_AZURE_KV_CERT_NAME",
        "AETHERIX_AZURE_CLIENT_ID",
        "AETHERIX_AZURE_TENANT_ID"
    )
}

$RepoRoot = (Resolve-Path "$PSScriptRoot\..\..").Path
$DistDir  = Join-Path $RepoRoot "agent\dist\windows_exe"
$AgentBin = Join-Path $DistDir  "aetherix-agent.exe"
$OutMsi   = Join-Path $DistDir  "aetherix-agent-$($env:AETHERIX_VERSION).msi"

if (-not (Test-Path $AgentBin)) {
    throw "FATAL: $AgentBin not present. Run cargo build first."
}

Write-Host "==> Restoring WiX 4 tools"
dotnet tool install --global wix --version 4.0.4 2>$null
$env:Path = "$env:Path;$env:USERPROFILE\.dotnet\tools"

# Generate a minimal WiX source that wraps the agent EXE as a per-machine
# service. Source is checked in under agent\packaging\windows\Product.wxs.
$WixSource = Join-Path $PSScriptRoot "windows\Product.wxs"
if (-not (Test-Path $WixSource)) {
    throw "FATAL: missing $WixSource"
}

Write-Host "==> Building MSI"
$WorkDir = Join-Path $env:RUNNER_TEMP "wix-build"
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
Copy-Item $AgentBin (Join-Path $WorkDir "aetherix-agent.exe") -Force

Push-Location $WorkDir
try {
    & wix build -arch x64 `
        -d "Version=$($env:AETHERIX_VERSION)" `
        -d "AgentBinaryPath=$WorkDir\aetherix-agent.exe" `
        -out $OutMsi $WixSource
    if ($LASTEXITCODE -ne 0) { throw "wix build failed" }
}
finally {
    Pop-Location
}

if ($DryRun) {
    Write-Host "DRY_RUN: skipping AzureSignTool"
    Get-FileHash -Algorithm SHA256 $OutMsi |
        Select-Object Hash, @{n="Path"; e={$OutMsi}} |
        Tee-Object -FilePath "$OutMsi.sha256"
    return
}

Write-Host "==> Acquiring federated Azure access token via GitHub OIDC"
$idToken = (Invoke-RestMethod -Headers @{Authorization = "Bearer $env:ACTIONS_ID_TOKEN_REQUEST_TOKEN"} `
    -Uri "$env:ACTIONS_ID_TOKEN_REQUEST_URL&audience=api://AzureADTokenExchange").value

Write-Host "==> Installing AzureSignTool"
dotnet tool install --global AzureSignTool --version 5.0.0 2>$null

Write-Host "==> Signing MSI via Key Vault"
& AzureSignTool sign `
    --azure-key-vault-url       $env:AETHERIX_AZURE_KV_URI `
    --azure-key-vault-certificate $env:AETHERIX_AZURE_KV_CERT_NAME `
    --azure-key-vault-tenant-id $env:AETHERIX_AZURE_TENANT_ID `
    --azure-key-vault-client-id $env:AETHERIX_AZURE_CLIENT_ID `
    --azure-key-vault-accesstoken $idToken `
    --file-digest sha256 `
    --timestamp-rfc3161 "http://timestamp.digicert.com" `
    --timestamp-digest  sha256 `
    --description "Aetherix Agent" `
    --description-url "https://aetherix.io" `
    $OutMsi

if ($LASTEXITCODE -ne 0) { throw "AzureSignTool failed" }

Write-Host "==> Verifying signature"
& signtool verify /pa /v $OutMsi
if ($LASTEXITCODE -ne 0) { throw "signtool verify failed" }

Get-FileHash -Algorithm SHA256 $OutMsi |
    Select-Object Hash, @{n="Path"; e={$OutMsi}} |
    Tee-Object -FilePath "$OutMsi.sha256"

Write-Host "Signed MSI ready: $OutMsi"
