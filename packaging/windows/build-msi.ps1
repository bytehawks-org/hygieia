# Build hygeia-proxy.msi (WiX v5). Run on Windows from the repository root after:
#   cargo build --release -p hygeia-proxy
#   cargo build --release --manifest-path crates/hygeia-tray/Cargo.toml
#   (cd web && npm ci && npm run build)
# Usage: packaging/windows/build-msi.ps1 [-Version 0.1.0] [-Out dist/hygeia-proxy.msi]
param(
    [string]$Version = '0.1.0',
    [string]$Out = 'dist/hygeia-proxy-windows-x64.msi'
)
$ErrorActionPreference = 'Stop'
if (-not (Get-Command wix -ErrorAction SilentlyContinue)) {
    dotnet tool install --global wix --version 5.0.2
    $env:PATH += ";$env:USERPROFILE\.dotnet\tools"
}
wix extension add --global WixToolset.UI.wixext/5.0.2

# The UI needs an RTF licence page: wrap the repository LICENSE.
$rtf = New-TemporaryFile
$body = (Get-Content LICENSE -Raw) -replace '\\', '\\\\' -replace '\{', '\{' -replace '\}', '\}' -replace "`r?`n", "\par`n"
Set-Content -Path $rtf -Value ("{\rtf1\ansi\deff0{\fonttbl{\f0 Consolas;}}\f0\fs18`n" + $body + "`n}") -Encoding ascii

New-Item -ItemType Directory -Force (Split-Path $Out) | Out-Null
# MSI versions are numeric a.b.c[.d]: strip a leading "v" and any pre-release suffix.
$msiVersion = ($Version -replace '^v', '') -replace '[-+].*$', ''
wix build packaging/windows/wix/hygeia.wxs -arch x64 -ext WixToolset.UI.wixext `
    -d Version=$msiVersion `
    -d ExeDir=target/release `
    -d TrayDir=crates/hygeia-tray/target/release `
    -d WebDir=web/out `
    -d LicenseRtf=$rtf `
    -o $Out
Write-Host "Built $Out"
