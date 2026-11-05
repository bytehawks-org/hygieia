# Install the Hygieia node as a Windows service (run from the unpacked zip, in an elevated PowerShell).
# NOT TESTED YET on a real Windows machine. DNS stays off; the system resolver is not touched.
#requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
$src = Split-Path -Parent $MyInvocation.MyCommand.Path
$dst = Join-Path $env:ProgramFiles 'Hygeia'
if (Get-Service HygeiaProxy -ErrorAction SilentlyContinue) {
    & (Join-Path $dst 'hygeia-proxy.exe') service uninstall
}
New-Item -ItemType Directory -Force $dst | Out-Null
Copy-Item (Join-Path $src 'hygeia-proxy.exe') $dst -Force
if (Test-Path (Join-Path $src 'web')) {
    Copy-Item (Join-Path $src 'web') $dst -Recurse -Force
}
if (Test-Path (Join-Path $src 'hygeia-tray.exe')) {
    Copy-Item (Join-Path $src 'hygeia-tray.exe') $dst -Force
    # Tray icon for every user at logon (status + shortcut to the dashboard; it holds no credential).
    New-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'HygieiaTray' `
        -Value ('"' + (Join-Path $dst 'hygeia-tray.exe') + '"') -PropertyType String -Force | Out-Null
}
& (Join-Path $dst 'hygeia-proxy.exe') service install
Start-Service HygeiaProxy
Write-Host "Started. Credential:  & '$dst\hygeia-proxy.exe' --data-dir `"$env:ProgramData\Hygeia`" token"
Write-Host "Sign in at http://127.0.0.1:8470/login/"
