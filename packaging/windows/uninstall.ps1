# Remove the service and the program files. State in %ProgramData%\Hygeia is kept (signing key, credentials).
#requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
$dst = Join-Path $env:ProgramFiles 'Hygeia'
& (Join-Path $dst 'hygeia-proxy.exe') service uninstall
Remove-Item $dst -Recurse -Force
Write-Host "Removed. Delete $env:ProgramData\Hygeia manually to forget the keys and credentials."
