# Remove the service and the program files. State in %ProgramData%\Hygeia is kept (signing key, credentials).
#requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
$dst = Join-Path $env:ProgramFiles 'Hygeia'
& (Join-Path $dst 'hygeia-proxy.exe') service uninstall
Remove-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'HygieiaTray' -ErrorAction SilentlyContinue
Get-Process hygeia-tray -ErrorAction SilentlyContinue | Stop-Process -Force
Remove-Item $dst -Recurse -Force
Write-Host "Removed. Delete $env:ProgramData\Hygeia manually to forget the keys and credentials."
