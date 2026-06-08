<#
.SYNOPSIS
  Install Bulwark as a locked-down Windows SERVICE (strongest desktop tamper tier).

.DESCRIPTION
  Installs `bulwark_svc.exe` as an auto-start LocalSystem service and LOCKS its DACL
  so a Standard (non-admin) child user cannot stop or delete it — only LocalSystem
  and Administrators (the guardian) can. The service supervises `bulwark_proxy.exe`
  and restarts it if the child kills it. Run AS ADMINISTRATOR (the guardian).

  THE MODEL (docs/design/tamper-protection.md §5):
    1. The CHILD account must be a *Standard* user (not Administrator).
    2. The GUARDIAN holds the admin password.
    3. The child cannot stop/delete the service (DACL) nor uninstall (needs admin).
    4. The tamper heartbeat alerts the guardian if protection ever drops.

  This supersedes install-bulwark-autostart.ps1 (the no-service, logon-task fallback).

.PARAMETER InstallDir
  Where to copy the binaries. Default C:\Program Files\Bulwark.
#>
[CmdletBinding()]
param(
    [string]$InstallDir = 'C:\Program Files\Bulwark',
    [string]$ServiceName = 'BulwarkChildSafety',
    [string]$SourceDir = $PSScriptRoot
)

$ErrorActionPreference = 'Stop'

$me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this as Administrator (the guardian)."
}

$svcExe   = Join-Path $InstallDir 'bulwark_svc.exe'
$proxyExe = Join-Path $InstallDir 'bulwark_proxy.exe'

# 1. Stage the binaries (the service expects bulwark_proxy.exe beside it).
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
foreach ($exe in 'bulwark_svc.exe', 'bulwark_proxy.exe') {
    $src = Join-Path $SourceDir $exe
    if (-not (Test-Path $src)) { throw "Missing $src — build it (cargo build --release -p bulwark-client) and place it next to this script." }
    Copy-Item $src (Join-Path $InstallDir $exe) -Force
}

# 2. Create the auto-start LocalSystem service (recreate if present).
& sc.exe stop   $ServiceName *> $null
& sc.exe delete $ServiceName *> $null
& sc.exe create $ServiceName binPath= "`"$svcExe`"" start= auto obj= LocalSystem DisplayName= "Bulwark Child Safety" | Out-Null
& sc.exe description $ServiceName "Bulwark transparent child-safety content filter." | Out-Null
# Auto-restart on crash (reset failure count daily; restart after 5s).
& sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/5000/restart/5000 | Out-Null

# 3. LOCK the DACL: LocalSystem (SY) + Administrators (BA) full control; Interactive
#    (IU) + Service (SU) users get query/read only — NO start (RP), stop (WP),
#    delete (DC/DE/SD), or write. This is what stops the child turning it off.
$sddl = 'D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)'
& sc.exe sdset $ServiceName $sddl | Out-Null

# 4. Start it.
& sc.exe start $ServiceName | Out-Null

Write-Host "Installed + locked service '$ServiceName' -> $svcExe"
Write-Host "Reminder: make the child account a STANDARD user; keep the admin password private."
Write-Host "Uninstall (guardian, elevated): .\uninstall-bulwark-service.ps1"
