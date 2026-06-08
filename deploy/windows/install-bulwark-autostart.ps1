<#
.SYNOPSIS
  Install Bulwark child-safety auto-start on Windows (tamper resistance, item 5).

.DESCRIPTION
  Registers a Scheduled Task that launches the Bulwark filter (bulwark_proxy.exe) at
  logon, running whether or not the child can see/stop it. Run this AS AN
  ADMINISTRATOR (the guardian); a Standard child user cannot modify or delete the
  task, and cannot uninstall a machine-wide install — that is the protection.

  THE MODEL (read docs/design/tamper-protection.md §5):
    1. The CHILD account must be a *Standard* user (not Administrator).
    2. The GUARDIAN holds the admin password.
    3. Uninstalling Bulwark then requires admin elevation the child doesn't have.
    4. The tamper heartbeat reports to the guardian if the filter is ever stopped.

  NOTE: this is the pragmatic starter. A production build should ship a real
  Windows SERVICE (SCM handler via the `windows-service` crate) so the child can't
  even stop it within their own session. Tracked as a follow-up.

.PARAMETER ExePath
  Full path to bulwark_proxy.exe. Defaults to the copy next to this script.

.EXAMPLE
  # From an elevated PowerShell:
  .\install-bulwark-autostart.ps1 -ExePath 'C:\Program Files\Bulwark\bulwark_proxy.exe'
#>
[CmdletBinding()]
param(
    [string]$ExePath = (Join-Path $PSScriptRoot 'bulwark_proxy.exe'),
    [string]$TaskName = 'BulwarkChildSafety'
)

$ErrorActionPreference = 'Stop'

# Must be elevated — registering a protected task + the standard-account model
# both require admin.
$me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this as Administrator (the guardian). A Standard child user must NOT be able to run it."
}
if (-not (Test-Path $ExePath)) {
    throw "bulwark_proxy.exe not found at '$ExePath'. Pass -ExePath."
}

# Run at any user logon, highest privileges, hidden window. Task is owned by the
# system/admin, so a Standard user cannot edit or delete it.
$action   = New-ScheduledTaskAction -Execute $ExePath
$trigger  = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -GroupId 'BUILTIN\Users' -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings -Force | Out-Null

Write-Host "Installed scheduled task '$TaskName' -> $ExePath"
Write-Host "Reminder: make the child account a STANDARD user and keep the admin password private."
Write-Host "Uninstall (guardian, elevated):  Unregister-ScheduledTask -TaskName '$TaskName' -Confirm:`$false"
