<#
.SYNOPSIS
  Remove the Bulwark Windows service (guardian, elevated).

.DESCRIPTION
  Stops + deletes the locked service and removes the installed binaries. Run AS
  ADMINISTRATOR. Also reminds you to UNTRUST the per-install root CA from the
  CHILD's user certificate store — an orphaned trusted root is a latent MITM
  backdoor, so removing it is a release requirement, not optional.
#>
[CmdletBinding()]
param(
    [string]$InstallDir = 'C:\Program Files\Bulwark',
    [string]$ServiceName = 'BulwarkChildSafety'
)

$ErrorActionPreference = 'Stop'

$me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this as Administrator (the guardian)."
}

& sc.exe stop   $ServiceName *> $null
& sc.exe delete $ServiceName *> $null
if (Test-Path $InstallDir) { Remove-Item -Recurse -Force $InstallDir }

Write-Host "Removed service '$ServiceName' and $InstallDir."
Write-Host "IMPORTANT: untrust the Bulwark root CA in the CHILD's user store so no MITM root lingers:"
Write-Host "  (in the child's session) certutil -delstore -user Root <Bulwark-CA-fingerprint>"
