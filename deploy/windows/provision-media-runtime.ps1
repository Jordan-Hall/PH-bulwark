<#
.SYNOPSIS
  Provision ffmpeg and an optional checksum-pinned NSFW ONNX model for Aegis.

.DESCRIPTION
  Writes stable per-user config under %LOCALAPPDATA%\Aegis so double-clicked
  parent-app launches can pass the same paths to aegis_proxy/aegis_vpn.

  ffmpeg is spawned as a child process, not linked. Model download is optional and
  must be paired with a SHA-256 when used for production provisioning.
#>
[CmdletBinding()]
param(
    [switch]$InstallFfmpeg,
    [string]$FfmpegPath,
    [string]$ModelUrl,
    [string]$ModelSha256,
    [string]$ModelPath = (Join-Path $env:LOCALAPPDATA 'Aegis\models\nsfw.onnx')
)

$ErrorActionPreference = 'Stop'

function Write-ConfigValue([string]$Name, [string]$Value) {
    $dir = Join-Path $env:LOCALAPPDATA 'Aegis'
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    Set-Content -LiteralPath (Join-Path $dir $Name) -NoNewline -Value $Value
}

function Resolve-Ffmpeg([string]$Explicit) {
    if ($Explicit) {
        $item = Get-Item -LiteralPath $Explicit -ErrorAction Stop
        return $item.FullName
    }
    $cmd = Get-Command ffmpeg.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $common = @(
        "$env:ProgramFiles\ffmpeg\bin\ffmpeg.exe",
        "$env:ProgramFiles\Gyan\ffmpeg\bin\ffmpeg.exe",
        "$env:LOCALAPPDATA\Microsoft\WinGet\Links\ffmpeg.exe"
    )
    foreach ($path in $common) {
        if (Test-Path -LiteralPath $path) { return (Get-Item -LiteralPath $path).FullName }
    }
    return $null
}

if ($InstallFfmpeg -and -not (Resolve-Ffmpeg $FfmpegPath)) {
    $winget = Get-Command winget.exe -ErrorAction SilentlyContinue
    if (-not $winget) {
        throw 'ffmpeg not found and winget is unavailable; install ffmpeg manually and pass -FfmpegPath.'
    }
    & winget install --id Gyan.FFmpeg --exact --accept-package-agreements --accept-source-agreements
    if ($LASTEXITCODE -ne 0) { throw 'winget failed to install Gyan.FFmpeg.' }
}

$resolvedFfmpeg = Resolve-Ffmpeg $FfmpegPath
if ($resolvedFfmpeg) {
    Write-ConfigValue 'ffmpeg_binary.txt' $resolvedFfmpeg
    [Environment]::SetEnvironmentVariable('FFMPEG_BINARY', $resolvedFfmpeg, 'User')
    [Environment]::SetEnvironmentVariable('AEGIS_FFMPEG_BINARY', $resolvedFfmpeg, 'User')
    Write-Host "ffmpeg: $resolvedFfmpeg"
} else {
    Write-Warning 'ffmpeg not found; video analysis will fail open until ffmpeg is installed or FFMPEG_BINARY is set.'
}

if ($ModelUrl) {
    if (-not $ModelSha256) {
        throw 'ModelUrl requires ModelSha256 so the downloaded model is checksum-pinned.'
    }
    $modelDir = Split-Path -Parent $ModelPath
    New-Item -ItemType Directory -Force -Path $modelDir | Out-Null
    Invoke-WebRequest -Uri $ModelUrl -OutFile $ModelPath
}

if (Test-Path -LiteralPath $ModelPath) {
    if ($ModelSha256) {
        $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $ModelPath).Hash.ToLowerInvariant()
        $expected = $ModelSha256.ToLowerInvariant()
        if ($actual -ne $expected) {
            throw "model SHA-256 mismatch: expected $expected got $actual"
        }
    }
    $resolvedModel = (Get-Item -LiteralPath $ModelPath).FullName
    Write-ConfigValue 'nsfw_model.txt' $resolvedModel
    [Environment]::SetEnvironmentVariable('AEGIS_NSFW_MODEL', $resolvedModel, 'User')
    Write-Host "NSFW model: $resolvedModel"
} else {
    Write-Warning 'NSFW model not configured; ONNX image/video scoring will fail open until a model is provisioned.'
}
