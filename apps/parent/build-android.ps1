# PH Bulwark Manager — Android build + LAUNCHER-ICON injection + sideload.
#
# WHY THIS WRAPPER EXISTS (two dx 0.8.0-alpha limitations it works around):
#
# 1. NO ICON SEAM. `build_android_app_dir` (dioxus-cli src/build/android.rs:293-374)
#    rewrites the gen res/ icons from dx's OWN embedded defaults (the Dioxus logo)
#    via include_bytes! on EVERY build. dx has a manifest seam and a main-activity
#    seam but NONE for res/ — and `[bundle].icon` / `[android].icon` are consumed
#    ONLY by the desktop bundlers (macos/linux/windows.rs), never the Android build
#    (verified in source). So to ship OUR shield logo we overlay our two adaptive
#    drawables onto the gen project AFTER dx generates it, then let Gradle
#    re-package. min_sdk = 26, so only the mipmap-anydpi-v26 adaptive icon is ever
#    used; overriding ic_launcher_foreground + ic_launcher_background suffices.
#
# 2. `dx build --device` HANGS after a clean build. dx finishes the .so + Gradle
#    assemble (logs "Client build completed successfully"), then does NOT return
#    (the historical ~1.5h "hang"). We therefore run dx in the background, wait for
#    that success line (the APK is built by then), KILL dx, and finish ourselves.
#
# Usage:  pwsh apps/parent/build-android.ps1 [-Serial 32161FDH20039M] [-NoInstall] [-TimeoutMin 30]
param(
    [string]$Serial = "32161FDH20039M",
    [switch]$NoInstall,
    [int]$TimeoutMin = 30
)
$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$adb  = "C:/Android/sdk/platform-tools/adb.exe"

$env:JAVA_HOME        = "C:/Users/Jordan/AppData/Local/Programs/Microsoft/jdk-17.0.10.7-hotspot"
$env:ANDROID_HOME     = "C:/Android/sdk"
$env:ANDROID_SDK_ROOT = "C:/Android/sdk"
$env:ANDROID_NDK_HOME = "C:/Android/sdk/ndk/26.3.11579264"

Write-Host "== [1/4] dx build (arm64 for $Serial) — watching for completion ==" -ForegroundColor Cyan
$dxlog = Join-Path $env:TEMP "manager_dx.log"
Remove-Item $dxlog, "$dxlog.err" -ErrorAction SilentlyContinue
$proc = Start-Process -FilePath "dx" `
    -ArgumentList @("build", "--platform", "android", "--device", $Serial) `
    -WorkingDirectory $root -NoNewWindow -PassThru `
    -RedirectStandardOutput $dxlog -RedirectStandardError "$dxlog.err"

$deadline = (Get-Date).AddMinutes($TimeoutMin)
$ok = $false
while ((Get-Date) -lt $deadline) {
    if ($proc.HasExited) {
        # A *clean* --device build HANGS (never exits), so an exit is far more
        # often the failure signature than success — distinguish by exit code.
        if ($proc.ExitCode -eq 0) { $ok = $true; break }
        Get-Content "$dxlog.err" -Raw -ErrorAction SilentlyContinue | Write-Host
        throw "dx build exited $($proc.ExitCode) - see $dxlog / $dxlog.err"
    }
    # Cargo/rustc errors land on STDERR ($dxlog.err); scan BOTH streams.
    $txt = (Get-Content $dxlog -Raw -ErrorAction SilentlyContinue) +
        (Get-Content "$dxlog.err" -Raw -ErrorAction SilentlyContinue)
    if ($txt -match "build completed successfully") { $ok = $true; break }
    if ($txt -match "(?m)BUILD FAILED|could not compile|error\[E") {
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        throw "dx build failed - see $dxlog / $dxlog.err"
    }
    Start-Sleep -Seconds 5
}
# dx hangs after a clean build with --device; stop it now that the APK is built.
if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
if (-not $ok) { throw "dx build did not report completion within $TimeoutMin min - see $dxlog" }
Write-Host "dx build completed; dx stopped." -ForegroundColor Green

$gen = Join-Path $root "target/dx/bulwark-parent/debug/android/app"
$res = Join-Path $gen "app/src/main/res"
if (-not (Test-Path $res)) { throw "gen res not found at $res (did dx layout change?)" }

Write-Host "== [2/4] overlay PH Bulwark launcher icon ==" -ForegroundColor Cyan
Copy-Item -Force (Join-Path $root "android/res/drawable/ic_launcher_background.xml") `
    (Join-Path $res "drawable/ic_launcher_background.xml")
New-Item -ItemType Directory -Force (Join-Path $res "drawable-v24") | Out-Null
Copy-Item -Force (Join-Path $root "android/res/drawable-v24/ic_launcher_foreground.xml") `
    (Join-Path $res "drawable-v24/ic_launcher_foreground.xml")

Write-Host "== [3/4] gradle re-package with our icon ==" -ForegroundColor Cyan
Push-Location $gen
try {
    & ./gradlew.bat assembleDebug --console=plain
    if ($LASTEXITCODE -ne 0) { throw "gradle assembleDebug failed (exit $LASTEXITCODE)" }
} finally { Pop-Location }

$apk = Join-Path $gen "app/build/outputs/apk/debug/app-debug.apk"
if (-not (Test-Path $apk)) { throw "APK not found at $apk" }
Write-Host "APK: $apk" -ForegroundColor Green

if ($NoInstall) { Write-Host "== [4/4] skipped (-NoInstall) =="; return }
Write-Host "== [4/4] adb install -r ==" -ForegroundColor Cyan
& $adb -s $Serial install -r $apk
if ($LASTEXITCODE -ne 0) { throw "adb install failed (exit $LASTEXITCODE)" }
Write-Host "Installed PH Bulwark Manager (with shield icon) to $Serial" -ForegroundColor Green
