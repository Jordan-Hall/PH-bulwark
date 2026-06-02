//! Best-effort device-capability detection.
//!
//! Produces a [`DeviceProfile`] (the `aegis.v1` wire message) that
//! `aegis-infer`'s [`OffloadRouter`] uses to negotiate local-vs-cluster routing
//! (see `docs/design/architecture.md` §4 and `interfaces.md`). This crate does
//! **not** decide routing — it only describes the hardware.
//!
//! Design rules honoured here:
//! * **No AI/ML** in this crate (PLAN §0b). Detection is pure platform probing.
//! * **No telemetry** (PLAN §3): nothing is reported off-device. The profile is
//!   handed to the local router (and, by the router's choice, to the user's own
//!   cluster over mTLS) — never to us.
//! * **Best-effort + fail-safe**: every probe degrades gracefully. Unknown CPU →
//!   empty string; unknown battery → `-1`; the always-present [`CPU`] execution
//!   provider is the floor so the profile is never empty.
//!
//! Execution-provider ordering is **best-first** per platform, mirroring `ort`'s
//! ordered-fallback contract (`docs/research/crate-research.md`): the router
//! requests providers in this order and `ort` silently degrades to CPU.

use aegis_proto::v1::{DeviceProfile, ExecutionProvider};
use sysinfo::System;

/// Inputs the caller may already know (device id, app version, a fresh RTT
/// measurement, battery), letting detection fill in only the hardware facts.
///
/// All fields are optional; [`detect_device_profile`] uses
/// [`DetectionHints::default`] when the caller has nothing to add.
#[derive(Clone, Debug, Default)]
pub struct DetectionHints {
    /// Stable supervised-device id (mTLS client-cert subject). Empty if unknown.
    pub device_id: Option<String>,
    /// Application/build version string for the profile.
    pub app_version: Option<String>,
    /// Most recent measured RTT to the cluster gateway, in milliseconds.
    pub rtt_ms: Option<u32>,
    /// Battery percentage if the platform reports it (`0..=100`). `None` leaves
    /// the profile's `battery_pct` at `-1` (unknown / on mains).
    pub battery_pct: Option<i32>,
    /// Whether the device is currently running on battery (vs. mains).
    pub on_battery: Option<bool>,
}

/// Detect this device's capabilities into a [`DeviceProfile`].
///
/// Best-effort: a probe that fails leaves its field at a conservative default
/// rather than erroring. Convenience wrapper over
/// [`detect_device_profile_with`] using default hints.
pub fn detect_device_profile() -> DeviceProfile {
    detect_device_profile_with(&DetectionHints::default())
}

/// Detect this device's capabilities, folding in any caller-supplied [`DetectionHints`].
pub fn detect_device_profile_with(hints: &DetectionHints) -> DeviceProfile {
    let mut sys = System::new();
    sys.refresh_memory();
    sys.refresh_cpu_all();

    let platform = detect_platform();
    let cpu = detect_cpu_model(&sys);
    let cpu_cores = detect_cpu_cores(&sys);
    let ram_mb = detect_ram_mb(&sys);
    let gpu = detect_gpu();
    let exec_providers = exec_providers_for(&platform, &gpu)
        .into_iter()
        .map(|p| p as i32)
        .collect();

    DeviceProfile {
        device_id: hints.device_id.clone().unwrap_or_default(),
        platform,
        cpu,
        cpu_cores,
        ram_mb,
        gpu,
        exec_providers,
        battery_pct: hints.battery_pct.unwrap_or(-1),
        on_battery: hints.on_battery.unwrap_or(false),
        rtt_ms: hints.rtt_ms.unwrap_or(0),
        app_version: hints.app_version.clone().unwrap_or_default(),
    }
}

/// Canonical platform string (matches the values documented on
/// `DeviceProfile.platform`: `"windows" | "linux" | "android" | "macos"`).
///
/// Android is a Linux kernel, so `cfg(target_os = "android")` is checked before
/// the generic `linux` arm.
pub fn detect_platform() -> String {
    if cfg!(target_os = "android") {
        "android"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "macos") || cfg!(target_os = "ios") {
        "macos"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        "unknown"
    }
    .to_owned()
}

/// The best-first ONNX execution-provider list for a platform + GPU presence.
///
/// CPU is always last and always present (the `ort` baseline). GPU-accelerated
/// providers are listed first **only on platforms where they apply** and only
/// when a GPU string was detected: Windows → DirectML, Linux → CUDA then
/// TensorRT, macOS → CoreML, Android → NNAPI. `ort` tries them in order and
/// silently falls back to CPU, so an over-optimistic list is safe.
pub fn exec_providers_for(platform: &str, gpu: &str) -> Vec<ExecutionProvider> {
    let has_gpu = !gpu.trim().is_empty();
    match platform {
        // Windows: DirectML is the broad GPU path; CPU floor.
        "windows" => {
            if has_gpu {
                vec![ExecutionProvider::Directml, ExecutionProvider::Cpu]
            } else {
                vec![ExecutionProvider::Cpu]
            }
        }
        // Android: NNAPI (and QNN on Qualcomm) before CPU.
        "android" => vec![ExecutionProvider::Nnapi, ExecutionProvider::Cpu],
        // Apple: CoreML before CPU.
        "macos" => vec![ExecutionProvider::Coreml, ExecutionProvider::Cpu],
        // Linux / everything else: prefer CUDA→TensorRT when a discrete GPU is
        // visible, else CPU only.
        "linux" => {
            if has_gpu {
                vec![
                    ExecutionProvider::Cuda,
                    ExecutionProvider::Tensorrt,
                    ExecutionProvider::Cpu,
                ]
            } else {
                vec![ExecutionProvider::Cpu]
            }
        }
        _ => vec![ExecutionProvider::Cpu],
    }
}

/// CPU model / brand string, e.g. `"AMD Ryzen 9 5900X 12-Core Processor"`.
/// Empty string when unavailable.
fn detect_cpu_model(sys: &System) -> String {
    sys.cpus()
        .first()
        .map(|c| c.brand().trim().to_owned())
        .unwrap_or_default()
}

/// Logical core count, preferring physical-core count when the OS exposes it.
/// Falls back to the logical CPU count from `sysinfo`, then to `1`.
fn detect_cpu_cores(sys: &System) -> u32 {
    let logical = sys.cpus().len();
    let physical = sys.physical_core_count().unwrap_or(0);
    let cores = if physical > 0 { physical } else { logical };
    u32::try_from(cores.max(1)).unwrap_or(u32::MAX)
}

/// Installed RAM in mebibytes. `sysinfo` reports total memory in **bytes**.
fn detect_ram_mb(sys: &System) -> u64 {
    sys.total_memory() / (1024 * 1024)
}

/// Best-effort GPU model string. `sysinfo` has no GPU API, so this is a hook for
/// platform-specific detection wired in by `aegis-net`/`aegis-infer` later
/// (DXGI on Windows, Metal on macOS, `/sys`/NVML on Linux). For now it honours an
/// explicit `AEGIS_GPU` override so operators and tests can pin a value without
/// pulling a heavy GPU-enumeration dependency into this foundational crate.
///
/// Returns an empty string when no GPU is known (the documented `DeviceProfile`
/// "no GPU" sentinel), which keeps the exec-provider list CPU-only.
fn detect_gpu() -> String {
    std::env::var("AEGIS_GPU").unwrap_or_default().trim().to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_a_profile_without_panicking() {
        let p = detect_device_profile();
        // CPU core count and RAM are always at least the conservative floor.
        assert!(p.cpu_cores >= 1, "expected at least one core");
        // Exec providers are never empty: CPU is the floor.
        assert!(!p.exec_providers.is_empty());
        assert!(p
            .exec_providers
            .contains(&(ExecutionProvider::Cpu as i32)));
        // Platform is one of the canonical strings (or "unknown" on exotic hosts).
        assert!(matches!(
            p.platform.as_str(),
            "windows" | "linux" | "android" | "macos" | "unknown"
        ));
    }

    #[test]
    fn hints_are_folded_in() {
        let hints = DetectionHints {
            device_id: Some("dev-99".to_owned()),
            app_version: Some("1.2.3".to_owned()),
            rtt_ms: Some(42),
            battery_pct: Some(80),
            on_battery: Some(true),
        };
        let p = detect_device_profile_with(&hints);
        assert_eq!(p.device_id, "dev-99");
        assert_eq!(p.app_version, "1.2.3");
        assert_eq!(p.rtt_ms, 42);
        assert_eq!(p.battery_pct, 80);
        assert!(p.on_battery);
    }

    #[test]
    fn unknown_battery_is_minus_one() {
        let p = detect_device_profile();
        assert_eq!(p.battery_pct, -1);
        assert!(!p.on_battery);
    }

    #[test]
    fn windows_prefers_directml_then_cpu_when_gpu_present() {
        let eps = exec_providers_for("windows", "NVIDIA GeForce RTX 4070");
        assert_eq!(
            eps,
            vec![ExecutionProvider::Directml, ExecutionProvider::Cpu]
        );
    }

    #[test]
    fn windows_cpu_only_without_gpu() {
        assert_eq!(exec_providers_for("windows", ""), vec![ExecutionProvider::Cpu]);
    }

    #[test]
    fn android_prefers_nnapi_then_cpu() {
        assert_eq!(
            exec_providers_for("android", ""),
            vec![ExecutionProvider::Nnapi, ExecutionProvider::Cpu]
        );
    }

    #[test]
    fn macos_prefers_coreml_then_cpu() {
        assert_eq!(
            exec_providers_for("macos", "Apple M2"),
            vec![ExecutionProvider::Coreml, ExecutionProvider::Cpu]
        );
    }

    #[test]
    fn linux_prefers_cuda_tensorrt_cpu_with_gpu() {
        assert_eq!(
            exec_providers_for("linux", "NVIDIA A100"),
            vec![
                ExecutionProvider::Cuda,
                ExecutionProvider::Tensorrt,
                ExecutionProvider::Cpu
            ]
        );
    }

    #[test]
    fn cpu_floor_is_always_present() {
        for (plat, gpu) in [
            ("windows", ""),
            ("android", ""),
            ("macos", ""),
            ("linux", ""),
            ("weirdos", "some-gpu"),
        ] {
            let eps = exec_providers_for(plat, gpu);
            assert!(
                eps.contains(&ExecutionProvider::Cpu),
                "CPU missing for {plat}"
            );
            assert_eq!(
                eps.last(),
                Some(&ExecutionProvider::Cpu),
                "CPU not last for {plat}"
            );
        }
    }
}
