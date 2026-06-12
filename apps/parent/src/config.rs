//! Filesystem/config layer: bundled-exe discovery, the per-user config dir,
//! NSFW-model/ffmpeg provisioning, and the CA + segment-store paths.

/// Locate a bundled filter binary `name` (e.g. `bulwark_proxy.exe`): an explicit
/// `env_key` override first, else next to THIS executable (where a packaged
/// release ships the filter binaries beside the console). `None` → the caller
/// falls back to a dev `cargo run`. No machine-specific path is ever hard-coded.
pub fn sibling_exe(env_key: &str, name: &str) -> Option<std::path::PathBuf> {
    if let Some(p) = std::env::var_os(env_key).filter(|s| !s.is_empty()) {
        let p = std::path::PathBuf::from(p);
        if p.exists() {
            return Some(p);
        }
    }
    let beside = std::env::current_exe().ok()?.parent()?.join(name);
    beside.exists().then_some(beside)
}

/// The bundled content-filtering proxy (`BULWARK_PROXY_EXE` override, else beside us).
pub fn proxy_exe() -> Option<std::path::PathBuf> {
    sibling_exe("BULWARK_PROXY_EXE", "bulwark_proxy.exe")
}

/// The bundled transparent-VPN binary (`BULWARK_VPN_EXE` override, else beside us).
/// VPN mode captures ALL traffic via a TUN and needs Administrator; `bulwark_vpn`
/// self-checks elevation and exits immediately if not elevated.
pub fn vpn_exe() -> Option<std::path::PathBuf> {
    sibling_exe("BULWARK_VPN_EXE", "bulwark_vpn.exe")
}

/// Repo root for the dev `cargo run` fallback only: `BULWARK_REPO_ROOT` or the cwd.
pub fn repo_root() -> std::path::PathBuf {
    std::env::var_os("BULWARK_REPO_ROOT")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| ".".into()))
}

/// Android app-private files dir (`Context.getFilesDir()`, e.g.
/// `/data/user/0/co.predatorhunters.bulwark.manager/files`) via the JNI context
/// that dioxus' mobile glue registers with `ndk-context` before app start.
/// `None` if any JNI step fails — callers fall back to the env-based chain.
#[cfg(target_os = "android")]
pub fn android_files_dir() -> Option<std::path::PathBuf> {
    let ctx = ndk_context::android_context();
    // SAFETY (audited FFI): vm()/context() are the live JavaVM + Activity
    // pointers ndk-context was initialized with by dioxus-desktop's android
    // glue; we only read through them from an attached thread.
    let vm = unsafe { jni::JavaVM::from_raw(ctx.vm().cast()) }.ok()?;
    let mut env = vm.attach_current_thread().ok()?;
    let context = unsafe { jni::objects::JObject::from_raw(ctx.context().cast()) };
    let files_dir = env
        .call_method(&context, "getFilesDir", "()Ljava/io/File;", &[])
        .ok()?
        .l()
        .ok()?;
    let abs = env
        .call_method(&files_dir, "getAbsolutePath", "()Ljava/lang/String;", &[])
        .ok()?
        .l()
        .ok()?;
    let s: String = env
        .get_string(&jni::objects::JString::from(abs))
        .ok()?
        .into();
    if s.is_empty() {
        return None;
    }
    Some(std::path::PathBuf::from(s))
}

/// Per-user config dir. Android: the app-private files dir — the ONLY reliably
/// writable location (`%LOCALAPPDATA%`/`$HOME` are unset in an app process and
/// `temp_dir()` is the unwritable `/data/local/tmp`). The server choice,
/// per-server sessions/tokens, and the pinned `cluster_ca.pem` that on-device
/// pairing requires all live under here. Desktop resolution is unchanged.
pub fn app_config_dir() -> std::path::PathBuf {
    use std::path::PathBuf;
    #[cfg(target_os = "android")]
    if let Some(files) = android_files_dir() {
        return files.join("bulwark");
    }
    if let Some(local) = std::env::var_os("LOCALAPPDATA").filter(|s| !s.is_empty()) {
        PathBuf::from(local).join("Bulwark")
    } else if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME").filter(|s| !s.is_empty()) {
        PathBuf::from(xdg).join("bulwark")
    } else if let Some(home) = std::env::var_os("HOME").filter(|s| !s.is_empty()) {
        PathBuf::from(home).join(".config/bulwark")
    } else {
        std::env::temp_dir().join("bulwark")
    }
}

pub fn config_value(name: &str) -> Option<String> {
    std::fs::read_to_string(app_config_dir().join(name))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

pub fn env_or_config(env: &str, file: &str) -> Option<String> {
    std::env::var(env)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| config_value(file))
}

/// The NSFW model path to hand the filter. Unset means the filter runs its
/// fail-open stub; we never invent a model path.
pub fn nsfw_model() -> Option<String> {
    env_or_config("BULWARK_NSFW_MODEL", "nsfw_model.txt")
}

/// Human-readable model status for the diagnostics panel.
pub fn nsfw_model_display() -> String {
    nsfw_model()
        .unwrap_or_else(|| "(unset — set BULWARK_NSFW_MODEL; filter runs fail-open)".to_string())
}

/// Optional pinned ffmpeg binary to hand the video pipeline.
pub fn ffmpeg_binary() -> Option<String> {
    env_or_config("FFMPEG_BINARY", "ffmpeg_binary.txt")
        .or_else(|| env_or_config("BULWARK_FFMPEG_BINARY", "ffmpeg_binary.txt"))
}

pub fn ffmpeg_display() -> String {
    ffmpeg_binary().unwrap_or_else(|| "(PATH lookup — set FFMPEG_BINARY if needed)".to_string())
}

/// Path to the per-install root CA the proxy uses to decrypt HTTPS. We don't
/// install it (that's a one-time `certutil` the user runs); we only report
/// whether it has been generated, and surface the trust command if needed.
pub fn ca_pem_path() -> std::path::PathBuf {
    // Identical `%LOCALAPPDATA%\Bulwark\...` path as before on Windows (that IS
    // the config dir); on Android this resolves inside the app files dir
    // instead of an unwritable relative `Bulwark\` path.
    app_config_dir().join("bulwark-root-ca.pem")
}

/// The per-user segment store directory. MUST mirror
/// `bulwark_video::store::default_segments_dir()` exactly — the child writes blobs
/// there; this lean parent UI deliberately does NOT depend on `bulwark-video` (it
/// would drag the whole video/vision/ONNX tree into the desktop app), so the
/// resolution is duplicated here. Keep the two in sync: Windows `%LOCALAPPDATA%`,
/// then `$XDG_DATA_HOME`, then `$HOME/.local/share`, else the temp dir.
pub fn segments_dir() -> std::path::PathBuf {
    use std::path::PathBuf;
    // Android: the local segment store never exists on the manager's phone (the
    // child-side filter writes it on ITS device) — point at the app files dir
    // so reads are a clean NotFound ("missing/purged") rather than touching the
    // unreadable /data/local/tmp.
    #[cfg(target_os = "android")]
    if let Some(files) = android_files_dir() {
        return files.join("bulwark-segments");
    }
    if let Some(local) = std::env::var_os("LOCALAPPDATA").filter(|s| !s.is_empty()) {
        return PathBuf::from(local).join("Bulwark").join("segments");
    }
    if let Some(xdg) = std::env::var_os("XDG_DATA_HOME").filter(|s| !s.is_empty()) {
        return PathBuf::from(xdg).join("bulwark").join("segments");
    }
    if let Some(home) = std::env::var_os("HOME").filter(|s| !s.is_empty()) {
        return PathBuf::from(home).join(".local/share/bulwark/segments");
    }
    std::env::temp_dir().join("bulwark-segments")
}
