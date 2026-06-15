//! Per-user config dir for the staff console (desktop). Kept SEPARATE from the
//! guardian Manager's `Bulwark` dir so a staff token can never land in a
//! guardian profile (and vice versa).

use std::path::PathBuf;

pub fn app_config_dir() -> PathBuf {
    if let Some(local) = std::env::var_os("LOCALAPPDATA").filter(|s| !s.is_empty()) {
        PathBuf::from(local).join("BulwarkStaff")
    } else if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME").filter(|s| !s.is_empty()) {
        PathBuf::from(xdg).join("bulwark-staff")
    } else if let Some(home) = std::env::var_os("HOME").filter(|s| !s.is_empty()) {
        PathBuf::from(home).join(".config/bulwark-staff")
    } else {
        std::env::temp_dir().join("bulwark-staff")
    }
}
