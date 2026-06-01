//! Configuration loading via `figment` (TOML file + env overrides).
//!
//! Every Aegis binary (`aegis-client`, `aegis-server`, …) loads one [`Config`].
//! The layering, lowest-to-highest precedence, is:
//!
//! 1. [`Config::default`] — compiled-in safe defaults (fail-safe per PLAN §3).
//! 2. A TOML file (path passed to [`Config::load`], or `AEGIS_CONFIG`).
//! 3. Environment variables prefixed `AEGIS_`, nested with `__`
//!    (e.g. `AEGIS_SMTP__HOST=mail.example.com`, `AEGIS_CLUSTER__ROLE=worker`).
//!
//! The structs are deliberately `#[serde(default)]` and grouped so new fields
//! can be added without breaking existing config files — keep it extensible.
//! No secrets are baked in; SMTP credentials et al. come from the file or env.

use std::path::{Path, PathBuf};

use figment::{
    providers::{Env, Format, Serialized, Toml},
    Figment,
};
use serde::{Deserialize, Serialize};

use crate::telemetry::LoggingConfig;

/// Environment variable naming the config file when [`Config::load_default`] is used.
pub const CONFIG_PATH_ENV: &str = "AEGIS_CONFIG";

/// Prefix for environment-variable overrides (`AEGIS_SMTP__HOST`, …).
pub const ENV_PREFIX: &str = "AEGIS_";

/// Top-level Aegis configuration. One per process.
///
/// Grouped into stable sub-structs (`smtp`, `cluster`, `policy`, `models`,
/// `logging`) so the TOML/env surface is namespaced and forward-compatible.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// This node/device's role + cluster wiring.
    pub cluster: ClusterConfig,
    /// Guardian-alert email (SMTP / Gmail) settings.
    pub smtp: SmtpConfig,
    /// Filesystem paths to policy/lexicon assets.
    pub policy: PolicyPaths,
    /// Model directory + checksum-registry location (no models loaded here — this
    /// crate has **no AI/ML**; the path is consumed by analyzer crates).
    pub models: ModelConfig,
    /// Local diagnostic logging (no telemetry).
    pub logging: LoggingConfig,
}

/// Cluster / transport wiring.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct ClusterConfig {
    /// Node role: `"lb" | "worker" | "all-in-one" | "client"`.
    pub role: String,
    /// gRPC endpoint this node binds (server roles) — `host:port`.
    pub bind_addr: String,
    /// Cluster gateway the client/worker dials — `host:port`.
    pub gateway_addr: String,
    /// Gossip seed nodes for SWIM membership (`host:port`).
    pub seed_nodes: Vec<String>,
    /// Directory holding mTLS material (CA, node cert, key).
    pub tls_dir: Option<PathBuf>,
    /// Postgres connection URL for shared server state (server roles only).
    pub database_url: Option<String>,
}

impl Default for ClusterConfig {
    fn default() -> Self {
        ClusterConfig {
            role: "all-in-one".to_owned(),
            bind_addr: "127.0.0.1:8443".to_owned(),
            gateway_addr: "127.0.0.1:8443".to_owned(),
            seed_nodes: Vec::new(),
            tls_dir: None,
            database_url: None,
        }
    }
}

/// Guardian-alert email settings consumed by `aegis-alert`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct SmtpConfig {
    /// Whether alert email is enabled at all.
    pub enabled: bool,
    /// SMTP relay host.
    pub host: String,
    /// SMTP relay port (587 submission by default).
    pub port: u16,
    /// SMTP username (empty = unauthenticated relay).
    pub username: String,
    /// SMTP password / app-password. Prefer supplying via env, not the file.
    pub password: String,
    /// `From:` address on guardian alerts.
    pub from: String,
    /// Guardian recipient addresses.
    pub to: Vec<String>,
    /// Use STARTTLS (true) vs. implicit TLS / plaintext.
    pub starttls: bool,
}

impl Default for SmtpConfig {
    fn default() -> Self {
        SmtpConfig {
            enabled: false,
            host: String::new(),
            port: 587,
            username: String::new(),
            password: String::new(),
            from: String::new(),
            to: Vec::new(),
            starttls: true,
        }
    }
}

/// Filesystem paths to policy + lexicon assets (consumed by `aegis-policy` /
/// `aegis-text`). Paths only — this crate does not parse them.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PolicyPaths {
    /// Path to the policy/threshold definition file.
    pub policy_file: Option<PathBuf>,
    /// Path to the grooming lexicon / rule pack directory.
    pub lexicon_dir: Option<PathBuf>,
    /// Path to age-profile definitions.
    pub age_profiles: Option<PathBuf>,
}

/// Model directory + checksum registry. This crate owns the **path config**, not
/// the loading: analyzer crates (`aegis-vision`/`-audio`/`-text`) load and verify
/// models against the SHA256 pins under `checksums_file`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ModelConfig {
    /// Directory containing downloaded ONNX model files.
    pub model_dir: Option<PathBuf>,
    /// Path to the SHA256 checksum-pin registry (model id → expected hash).
    pub checksums_file: Option<PathBuf>,
}

impl Config {
    /// Build the layered figment (defaults → optional TOML → env) without
    /// extracting it yet. Useful for callers that want to merge extra providers.
    pub fn figment(path: Option<&Path>) -> Figment {
        let mut fig = Figment::from(Serialized::defaults(Config::default()));
        if let Some(p) = path {
            fig = fig.merge(Toml::file(p));
        }
        // Env overrides last (highest precedence). `AEGIS_` prefix, `__` nests:
        // `AEGIS_SMTP__HOST` → smtp.host, `AEGIS_CLUSTER__SEED_NODES` (CSV-ish).
        fig.merge(Env::prefixed(ENV_PREFIX).split("__"))
    }

    /// Load configuration, layering a TOML file at `path` (if given) over the
    /// compiled-in defaults, then applying `AEGIS_`-prefixed env overrides.
    ///
    /// A `path` that does not exist is **not** an error from `figment` itself
    /// (the provider is skipped); pass `None` to skip the file entirely. Use
    /// [`Config::load_required`] if a missing file must fail.
    pub fn load(path: Option<&Path>) -> crate::Result<Config> {
        Self::figment(path).extract().map_err(Into::into)
    }

    /// Like [`Config::load`] but errors if `path` does not exist on disk.
    pub fn load_required(path: &Path) -> crate::Result<Config> {
        if !path.exists() {
            return Err(crate::Error::ConfigNotFound(path.to_path_buf()));
        }
        Self::load(Some(path))
    }

    /// Load using the path from `$AEGIS_CONFIG` if set, else defaults + env only.
    pub fn load_default() -> crate::Result<Config> {
        match std::env::var_os(CONFIG_PATH_ENV) {
            Some(p) => Self::load(Some(Path::new(&p))),
            None => Self::load(None),
        }
    }

    /// Validate cross-field invariants the type system can't express. Cheap,
    /// pure; call after loading. Fail-safe: surfaces misconfiguration early.
    pub fn validate(&self) -> crate::Result<()> {
        const ROLES: [&str; 4] = ["lb", "worker", "all-in-one", "client"];
        if !ROLES.contains(&self.cluster.role.as_str()) {
            return Err(crate::Error::invalid_value(format!(
                "cluster.role must be one of {ROLES:?}, got {:?}",
                self.cluster.role
            )));
        }
        if self.smtp.enabled {
            if self.smtp.host.trim().is_empty() {
                return Err(crate::Error::config("smtp.enabled but smtp.host is empty"));
            }
            if self.smtp.to.is_empty() {
                return Err(crate::Error::config(
                    "smtp.enabled but no recipients in smtp.to",
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use figment::Jail;

    #[test]
    fn defaults_are_safe() {
        let c = Config::default();
        assert_eq!(c.cluster.role, "all-in-one");
        assert!(!c.smtp.enabled);
        assert_eq!(c.smtp.port, 587);
        c.validate().expect("default config should validate");
    }

    #[test]
    fn loads_toml_and_env_layers() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "aegis.toml",
                r#"
                [cluster]
                role = "worker"
                bind_addr = "0.0.0.0:9000"

                [smtp]
                enabled = true
                host = "mail.example.com"
                to = ["guardian@example.com"]

                [models]
                model_dir = "/opt/aegis/models"
                "#,
            )?;

            // Env override should win over the TOML value.
            jail.set_env("AEGIS_CLUSTER__BIND_ADDR", "0.0.0.0:9999");
            jail.set_env("AEGIS_SMTP__PASSWORD", "from-env");

            let cfg = Config::load(Some(Path::new("aegis.toml")))
                .expect("config should load");

            assert_eq!(cfg.cluster.role, "worker");
            assert_eq!(cfg.cluster.bind_addr, "0.0.0.0:9999"); // env beat toml
            assert!(cfg.smtp.enabled);
            assert_eq!(cfg.smtp.host, "mail.example.com");
            assert_eq!(cfg.smtp.password, "from-env");
            assert_eq!(cfg.smtp.to, vec!["guardian@example.com".to_owned()]);
            assert_eq!(
                cfg.models.model_dir.as_deref(),
                Some(Path::new("/opt/aegis/models"))
            );
            cfg.validate().expect("loaded config should validate");
            Ok(())
        });
    }

    #[test]
    fn missing_required_file_errors() {
        let err = Config::load_required(Path::new("definitely-not-here.toml"))
            .unwrap_err();
        assert!(matches!(err, crate::Error::ConfigNotFound(_)));
    }

    #[test]
    fn unknown_role_fails_validation() {
        let mut c = Config::default();
        c.cluster.role = "overlord".to_owned();
        assert!(matches!(c.validate(), Err(crate::Error::InvalidValue(_))));
    }

    #[test]
    fn enabled_smtp_requires_host_and_recipients() {
        let mut c = Config::default();
        c.smtp.enabled = true;
        assert!(c.validate().is_err()); // no host

        c.smtp.host = "mail.example.com".to_owned();
        assert!(c.validate().is_err()); // no recipients

        c.smtp.to = vec!["g@example.com".to_owned()];
        assert!(c.validate().is_ok());
    }
}
