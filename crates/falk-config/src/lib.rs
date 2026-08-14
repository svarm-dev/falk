//! Layered configuration for falk.
//!
//! Precedence (highest first): **CLI flags > `FALK_*` env > `falk.toml` > defaults**.
//!
//! Dual identity lives on [`Mode`]:
//! - [`Mode::Standalone`] is the default and is fully useful with no Svärm.
//! - [`Mode::Svarm`] is opt-in (`--svarm`, `[svarm] enabled = true`, or `FALK_SVARM`).
//!   It is a runtime switch, not a Cargo feature and not an Elixir dependency.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};

/// How falk presents itself to the parent process.
///
/// Standalone is the default: raw-mode PTY transparency when stdin is a TTY.
/// Svärm mode is additive: outer interface is plain stdio (Svärm `Port.open`
/// compatible) while the inner agent still gets a real PTY. Svärm `Port.open`
/// cannot carry SIGWINCH, so resize in Svärm mode is a documented limitation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    #[default]
    Standalone,
    Svarm,
}

impl FromStr for Mode {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "standalone" | "default" => Ok(Self::Standalone),
            "svarm" | "svaerm" => Ok(Self::Svarm),
            other => Err(ConfigError::InvalidValue {
                key: "mode".into(),
                value: other.into(),
            }),
        }
    }
}

/// Security engine enforcement after a fail-closed finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum EnforcementMode {
    Warn,
    #[default]
    Block,
    Kill,
}

impl FromStr for EnforcementMode {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "warn" => Ok(Self::Warn),
            "block" => Ok(Self::Block),
            "kill" => Ok(Self::Kill),
            other => Err(ConfigError::InvalidValue {
                key: "enforcement".into(),
                value: other.into(),
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub general: GeneralConfig,
    #[serde(default)]
    pub pty: PtyConfig,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub finops: FinopsConfig,
    #[serde(default)]
    pub svarm: SvarmConfig,
    #[serde(default)]
    pub tracing: TracingConfig,
}

impl Config {
    pub fn is_svarm(&self) -> bool {
        self.general.mode == Mode::Svarm || self.svarm.enabled
    }

    pub fn effective_mode(&self) -> Mode {
        if self.is_svarm() {
            Mode::Svarm
        } else {
            Mode::Standalone
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneralConfig {
    #[serde(default)]
    pub mode: Mode,
    #[serde(default)]
    pub ticket: String,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            mode: Mode::Standalone,
            ticket: String::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PtyConfig {
    #[serde(default = "default_rows")]
    pub rows: u16,
    #[serde(default = "default_cols")]
    pub cols: u16,
    #[serde(default = "default_kill_grace_ms")]
    pub kill_grace_ms: u64,
    #[serde(default = "default_true")]
    pub raw_mode: bool,
}

impl Default for PtyConfig {
    fn default() -> Self {
        Self {
            rows: default_rows(),
            cols: default_cols(),
            kill_grace_ms: default_kill_grace_ms(),
            raw_mode: true,
        }
    }
}

fn default_rows() -> u16 {
    24
}
fn default_cols() -> u16 {
    80
}
fn default_kill_grace_ms() -> u64 {
    1500
}
fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityConfig {
    #[serde(default)]
    pub enforcement: EnforcementMode,
    #[serde(default = "default_max_ast_depth")]
    pub max_ast_depth: usize,
    #[serde(default = "default_max_ast_nodes")]
    pub max_ast_nodes: usize,
    #[serde(default)]
    pub allowlist: AllowlistConfig,
    #[serde(default)]
    pub blocklist: BlocklistConfig,
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub redaction: RedactionConfig,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            enforcement: EnforcementMode::Block,
            max_ast_depth: default_max_ast_depth(),
            max_ast_nodes: default_max_ast_nodes(),
            allowlist: AllowlistConfig::default(),
            blocklist: BlocklistConfig::default(),
            network: NetworkConfig::default(),
            redaction: RedactionConfig::default(),
        }
    }
}

fn default_max_ast_depth() -> usize {
    64
}
fn default_max_ast_nodes() -> usize {
    4096
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AllowlistConfig {
    #[serde(default)]
    pub commands: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct BlocklistConfig {
    #[serde(default)]
    pub commands: Vec<String>,
    #[serde(default)]
    pub sensitive_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct NetworkConfig {
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    #[serde(default)]
    pub blocked_domains: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactionConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_holdback")]
    pub holdback_bytes: usize,
}

impl Default for RedactionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            holdback_bytes: default_holdback(),
        }
    }
}

fn default_holdback() -> usize {
    512
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FinopsConfig {
    #[serde(default, deserialize_with = "empty_decimal")]
    pub soft_limit_usd: Option<Decimal>,
    #[serde(default, deserialize_with = "empty_decimal")]
    pub hard_limit_usd: Option<Decimal>,
    #[serde(default)]
    pub max_prompt_tokens: u64,
    #[serde(default)]
    pub max_completion_tokens: u64,
    #[serde(default = "default_true")]
    pub estimator: bool,
    #[serde(default)]
    #[serde(rename = "loop")]
    pub loop_detect: LoopConfig,
    #[serde(default)]
    pub providers: BTreeMap<String, ProviderPricing>,
}

impl Default for FinopsConfig {
    fn default() -> Self {
        Self {
            soft_limit_usd: None,
            hard_limit_usd: None,
            max_prompt_tokens: 0,
            max_completion_tokens: 0,
            estimator: true,
            loop_detect: LoopConfig::default(),
            providers: default_providers(),
        }
    }
}

fn empty_decimal<'de, D>(deserializer: D) -> Result<Option<Decimal>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<toml::Value>::deserialize(deserializer)?;
    match value {
        None => Ok(None),
        Some(toml::Value::String(s)) if s.trim().is_empty() => Ok(None),
        Some(toml::Value::String(s)) => s.parse().map(Some).map_err(serde::de::Error::custom),
        Some(toml::Value::Float(_)) => Err(serde::de::Error::custom(
            "USD values must be quoted decimal strings (e.g. \"0.10\"), not toml floats",
        )),
        Some(toml::Value::Integer(i)) => Ok(Some(Decimal::from(i))),
        Some(other) => Err(serde::de::Error::custom(format!(
            "invalid decimal: {other}"
        ))),
    }
}

fn default_providers() -> BTreeMap<String, ProviderPricing> {
    let mut map = BTreeMap::new();
    map.insert(
        "anthropic".into(),
        ProviderPricing {
            input_per_mtok: dec("3.00"),
            output_per_mtok: dec("15.00"),
            cache_read_per_mtok: dec("0.30"),
            cache_write_per_mtok: dec("3.75"),
        },
    );
    map.insert(
        "openai".into(),
        ProviderPricing {
            input_per_mtok: dec("2.50"),
            output_per_mtok: dec("10.00"),
            cache_read_per_mtok: dec("1.25"),
            cache_write_per_mtok: dec("2.50"),
        },
    );
    map
}

fn dec(s: &str) -> Decimal {
    Decimal::from_str(s).unwrap_or(Decimal::ZERO)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoopConfig {
    #[serde(default = "default_loop_window")]
    pub window: usize,
    #[serde(default = "default_loop_threshold")]
    pub repeat_threshold: usize,
    #[serde(default = "default_failure_markers")]
    pub failure_markers: Vec<String>,
}

impl Default for LoopConfig {
    fn default() -> Self {
        Self {
            window: default_loop_window(),
            repeat_threshold: default_loop_threshold(),
            failure_markers: default_failure_markers(),
        }
    }
}

fn default_loop_window() -> usize {
    8
}
fn default_loop_threshold() -> usize {
    4
}
fn default_failure_markers() -> Vec<String> {
    ["error", "failed", "permission denied", "traceback"]
        .into_iter()
        .map(str::to_string)
        .collect()
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProviderPricing {
    #[serde(default)]
    pub input_per_mtok: Decimal,
    #[serde(default)]
    pub output_per_mtok: Decimal,
    #[serde(default)]
    pub cache_read_per_mtok: Decimal,
    #[serde(default)]
    pub cache_write_per_mtok: Decimal,
}

impl Default for ProviderPricing {
    fn default() -> Self {
        Self {
            input_per_mtok: Decimal::ZERO,
            output_per_mtok: Decimal::ZERO,
            cache_read_per_mtok: Decimal::ZERO,
            cache_write_per_mtok: Decimal::ZERO,
        }
    }
}

/// Svärm-mode settings. Off by default; never pulls in Elixir or Svärm crates.
///
/// falk never writes Task fields `status`, `wait_reason`, `pending_question`,
/// or `attempts` — those belong exclusively to the Svärm Orchestrator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SvarmConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub run_id: String,
    #[serde(default)]
    pub task_id: String,
    #[serde(default)]
    pub ndjson_path: String,
    #[serde(default)]
    pub ndjson_fd: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TracingConfig {
    #[serde(default = "default_trace_level")]
    pub level: String,
}

impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            level: default_trace_level(),
        }
    }
}

fn default_trace_level() -> String {
    "warn".into()
}

/// CLI-layer overrides. `None` means "not provided on the command line".
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CliOverrides {
    pub config_path: Option<PathBuf>,
    pub hard_limit: Option<Decimal>,
    pub soft_limit: Option<Decimal>,
    pub svarm: Option<bool>,
    pub run_id: Option<String>,
    pub task_id: Option<String>,
    pub ticket: Option<String>,
    pub enforcement: Option<EnforcementMode>,
    pub ndjson_path: Option<PathBuf>,
    pub mode: Option<Mode>,
}

/// Environment-layer overrides parsed from `FALK_*`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EnvOverrides {
    pub config_path: Option<PathBuf>,
    pub hard_limit: Option<Decimal>,
    pub soft_limit: Option<Decimal>,
    pub svarm: Option<bool>,
    pub run_id: Option<String>,
    pub task_id: Option<String>,
    pub ticket: Option<String>,
    pub enforcement: Option<EnforcementMode>,
    pub ndjson_path: Option<PathBuf>,
    pub mode: Option<Mode>,
    pub ndjson_fd: Option<i32>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("invalid {key}: {value}")]
    InvalidValue { key: String, value: String },
    #[error("failed to read config file {path}: {message}")]
    Io { path: String, message: String },
    #[error("failed to parse config: {0}")]
    Parse(String),
}

/// Load `falk.toml` (or the given path). Missing file is not an error when
/// `required` is false — defaults apply.
pub fn load_file(path: &Path) -> Result<Config, ConfigError> {
    let raw = fs::read_to_string(path).map_err(|err| ConfigError::Io {
        path: path.display().to_string(),
        message: err.to_string(),
    })?;
    parse_toml(&raw)
}

/// Parse a TOML document into [`Config`]. Empty / missing sections use defaults.
pub fn parse_toml(raw: &str) -> Result<Config, ConfigError> {
    let mut parsed: Config =
        toml::from_str(raw).map_err(|err| ConfigError::Parse(err.to_string()))?;
    if parsed.finops.providers.is_empty() {
        parsed.finops.providers = default_providers();
    }
    Ok(parsed)
}

/// Read `FALK_*` from the process environment.
pub fn env_overrides_from_os() -> Result<EnvOverrides, ConfigError> {
    env_overrides_from_pairs(env::vars())
}

/// Parse env-style key/value pairs. Keys are matched case-insensitively.
pub fn env_overrides_from_pairs<I, K, V>(pairs: I) -> Result<EnvOverrides, ConfigError>
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<str>,
    V: AsRef<str>,
{
    let mut out = EnvOverrides::default();
    for (key, value) in pairs {
        let key = key.as_ref();
        let value = value.as_ref();
        let Some(name) = strip_falk_prefix(key) else {
            continue;
        };
        match name {
            "CONFIG" | "CONFIG_PATH" => {
                out.config_path = Some(PathBuf::from(value));
            }
            "HARD_LIMIT" | "HARD_LIMIT_USD" => {
                out.hard_limit = parse_optional_decimal("FALK_HARD_LIMIT", value)?;
            }
            "SOFT_LIMIT" | "SOFT_LIMIT_USD" => {
                out.soft_limit = parse_optional_decimal("FALK_SOFT_LIMIT", value)?;
            }
            "SVARM" => {
                out.svarm = Some(parse_bool(value));
            }
            "MODE" => {
                out.mode = Some(value.parse()?);
            }
            "RUN_ID" => out.run_id = Some(value.to_string()),
            "TASK_ID" => out.task_id = Some(value.to_string()),
            "TICKET" => out.ticket = Some(value.to_string()),
            "ENFORCEMENT" => out.enforcement = Some(value.parse()?),
            "NDJSON" | "NDJSON_PATH" => {
                out.ndjson_path = Some(PathBuf::from(value));
            }
            "NDJSON_FD" => {
                out.ndjson_fd = Some(value.parse().map_err(|_| ConfigError::InvalidValue {
                    key: "FALK_NDJSON_FD".into(),
                    value: value.into(),
                })?);
            }
            _ => {}
        }
    }
    Ok(out)
}

fn strip_falk_prefix(key: &str) -> Option<&str> {
    let upper = key.to_ascii_uppercase();
    if let Some(rest) = upper.strip_prefix("FALK_") {
        // rest is a temporary; return the original suffix with same length.
        Some(&key[key.len() - rest.len()..])
    } else {
        None
    }
}

fn parse_bool(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn parse_optional_decimal(key: &str, value: &str) -> Result<Option<Decimal>, ConfigError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    Decimal::from_str(trimmed)
        .map(Some)
        .map_err(|_| ConfigError::InvalidValue {
            key: key.into(),
            value: value.into(),
        })
}

/// Merge layers. CLI wins, then env, then file, then `defaults`.
///
/// This is the shipped merge function tests must call.
pub fn merge(
    cli: &CliOverrides,
    env: &EnvOverrides,
    file: Option<&Config>,
    defaults: Config,
) -> Config {
    let mut cfg = match file {
        Some(file) => {
            let mut merged = defaults;
            overlay_file(&mut merged, file);
            merged
        }
        None => defaults,
    };

    if let Some(mode) = env.mode {
        cfg.general.mode = mode;
    }
    if let Some(true) = env.svarm {
        cfg.svarm.enabled = true;
        cfg.general.mode = Mode::Svarm;
    }
    if let Some(false) = env.svarm {
        cfg.svarm.enabled = false;
        if env.mode.is_none() {
            cfg.general.mode = Mode::Standalone;
        }
    }
    if let Some(limit) = env.hard_limit {
        cfg.finops.hard_limit_usd = Some(limit);
    }
    if let Some(limit) = env.soft_limit {
        cfg.finops.soft_limit_usd = Some(limit);
    }
    if let Some(ref id) = env.run_id {
        cfg.svarm.run_id = id.clone();
    }
    if let Some(ref id) = env.task_id {
        cfg.svarm.task_id = id.clone();
    }
    if let Some(ref ticket) = env.ticket {
        cfg.general.ticket = ticket.clone();
    }
    if let Some(enforcement) = env.enforcement {
        cfg.security.enforcement = enforcement;
    }
    if let Some(ref path) = env.ndjson_path {
        cfg.svarm.ndjson_path = path.display().to_string();
    }
    if let Some(fd) = env.ndjson_fd {
        cfg.svarm.ndjson_fd = fd;
    }

    // CLI is the highest layer.
    if let Some(mode) = cli.mode {
        cfg.general.mode = mode;
    }
    if let Some(true) = cli.svarm {
        cfg.svarm.enabled = true;
        cfg.general.mode = Mode::Svarm;
    }
    if let Some(false) = cli.svarm {
        cfg.svarm.enabled = false;
        if cfg.general.mode == Mode::Svarm && cli.mode.is_none() {
            cfg.general.mode = Mode::Standalone;
        }
    }
    if let Some(limit) = cli.hard_limit {
        cfg.finops.hard_limit_usd = Some(limit);
    }
    if let Some(limit) = cli.soft_limit {
        cfg.finops.soft_limit_usd = Some(limit);
    }
    if let Some(ref id) = cli.run_id {
        cfg.svarm.run_id = id.clone();
    }
    if let Some(ref id) = cli.task_id {
        cfg.svarm.task_id = id.clone();
    }
    if let Some(ref ticket) = cli.ticket {
        cfg.general.ticket = ticket.clone();
    }
    if let Some(enforcement) = cli.enforcement {
        cfg.security.enforcement = enforcement;
    }
    if let Some(ref path) = cli.ndjson_path {
        cfg.svarm.ndjson_path = path.display().to_string();
    }

    cfg
}

fn overlay_file(base: &mut Config, file: &Config) {
    base.general = file.general.clone();
    base.pty = file.pty.clone();
    base.security = file.security.clone();
    base.finops = file.finops.clone();
    base.svarm = file.svarm.clone();
    base.tracing = file.tracing.clone();
    if base.finops.providers.is_empty() {
        base.finops.providers = default_providers();
    }
}

/// Resolve which config file to load: CLI path, else `FALK_CONFIG`, else `falk.toml`
/// in the current directory if it exists.
pub fn resolve_config_path(cli: &CliOverrides, env: &EnvOverrides) -> Option<PathBuf> {
    if let Some(ref path) = cli.config_path {
        return Some(path.clone());
    }
    if let Some(ref path) = env.config_path {
        return Some(path.clone());
    }
    let default = PathBuf::from("falk.toml");
    if default.is_file() {
        Some(default)
    } else {
        None
    }
}

/// Load and merge from a file path (if any) plus CLI/env. Tests should prefer
/// [`merge`] with explicit layers.
pub fn load_merged(cli: &CliOverrides, env: &EnvOverrides) -> Result<Config, ConfigError> {
    let file = match resolve_config_path(cli, env) {
        Some(path) => Some(load_file(&path)?),
        None => None,
    };
    Ok(merge(cli, env, file.as_ref(), Config::default()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_mode_is_standalone() {
        let cfg = Config::default();
        assert_eq!(cfg.effective_mode(), Mode::Standalone);
        assert!(!cfg.is_svarm());
        assert!(!cfg.svarm.enabled);
    }

    #[test]
    fn parse_example_sections() {
        let raw = include_str!("../../../falk.toml");
        let cfg = parse_toml(raw).expect("example falk.toml must parse");
        assert_eq!(cfg.general.mode, Mode::Standalone);
        assert_eq!(cfg.pty.rows, 24);
        assert_eq!(cfg.security.enforcement, EnforcementMode::Block);
        assert!(cfg.security.allowlist.commands.is_empty());
        assert!(!cfg.security.blocklist.sensitive_paths.is_empty());
        assert!(cfg.security.network.allowed_domains.is_empty());
        assert!(cfg.security.redaction.enabled);
        assert_eq!(cfg.finops.loop_detect.window, 8);
        assert!(cfg.finops.providers.contains_key("anthropic"));
        assert!(!cfg.svarm.enabled);
        assert_eq!(cfg.tracing.level, "warn");
    }

    #[test]
    fn merge_cli_beats_env_beats_file_beats_defaults() {
        let file = parse_toml(
            r#"
            [general]
            mode = "standalone"
            ticket = "from-file"
            [finops]
            hard_limit_usd = "1.00"
            soft_limit_usd = "0.50"
            [svarm]
            enabled = false
            run_id = "file-run"
            "#,
        )
        .unwrap();

        let env = EnvOverrides {
            hard_limit: Some(dec("2.00")),
            ticket: Some("from-env".into()),
            run_id: Some("env-run".into()),
            ..EnvOverrides::default()
        };
        let cli = CliOverrides {
            hard_limit: Some(dec("2.50")),
            svarm: Some(true),
            run_id: Some("cli-run".into()),
            ..CliOverrides::default()
        };

        let merged = merge(&cli, &env, Some(&file), Config::default());
        assert_eq!(merged.finops.hard_limit_usd, Some(dec("2.50")));
        assert_eq!(merged.finops.soft_limit_usd, Some(dec("0.50")));
        assert_eq!(merged.general.ticket, "from-env");
        assert_eq!(merged.svarm.run_id, "cli-run");
        assert_eq!(merged.effective_mode(), Mode::Svarm);
        assert!(merged.svarm.enabled);
    }

    #[test]
    fn env_svarm_opts_in_without_cli() {
        let env = env_overrides_from_pairs([("FALK_SVARM", "true")]).unwrap();
        let merged = merge(&CliOverrides::default(), &env, None, Config::default());
        assert_eq!(merged.effective_mode(), Mode::Svarm);
    }

    #[test]
    fn file_svarm_enabled_opts_in() {
        let file = parse_toml("[svarm]\nenabled = true\n").unwrap();
        let merged = merge(
            &CliOverrides::default(),
            &EnvOverrides::default(),
            Some(&file),
            Config::default(),
        );
        assert!(merged.is_svarm());
    }

    #[test]
    fn env_pairs_parse_falk_prefix_only() {
        let env = env_overrides_from_pairs([
            ("FALK_HARD_LIMIT", "3.25"),
            ("HARD_LIMIT", "9.99"),
            ("FALK_ENFORCEMENT", "kill"),
        ])
        .unwrap();
        assert_eq!(env.hard_limit, Some(dec("3.25")));
        assert_eq!(env.enforcement, Some(EnforcementMode::Kill));
    }

    #[test]
    fn env_svarm_false_clears_file_mode_svarm() {
        let file = parse_toml("[general]\nmode = \"svarm\"\n").unwrap();
        let env = env_overrides_from_pairs([("FALK_SVARM", "false")]).unwrap();
        let merged = merge(&CliOverrides::default(), &env, Some(&file), Config::default());
        assert_eq!(merged.effective_mode(), Mode::Standalone);
        assert!(!merged.svarm.enabled);
    }

    #[test]
    fn empty_env_usd_is_unset_and_unquoted_float_is_rejected() {
        let env = env_overrides_from_pairs([
            ("FALK_HARD_LIMIT", ""),
            ("FALK_SOFT_LIMIT", "   "),
        ])
        .expect("blank FALK_* USD must not be a parse error");
        assert_eq!(env.hard_limit, None);
        assert_eq!(env.soft_limit, None);
        let err = parse_toml("[finops]\nhard_limit_usd = 0.1\n")
            .expect_err("unquoted toml float must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("quoted") || msg.contains("float") || msg.contains("decimal"),
            "{msg}"
        );
        let ok = parse_toml("[finops]\nhard_limit_usd = \"0.10\"\n").unwrap();
        assert_eq!(ok.finops.hard_limit_usd, Some(dec("0.10")));
    }
}
