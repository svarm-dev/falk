//! falk — lightweight PTY runtime sentinel for AI coding agents.
//!
//! Dual identity (runtime switch, not a Cargo feature, not an Elixir dep):
//!
//! * **Standalone (default)** — anyone can run `falk -- claude` with zero
//!   Svärm knowledge. Raw-mode PTY, signal/resize forwarding, exit-code fidelity.
//! * **Svärm mode (opt-in)** — `--svarm` / `[svarm] enabled = true` / `FALK_SVARM`.
//!   Outer interface is plain stdio (Svärm `Runner.Cli` `Port.open` compatible);
//!   the inner agent still gets a real PTY. Side-channel is NDJSON only.
//!   falk never writes Task fields `status`, `wait_reason`, `pending_question`,
//!   or `attempts`.
//!
//! Port-vs-PTY: Svärm `Port.open` cannot carry SIGWINCH. Resize in Svärm mode
//! is a documented limitation, not a failure.

mod claude_jsonl;
mod runtime;

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Context;
use clap::Parser;
use falk_config::{
    CliOverrides, Config, EnforcementMode, Mode, env_overrides_from_os, load_file, merge,
    resolve_config_path,
};
use rust_decimal::Decimal;

/// Lightweight PTY runtime sentinel and opt-in Svärm FinOps circuit breaker.
///
/// Wrap any agent with `--` so falk flags stay separate from the command:
///
///   falk --hard-limit 2.50 -- claude
///   falk -c falk.toml -- aider --yes-always
///   falk --svarm -- /bin/echo hello
#[derive(Debug, Parser)]
#[command(
    name = "falk",
    version,
    about = "Standalone PTY wrapper and opt-in Svärm FinOps circuit breaker for AI coding agents",
    long_about = "falk is a zero-Svärm-dependency PTY wrapper (standalone by default) \
and an opt-in Svärm runtime security / FinOps plane.\n\n\
Use `--` to separate falk flags from the wrapped command:\n  \
falk --hard-limit 2.50 -- claude\n  \
falk -c falk.toml -- aider --yes-always\n  \
falk --svarm -- /bin/echo hello\n\n\
Standalone is fully useful on its own. Svärm mode (`--svarm`) switches the outer \
interface to plain stdio for Port.open; the inner agent still gets a real PTY. \
Svärm Port.open cannot carry SIGWINCH (resize limitation)."
)]
struct Cli {
    /// Path to falk.toml (CLI > env FALK_CONFIG > ./falk.toml > defaults)
    #[arg(short = 'c', long = "config", value_name = "PATH")]
    config: Option<PathBuf>,

    /// Hard USD ceiling. Crossing it killpg(SIGTERM) then SIGKILL after grace.
    #[arg(long = "hard-limit", value_name = "USD")]
    hard_limit: Option<String>,

    /// Soft USD ceiling. Crossing it only warns.
    #[arg(long = "soft-limit", value_name = "USD")]
    soft_limit: Option<String>,

    /// Opt in to Svärm mode (plain stdio outer, PTY inner, NDJSON side-channel).
    /// Off by default. Standalone remains the default identity.
    #[arg(long = "svarm")]
    svarm: bool,

    /// Force standalone mode even if the config file enables Svärm.
    #[arg(long = "standalone", conflicts_with = "svarm")]
    standalone: bool,

    /// Svärm run id injected into NDJSON usage events (never a Task field).
    #[arg(long = "run-id", value_name = "ID")]
    run_id: Option<String>,

    /// Svärm task id injected into NDJSON usage events (never a Task field).
    #[arg(long = "task-id", value_name = "ID")]
    task_id: Option<String>,

    /// Optional ticket / correlation id.
    #[arg(long = "ticket", value_name = "ID")]
    ticket: Option<String>,

    /// Security enforcement: warn | block | kill
    #[arg(long = "enforcement", value_name = "MODE")]
    enforcement: Option<String>,

    /// NDJSON side-channel path (Svärm mode; never mixed into agent stdout).
    #[arg(long = "ndjson", value_name = "PATH")]
    ndjson: Option<PathBuf>,

    /// Command to wrap. Use `--` so falk flags are not consumed by the agent.
    #[arg(last = true, value_name = "COMMAND")]
    command: Vec<String>,
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(err) => {
            eprintln!("falk: {err:#}");
            ExitCode::from(2)
        }
    }
}

/// Resolve the tracing directive: `RUST_LOG` wins when set, else `[tracing] level`.
pub fn tracing_filter_directive(file_level: &str, rust_log: Option<&str>) -> String {
    match rust_log.map(str::trim).filter(|s| !s.is_empty()) {
        Some(env) => env.to_string(),
        None if file_level.trim().is_empty() => "warn".into(),
        None => file_level.trim().to_string(),
    }
}

fn init_tracing(file_level: &str) {
    let directive = tracing_filter_directive(file_level, std::env::var("RUST_LOG").ok().as_deref());
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(directive))
        .with_writer(std::io::stderr)
        .try_init();
}

fn run() -> anyhow::Result<ExitCode> {
    let cli = Cli::parse();
    if cli.command.is_empty() {
        anyhow::bail!("missing command; usage: falk [OPTIONS] -- <COMMAND>...");
    }

    let overrides = cli_overrides(&cli)?;
    let env = env_overrides_from_os().context("parse FALK_* environment")?;
    let file = match resolve_config_path(&overrides, &env) {
        Some(path) => Some(load_file(&path).with_context(|| format!("load {}", path.display()))?),
        None => None,
    };
    let cfg = merge(&overrides, &env, file.as_ref(), Config::default());
    init_tracing(&cfg.tracing.level);

    runtime::run_wrapped(&cli.command, &cfg)
}

fn cli_overrides(cli: &Cli) -> anyhow::Result<CliOverrides> {
    let parse_usd = |raw: &str, name: &str| -> anyhow::Result<Decimal> {
        raw.parse::<Decimal>()
            .map_err(|_| anyhow::anyhow!("invalid {name}: {raw}"))
    };
    Ok(CliOverrides {
        config_path: cli.config.clone(),
        hard_limit: cli
            .hard_limit
            .as_deref()
            .map(|s| parse_usd(s, "--hard-limit"))
            .transpose()?,
        soft_limit: cli
            .soft_limit
            .as_deref()
            .map(|s| parse_usd(s, "--soft-limit"))
            .transpose()?,
        svarm: if cli.svarm {
            Some(true)
        } else if cli.standalone {
            Some(false)
        } else {
            None
        },
        run_id: cli.run_id.clone(),
        task_id: cli.task_id.clone(),
        ticket: cli.ticket.clone(),
        enforcement: cli
            .enforcement
            .as_deref()
            .map(str::parse::<EnforcementMode>)
            .transpose()
            .map_err(|err| anyhow::anyhow!("{err}"))?,
        ndjson_path: cli.ndjson.clone(),
        mode: if cli.svarm {
            Some(Mode::Svarm)
        } else if cli.standalone {
            Some(Mode::Standalone)
        } else {
            None
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn help_documents_required_flags() {
        let mut cmd = Cli::command();
        let mut buf = Vec::new();
        cmd.write_long_help(&mut buf).unwrap();
        let help = String::from_utf8(buf).unwrap();
        assert!(help.contains("--hard-limit"), "{help}");
        assert!(help.contains("-c") && help.contains("config"), "{help}");
        assert!(help.contains("--svarm"), "{help}");
        assert!(help.contains("--"), "{help}");
        assert!(
            help.contains("separate") || help.contains("COMMAND") || help.contains("`--`"),
            "{help}"
        );
    }

    #[test]
    fn default_cli_is_not_svarm() {
        let cli = Cli::parse_from(["falk", "--", "/bin/echo", "x"]);
        assert!(!cli.svarm);
        assert_eq!(cli.command, ["/bin/echo", "x"]);
    }

    #[test]
    fn tracing_file_level_applies_when_rust_log_unset() {
        assert_eq!(tracing_filter_directive("debug", None), "debug");
        assert_eq!(tracing_filter_directive("debug", Some("")), "debug");
        assert_eq!(
            tracing_filter_directive("debug", Some("info")),
            "info",
            "RUST_LOG must win when set"
        );
        assert_eq!(tracing_filter_directive("", None), "warn");
    }
}
