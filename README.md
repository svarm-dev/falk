# falk

Lightweight, zero-dependency, ultra-fast Rust CLI that wraps an AI coding agent
under a real PTY and acts as a runtime sentinel + FinOps circuit breaker.

## Dual identity

**Standalone (default).** Anyone can run falk with zero knowledge of Svärm:

```bash
falk --hard-limit 2.50 -- claude
falk -c falk.toml -- aider --yes-always
falk -- /bin/echo hello
```

The wrapped command becomes the session + process-group leader. Standalone
mode is fully useful on its own: raw-mode when stdin is a TTY, SIGINT /
SIGTERM / SIGWINCH forwarding, ANSI passthrough, and the child's exit status
is preserved. The terminal is restored on every path.

**Svärm mode (opt-in).** falk is also the missing mid-run enforcement layer
for [Svärm](https://github.com/svarm-dev/svarm). Enable it with `--svarm`,
`[svarm] enabled = true`, or `FALK_SVARM=true`.

- Outer interface is **plain stdio**, compatible with Svärm `Runner.Cli`
  `Port.open`.
- The inner agent still gets a **real PTY**.
- Side-channel is **NDJSON only**.
- falk **never** writes Task fields `status`, `wait_reason`,
  `pending_question`, or `attempts` — those belong to the Orchestrator.
- Svärm Budget is preflight-only. falk owns the mid-run hard kill:
  `killpg(SIGTERM)` → grace → `killpg(SIGKILL)`.

There is **no** compile-time or runtime dependency on Svärm or Elixir.

### Port-vs-PTY resize limitation

Svärm `Port.open` is a non-PTY pipe and cannot carry `SIGWINCH`. In Svärm
mode falk will not see parent-terminal resizes. The inner PTY is opened at
the configured `[pty]` size (or 24×80). This is a documented limitation, not
a failure.

## Configuration

Precedence: **CLI flags > `FALK_*` env > `falk.toml` > defaults**.

See [`falk.toml`](falk.toml) for every section: `[general]`, `[pty]`,
`[security]`, `[security.allowlist]`, `[security.blocklist]`,
`[security.network]`, `[security.redaction]`, `[finops]`, `[finops.loop]`,
`[finops.providers.*]`, `[svarm]`, `[tracing]`.

## Docs

- [Svärm mode & NDJSON contract](docs/svarm.md)
- [Example Svärm `agents.toml` wrappers](examples/agents.toml)

## Build

```bash
cargo build --release
./target/release/falk --help
```
