# Svärm mode and the NDJSON side-channel

Standalone is the default. Svärm mode is **opt-in**:

```bash
falk --svarm --run-id RUN --task-id TASK -- /path/to/agent
```

```toml
[svarm]
enabled = true
run_id = "…"
task_id = "…"
ndjson_path = "falk-events.ndjson"
```

```bash
export FALK_SVARM=true
export FALK_RUN_ID=…
export FALK_TASK_ID=…
export FALK_NDJSON=falk-events.ndjson
```

## Dual identity

falk does not depend on Svärm or Elixir at compile time or at runtime.
Svärm mode is a runtime switch: the same static binary presents a different
outer interface.

| | Standalone (default) | Svärm (opt-in) |
|---|---|---|
| Outer I/O | raw TTY when stdin is a TTY | plain stdio (`Port.open`) |
| Inner agent | real PTY, session + PG leader | real PTY, session + PG leader |
| SIGWINCH / resize | forwarded | **not available** (Port-vs-PTY) |
| Redaction | typed `[REDACTED:…]` markers | `Svarm.Redact`: `[redacted]` |
| Control plane | none required | NDJSON side-channel only |

falk **never** writes Task fields `status`, `wait_reason`,
`pending_question`, or `attempts`. Those are owned exclusively by the
Svärm Orchestrator.

## Port-vs-PTY resize limitation

Svärm `Runner.Cli` opens the child with `Port.open` (non-PTY) and
`:stderr_to_stdout`. A pipe cannot carry `SIGWINCH`, so falk cannot resize
the inner PTY when the Svärm parent terminal changes size. Configure
`[pty] rows` / `cols` instead. This is a documented limitation, not a
failure.

Because Svärm drains stderr into stdout, NDJSON **must not** go to stderr.
Write it to `--ndjson PATH`, `FALK_NDJSON`, `[svarm] ndjson_path`, or
`[svarm] ndjson_fd`. If none are set in Svärm mode, falk writes
`falk-events.ndjson` in the working directory.

## NDJSON event shapes

One JSON object per line. Incremental `usage` events map 1:1 onto
`Svarm.Usage` / `Usage.Record`.

### `usage`

```json
{
  "event": "usage",
  "run_id": "run-…",
  "task_id": "task-…",
  "provider": "anthropic",
  "model_id": "claude-sonnet-4",
  "prompt_tokens": 1200,
  "completion_tokens": 340,
  "cache_read_tokens": 50,
  "provider_cost_usd": "0.042",
  "estimated": false,
  "source": "falk"
}
```

Fields intended for `Usage.Record.append/1`: `run_id`, `task_id`,
`provider`, `model_id`, `prompt_tokens`, `completion_tokens`,
`provider_cost_usd`, `estimated`, `source`.

### `limit`

```json
{"event":"limit","kind":"hard","total_usd":"2.50","ceiling_usd":"2.50"}
{"event":"limit","kind":"soft","total_usd":"1.00","ceiling_usd":"1.00"}
```

### `loop`

```json
{"event":"loop","reason":"repeated command fingerprint …","repeats":4}
```

### `security`

```json
{"event":"security","verdict":"kill","reason":"command `rm` is on the blocklist"}
```

### `warn`

```json
{"event":"warn","component":"runtime","message":"finops soft limit …"}
```

No event includes `status`, `wait_reason`, `pending_question`, or `attempts`.

## Redaction (Svärm mode)

Aligned with `lib/svarm/redact.ex` on svarm-dev/svarm main:

| Pattern | Replacement |
|---|---|
| PEM private key block | `[redacted pem]` |
| `API_KEY=…` / `TOKEN=…` / … | `API_KEY=[redacted]` |
| `Authorization: …` | `Authorization: [redacted]` |
| `Bearer …` | `Bearer [redacted]` |
| `sk-ant-…`, `sk-…`, GitHub PATs, … | `[redacted]` |
| bare JWT | `[redacted]` |

Streaming redaction uses a hold-back window so secrets that span PTY
read buffers are still caught.

## Optional Linux sandbox

Landlock / seccomp are not enabled in this release. Process-group
containment (`setsid` + `killpg`) is the shipped hard-action mechanism.
