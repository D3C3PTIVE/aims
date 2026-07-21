# BRING — sourcing an implant context into the operator's shell

> Design/plan doc. Drafted 2026-07-19. **Not yet built** — captures the agreed design for a
> future session. **Companion docs:** [`CLAUDE.md`](./CLAUDE.md) · [`STATE.md`](./STATE.md) ·
> [`SCAN.md`](./SCAN.md) · [`DEDUP.md`](./DEDUP.md) · [`ROADMAP.md`](./ROADMAP.md).

## Goal

`aims bring <agent-id>` **sources an implant context into the operator's live shell**: a prompt
segment for the current agent, a short alias root to drive it, scoped completions, and a clean
`leave` teardown. The shell becomes "about" that agent until you `leave`. The agent is a
`c2.Agent` (`c2/pb/agent.proto`: `Id`, `Name`, `Tool`, `Arch`, `WorkingDirectory`, `LastCheckin`,
`Channels`, `Tasks`, …) — enough to label a prompt and dispatch tasks.

## Core mechanism — "source", not "run"

A child process can't mutate its parent shell, so `aims` **prints shell code to stdout and the
shell evaluates it in place** — exactly what carapace does here (`carapace aims <shell>`; see
`_carapace` + `carapace.Gen(cmd)` in `cmd/`). `aims bring <id>` is a **shell-code generator
parameterized by an agent ID**; the doing happens on source:

```sh
source <(aims bring web01)    # zsh/bash process substitution
eval "$(aims bring web01)"    # portable form
```

## Two ergonomic layers (à la carapace / direnv / zoxide)

1. **`aims init <bash|zsh|fish>`** — run once in the rc file; installs the fixed `bring`/`leave`
   functions so the operator types `bring web01`: `bring() { source <(command aims bring "$@"); }`
2. **`aims bring <id>`** — the per-agent generator: connect, `c2.Agents.Read(id)`, render a
   shell-escaped, dialect-aware snippet to stdout.

Same split as carapace's init stub vs. `_carapace` callback, or `direnv hook` vs. `direnv export`.

## What the sourced context contains

### ENV — identity + presentation only (deliberately minimal)

Env carries **what shell context I'm in** (identity + stack), never **what the agent is** — rich/
volatile data is fetched live by ID at use time, so env can't drift as the implant moves.

| Var | Purpose | Used by |
|-----|---------|---------|
| `AIMS_AGENT_ID`    | canonical UUID identity. **Only** value used for dispatch. | aliases, completions, live queries |
| `AIMS_AGENT_NAME`  | display label. **Never** dispatched on. | prompt, banners |
| `AIMS_CONTEXT_DEPTH` | nesting/stack depth. | prompt, teardown |

Optional display-only add-ons (escaped, point-in-time snapshot, never authoritative):
`AIMS_AGENT_USER`, `AIMS_AGENT_HOST` (as the operator's real `sliver_local.zsh` does).

### PROMPT segment

Prepend the agent like a venv's `(venv)` / kubectx — e.g. `[web01] ⇕2 $`. Render a
**well-delimited, replaceable segment** (not a fixed PS1) to slot into the operator's own
sec-prompt; support `PROMPT`/`PS1` directly (save prior value) or an oh-my-posh segment. Include
**stack depth** so stacked agents are visible at a glance.

> TODO: paste the operator's sec-prompt (PS1 + oh-my-posh) and template the segment into it.

Prompt-enrichment ideas (all point-in-time display snapshots; show nothing when absent):
- **Traceroute at a glance** — hop distance + last hop before target (`[web01 ·3h·gw 10.0.0.1]`).
  Preload `Agent.Host.Trace.Hops`+`Distance`; reuse host route rendering in `host.DisplayFields`.
- **Active port-forwards** — source→target `addr:port` (or a count when tight). Needs a forwards
  field on the c2 model/payload.
- **Server-global status line** (agentless, RPROMPT or below prompt) — running scans, task counts.
  Also signals that `aims init` was sourced when no agent is brought. Waits on scan/task list RPCs.

### Alias root — `aimsi`, not shadowed root commands

No top-level aliases shadowing `ls`/`ps`. One short **alias root** — provisionally `aimsi` ("aims
implant") — is the agent-bound task entrypoint; muscle memory builds on it (`aimsi exec ls`,
`aimsi download …`, `aimsi shell`). Implement as a **function**, not an alias, so it forwards args
and can carry a `compdef`:

```sh
aimsi() { aims c2 task "$AIMS_AGENT_ID" "$@"; }   # dispatch keys off ID, not name
```

`aims c2 task` doesn't exist yet (see open decision 2); `aimsi` is correct-in-form for when it
lands. Via `Agent.Tool` (live query by ID), `aimsi` can hand off to the implant's native tool
(sliver, mythic, custom), agent pre-selected — AIMS stays the catalog, tools stay the executors.

### Scoped completions

Register carapace completions **scoped to the brought agent** for `aimsi` & friends — live-querying
remote files (under `WorkingDirectory`), processes, channels, task IDs — the same "completions are
live RPC queries" pattern (`CompleteBy*` → `display.Completions`), parameterized by `AIMS_AGENT_ID`.
Consider tag groups / deliberate ordering to sub-categorize candidates (per CLAUDE.md preference).

### `leave` / teardown

Mandatory clean exit (venv's `deactivate`): restore saved prompt, `unset` context vars,
`unalias`/unset `aimsi`, deregister completions. Installed by `aims init`.

## Nesting / swap

Bringing a second agent **stacks**, not clobbers: push prior prompt+vars onto a per-shell stack,
increment `AIMS_CONTEXT_DEPTH`; `leave` **pops** to the previous agent (not a hardcoded default),
decrements depth, and at depth 1 fully tears down. Show depth in the segment (`⇕2`).

## Security — injection is a first-class concern

Agent strings (`Name`, `WorkingDirectory`, hostname, …) are **attacker-influenced** — the implant
reports them. Raw interpolation into sourced shell code means an implant named `web01"; rm -rf ~; #`
gets **code execution on the operator's box**. Non-negotiable:
- Route **every** agent-derived value through strict shell escaping (single-quote escape, or pass as
  positional args to a fixed body); **never** splice as literal snippet text.
- `Name` is display-only; dispatch keys off the UUID `Id`, which AIMS controls.
- One vetted template with a single escaping boundary, not string concatenation.
- Guard prompt mangling behind an interactive-shell check.

This is the one thing to get right from commit one.

## Idempotency & non-interactive guard

- Re-bringing the **same** agent refreshes, not double-prepends/re-stacks (detect current
  `AIMS_AGENT_ID` == requested).
- Skip prompt mangling when non-interactive (`[[ -o interactive ]]` / `$-`) so scripts sourcing
  `aims bring` aren't garbled.

## Multi-shell templating

bash/zsh/fish differ on prompt var, function/array syntax, and sourcing. Don't hand-roll per-shell
strings — mirror carapace (per-shell templates + shell detection); pick the template from `<shell>`.

## Command surface

```
aims init <bash|zsh|fish>   # once, in rc — installs bring()/leave() (à la _carapace)
aims bring <agent-id>       # generator: emits the context snippet for one agent
  → bring web01             # sugar from the init function
  → leave                   # pop one context / full teardown at depth 1
```

## Architecture

### The trust split (the crux)

The design turns on **keeping attacker-controlled agent data out of executed shell code** — two
halves at opposite trust levels:

- **Fixed trusted code** — `bring`/`leave` functions, prompt logic, `aimsi`, completion
  registration. Contains **no agent data**, audited once, emitted by `aims shell-init <shell>`
  (sourced once from rc, like `carapace <bin> <shell>`).
- **Per-agent payload** — emitted by `aims bring <id>`; the *only* injection surface, reduced to
  **escaped scalar values, never logic**.

> **Prime rule: `aims bring` emits data, `shell-init` emits code.** Agent strings enter the shell
> only as the *contents of variables the trusted functions assign*. `web01"; rm -rf ~; #` becomes
> the literal value of `$AIMS_AGENT_NAME`, never in a position to execute.

Concretely, `bring()` **captures** `aims bring` output and parses it as data (a `read` loop over
strict `KEY<TAB>VALUE`-per-line or NUL-delimited), rather than sourcing it — no agent byte is ever
evaluated. (`source <(aims bring …)` is a strictly-weaker fallback that then requires the quoter on
every value. Prefer capture-as-data.)

### Package layout

```
cmd/bring/
  bring.go        # Commands(con) → the `bring` and `shell-init` subcommands
  generate.go     # connect → Agents.Read(id) → assemble Context → emit payload
  context.go      # type Context: flat escaped view of a pb.Agent (id, name, tool, cwd…)
  shell/
    shell.go      # type Shell (bash|zsh|fish); Detect(); Quote(Shell, string)  ← audited
    init.go       # renders fixed bring()/leave()/alias/completion machinery per shell
    payload.go    # renders per-agent data payload per shell
    templates/    # embed.FS: bash/zsh/fish .tmpl for both init and payload
```

`shell.Quote` is the single escaping boundary — ~15-line, unit-tested, per-dialect (POSIX
single-quote wrap with `'\''` splicing for bash/zsh; fish's own rules). Every agent value routed
through `text/template` goes through a FuncMap that forces `Quote` — templates can't emit a raw
value by mistake.

### Command wiring

`bring` is an operator/shell meta-command; bind it top-level in `cmd/aims/commands.go` (own group,
e.g. `"shell"`).
- `aims bring <agent-id>` — **connects** (reads the agent): give it `ConnectRun` (via `bindRunners`)
  and arg completion reusing `c2.CompleteByID`.
- `aims shell-init <shell>` — **offline** code-gen; exclude from the connect pre-run (like the
  teamclient `import` commands in `client.isOffline`).

### Generator flow (`aims bring <id>`)

1. `client.ConnectComplete`-style connect (reuse existing path).
2. `con.Agents.Read(ctx, &c2.ReadAgentRequest{Agent: &pb.Agent{Id: id}, Filters: &c2.AgentFilters{MaxResults: 1}})`.
3. Build `Context` from the `pb.Agent`.
4. Render the per-shell **payload** template (escaped scalars only) to stdout; the trusted `bring()`
   consumes it and applies stack + prompt.

### Shell state model (nesting) — all in trusted functions, no agent data in the logic

- Parallel-array stack: `_aims_stack_id`, `_aims_stack_name`, `_aims_stack_prompt`;
  `AIMS_CONTEXT_DEPTH` = stack length.
- `bring()`: push current → set new `AIMS_AGENT_ID/NAME` from parsed payload → rebuild segment from
  `$AIMS_AGENT_NAME`+depth → (re)assert `aimsi` + completions.
- `leave()`: pop → restore saved prompt/vars → at depth 0 unset vars, drop `aimsi`, deregister
  completions.
- Segment reads `$AIMS_AGENT_NAME` as a value; zsh may treat `%` as a prompt escape — sanitize
  `%`→`%%` in the zsh payload if it bothers (cosmetic).

### Injection surface at a glance

| Piece | Emitted by | Agent data? |
|-------|-----------|:---:|
| `bring()`/`leave()`, prompt logic, `aimsi`, completion registration | `shell-init` | no |
| `AIMS_AGENT_ID/NAME`, tool, cwd values | `bring` | **yes → escaped scalars only** |

The injection surface is one table row.

## Open decisions

1. **Alias root name** — `aimsi` or another short token (becomes muscle memory).
2. **Aliases = AIMS subcommands vs. shims over `Agent.Tool`** — how much control plane lives in
   `aims c2 task …` vs. the agent's native tool. Sets AIMS-as-catalog vs. AIMS-as-driver.
3. **Prompt integration** — slot into the operator's PS1 / oh-my-posh (pending their code); keep the
   segment replaceable.
4. **Saved-state stack storage** — env-only vs. a per-PID temp file.
5. **Where `bring`/`leave` live** — pure generated shell (like carapace) vs. a hidden `aims` helper.
