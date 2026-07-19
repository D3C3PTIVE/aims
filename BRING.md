# BRING — sourcing an implant context into the operator's shell

> Design/plan doc. Drafted 2026-07-19. Feature is **not yet built** — this captures the
> agreed design so a future session (or agent) can implement it.
>
> **Companion docs:** [`CLAUDE.md`](./CLAUDE.md) — root context · [`STATE.md`](./STATE.md) —
> current state · [`SCAN.md`](./SCAN.md) · [`DEDUP.md`](./DEDUP.md) · [`ROADMAP.md`](./ROADMAP.md).

## Goal

A command — provisionally `aims bring <agent-id>` — that **sources an implant context into
the operator's live shell**: a prompt segment showing the current agent, a short alias root to
drive it, scoped completions, and a clean teardown. Bringing an agent makes the surrounding
shell "about" that agent until you `leave` it.

The controlling agent object is a `c2.Agent` (`c2/pb/agent.proto`): it carries `Id`, `Name`,
`Tool`, `Arch`, `Locale`, `WorkingDirectory`, `LastCheckin`, `Channels`, `Tasks`,
`TasksCount`, … — enough to label a prompt and to dispatch tasks against the agent.

## The core mechanism (why it's "source", not "run")

A child process cannot mutate its parent shell — `aims` can't set your `PROMPT`, add aliases,
or export vars into the shell that launched it. The only channel is: **`aims` prints shell code
to stdout, and the shell evaluates it in place.** This is exactly what carapace already does in
this repo (`carapace aims <shell>` → a source-able snippet; see the `_carapace` subcommand and
`carapace.Gen(cmd)` wiring in `cmd/`). So:

> `aims bring <id>` is **not** "a command that does something" — it is a **shell-code generator
> parameterized by an agent ID**. The doing happens when the shell sources its stdout.

```sh
source <(aims bring web01)    # zsh/bash process substitution
eval "$(aims bring web01)"    # portable form
```

Carapace inspiration is the model throughout: emit-and-source, multi-shell templating, and a
two-layer split between a fixed init stub and a per-invocation generator.

## Two ergonomic layers (like carapace / direnv / zoxide)

1. **`aims init <bash|zsh|fish>`** — run once in the rc file. Installs the fixed `bring` / `leave`
   shell functions so the operator types `bring web01`, not the raw `source <(…)`. The function
   is the stable part; it just wraps the source:
   ```sh
   bring() { source <(command aims bring "$@"); }
   ```
2. **`aims bring <id>`** — the per-agent generator the function calls: connect to the server
   (`client.ConnectComplete`-style), `c2.Agents.Read(id)`, render a shell-escaped,
   dialect-aware snippet to stdout.

Same split as carapace's `_carapace` (live callback) vs. sourced init stub, and as
`direnv hook` vs. `direnv export`.

## What the sourced context contains

### ENV — identity + presentation state only (orthogonal, deliberately minimal)

Design principle that keeps env from rotting into a stale mirror of the DB:

> **Env carries only *what shell context I'm in* (identity + stack state). It never caches
> *what the agent is* — all rich/volatile agent data (cwd, last check-in, channels, tool) is
> fetched live by ID at use time.** Otherwise the env drifts out of date the moment the implant
> moves.

Minimal orthogonal set — each variable has one job and they don't overlap:

| Var | Purpose | Used by |
|-----|---------|---------|
| `AIMS_AGENT_ID`    | canonical identity (UUID). The **only** value used for dispatch. | aliases, completions, live queries |
| `AIMS_AGENT_NAME`  | display label. **Never** used for dispatch — presentation only. | prompt, banners |
| `AIMS_CONTEXT_DEPTH` | nesting/stack depth (see Nesting). | prompt indicator, teardown |

Everything richer (Tool backend, WorkingDirectory, check-in state) is a **live query keyed by
`AIMS_AGENT_ID`**, not an env var. This is the orthogonality: identity vs. display vs. stack are
three separate axes; live agent state is a fourth thing that simply isn't env's job.

### PROMPT segment

Prepend the agent to the prompt like a venv's `(venv)` or kubectx — e.g. `[web01] ⇕2 $`. Two
supported paths:
- **`PROMPT`/`PS1`** directly (save the prior value first — see teardown).
- **oh-my-posh** segment, for operators who drive their prompt through it.

The operator will supply their own sec-prompt code to integrate against — **the generator should
render a well-delimited, replaceable segment**, not assume a fixed prompt string. Include the
**stack depth** in the segment (see Nesting) so several brought agents are visible at a glance.

> TODO: paste the operator's sec-prompt (PS1 + oh-my-posh) here when provided, and template the
> agent segment to slot into it.

### Alias root — `aimsi`, not shadowed root commands

Do **not** define top-level aliases like `ls`/`ps` that shadow real commands. Instead define one
short **alias root** — provisionally `aimsi` ("aims implant") — that *is* the agent-bound task
entrypoint:

```sh
alias aimsi='aims c2 task "$AIMS_AGENT_ID"'   # ID from env; dispatch keys off identity, not name
```

The operator then builds muscle memory on top of it: `aimsi exec ls`, `aimsi download /etc/passwd`,
`aimsi shell`. `aimsi` is **the root of the implant context** — any further convenience
functions hang off it (or off `AIMS_AGENT_ID`) under this single short prefix, rather than
polluting/overriding the root command namespace. The exact name (`aimsi` or another short token)
is still open.

**Dispatch to other tools — this is what `Agent.Tool` is for.** `aimsi` can resolve the agent's
`Tool` (via a live query by ID) and hand off to whatever actually controls that implant
(sliver, mythic, a custom binary), agent pre-selected. AIMS stays the shared catalog; the tools
stay the executors.

### Scoped completions

Register carapace completions **scoped to the brought agent** for `aimsi` and friends —
live-querying the agent for remote files (under its `WorkingDirectory`), running processes,
channels, task IDs, etc. Same "completions are live RPC queries" pattern already used across the
CLI (`CompleteBy*` callbacks feeding `display.Completions`), now parameterized by
`AIMS_AGENT_ID`. Consider carapace **tag groups** / deliberate ordering to sub-categorize
candidates (per the standing completion-design preference in CLAUDE.md).

### `leave` / teardown

Sourcing pollutes the shell, so a clean exit is mandatory (venv's `deactivate`): restore the
saved prompt, `unset` the context vars, `unalias aimsi`, and deregister the scoped completions.
Emitted as part of the snippet / installed by `aims init`.

## Nesting / swap

Bringing a second agent while one is active should **stack**, not clobber:
- Push the prior `PROMPT` and context vars onto a saved-state stack (small, keyed by shell PID —
  env or a temp file under `$$`); increment `AIMS_CONTEXT_DEPTH`.
- `leave` **pops** back to the previous agent (restoring its prompt/vars), not to a hardcoded
  default; decrement depth. `leave` at depth 1 fully tears down.
- **Show the stack depth in the prompt segment** (e.g. `⇕2`) so the operator sees how many agent
  contexts are stacked.

## Security — injection is a first-class concern

In a C2 setting, agent-derived strings (`Name`, `WorkingDirectory`, reported hostname, …) are
**attacker-influenced**: the implant reports them. If `aims bring` interpolates them raw into
shell code the operator then `source`s, a malicious implant checking in as
`web01"; rm -rf ~; #` gets **code execution on the operator's box**.

Non-negotiable rules for the generator:
- Emit **every** agent-derived value through strict shell escaping — single-quote-escape, or pass
  values as positional args to a fixed function body; **never** splice them as literal snippet text.
- Treat `Name` as display-only; dispatch keys off the UUID `Id`, which AIMS controls.
- Prefer rendering via a vetted template with a single escaping boundary, not string concatenation.
- Guard interactive-only behavior (prompt mangling) behind an interactive-shell check.

This is the one thing to get right from commit one.

## Idempotency & non-interactive guard

- Re-bringing the **same** agent is a refresh, not a double-prepended prompt / re-stacked context
  (detect current `AIMS_AGENT_ID` == requested).
- Skip prompt mangling and interactive niceties when the shell is non-interactive
  (`[[ -o interactive ]]` in zsh / `$-` check in bash), so scripts that source `aims bring` don't
  get a garbled prompt.

## Multi-shell templating

bash / zsh / fish differ on the prompt variable, function/array syntax, and how you source. Do
**not** hand-roll per-shell string building — mirror carapace's structure (per-shell templates +
shell detection) so `bring` works everywhere completions already do. The generator picks the
template from the `<shell>` arg (as `aims init <shell>` does).

## Command surface (sketch)

```
aims init <bash|zsh|fish>   # once, in rc — installs the `bring` / `leave` functions (à la _carapace)
aims bring <agent-id>       # the generator: emits the context snippet for one agent
  → bring web01             # sugar from the init function
  → leave                   # pop one context / full teardown at depth 1
```

Generator internals: connect → `c2.Agents.Read(id)` → render shell-escaped, dialect-aware
template → stdout.

## Architecture

> Added 2026-07-19 after grounding in the real command tree, the c2 client, and the carapace
> wiring. This is the concrete build design; the sketch above is the intent.

### The trust split (the crux)

The whole design turns on **keeping attacker-controlled agent data out of executed shell code**.
So the machinery is split into two halves with opposite trust levels:

- **Fixed, trusted code** — the `bring()` / `leave()` shell functions, the prompt logic, the
  `aimsi` alias, the completion registration. This is *our* code, contains **no agent data**,
  is audited once, and is emitted by `aims shell-init <shell>` (sourced once from the rc file,
  exactly like `carapace <bin> <shell>`).
- **Per-agent payload** — emitted by `aims bring <id>`. This contains agent-derived values
  (name, id, tool, cwd) and is the *only* injection surface. It is therefore reduced to
  **escaped scalar values, never logic**.

> **Prime rule: `aims bring` emits data, `shell-init` emits code.** Agent strings cross into the
> shell as the *contents of variables the trusted functions assign*, never as snippet text that
> is sourced/eval'd. An implant named `web01"; rm -rf ~; #` becomes the literal value of
> `$AIMS_AGENT_NAME`; it is never in a position to execute.

Concretely, `bring()` **captures** `aims bring` output and parses it as data (a `read` loop over
a strict `KEY<TAB>VALUE`-per-line, or NUL-delimited, format), rather than `source`-ing it. That
way no agent byte is ever evaluated as code. (The simpler `source <(aims bring …)` form is the
fallback if a shell can't do the capture cleanly — but then every emitted value MUST go through
the quoter below, and that path is strictly weaker. Prefer capture-as-data.)

### Package layout

```
cmd/bring/
  bring.go        # Commands(con) *cobra.Command → the `bring` and `shell-init` subcommands
  generate.go     # generator: connect → Agents.Read(id) → assemble Context → emit payload
  context.go      # type Context: the flat, escaped view of a pb.Agent (id, name, tool, cwd…)
  shell/
    shell.go      # type Shell (bash|zsh|fish); Detect(); Quote(Shell, string) string  ← audited
    init.go       # renders the fixed bring()/leave()/alias/completion machinery per shell
    payload.go    # renders the per-agent data payload per shell
    templates/    # embed.FS: bash.tmpl, zsh.tmpl, fish.tmpl for both init and payload
```

`shell.Quote` is the single escaping boundary — a ~15-line, unit-tested, per-dialect quoter
(POSIX single-quote wrapping with `'\''` splicing for bash/zsh; fish's own rules). Every agent
value routed through `text/template` uses a FuncMap that forces it through `Quote`; templates
can't interpolate a raw value even by mistake.

### Command wiring

`bring` is an operator/shell meta-command, not a database or c2-object command. Bind it
top-level in `cmd/aims/commands.go` (its own group, e.g. `"shell"`, or a bare `AddCommand`),
alongside where the teamserver commands attach:

- `aims bring <agent-id>` — **connects** (needs the server to read the agent). Give it the
  `ConnectRun` pre-run (via `bindRunners`, same as every leaf that talks to the server) and an
  arg completion that reuses `c2.CompleteByID`.
- `aims shell-init <bash|zsh|fish>` — **offline**; pure code generation, no server. Must be
  excluded from the connect pre-run (like the teamclient `import` commands in
  `client.isOffline`).

### Generator flow (`aims bring <id>`)

1. `client.ConnectComplete`-style connect (reuse the existing connect path).
2. `con.Agents.Read(ctx, &c2.ReadAgentRequest{Agent: &pb.Agent{Id: id}, Filters: &c2.AgentFilters{MaxResults: 1}})`.
3. Build `Context` from the returned `pb.Agent` (`Id`, `Name`, `Tool`, `WorkingDirectory`, …).
4. Render the per-shell **payload** template (escaped scalars only) to stdout.
   The trusted `bring()` function (from `shell-init`) consumes it and applies stack + prompt.

### Shell state model (nesting)

Managed entirely by the trusted functions — no agent data in the logic:

- A parallel-array stack in the shell: `_aims_stack_id`, `_aims_stack_name`, `_aims_stack_prompt`
  (the saved prior `PROMPT`). `AIMS_CONTEXT_DEPTH` = stack length.
- `bring()`: push current (id/name/prompt) → set new `AIMS_AGENT_ID/NAME` from the parsed
  payload → rebuild the prompt segment from `$AIMS_AGENT_NAME` + depth → (re)assert the `aimsi`
  alias + completions.
- `leave()`: pop → restore the saved prompt/vars → at depth 0, unset vars, `unalias aimsi`,
  deregister completions.
- Prompt segment reads `$AIMS_AGENT_NAME` as a value (safe); note zsh may interpret `%` in the
  name as a prompt escape — cosmetic only, sanitize `%`→`%%` in the zsh payload if it bothers.

### What stays fixed vs. per-agent (injection surface at a glance)

| Piece | Emitted by | Contains agent data? |
|-------|-----------|:---:|
| `bring()` / `leave()` functions | `shell-init` | no |
| prompt-segment logic | `shell-init` | no (reads a var) |
| `aimsi` alias | `shell-init` | no (uses `$AIMS_AGENT_ID`) |
| completion registration | `shell-init` | no |
| `AIMS_AGENT_ID/NAME`, tool, cwd values | `bring` | **yes → escaped scalars only** |

The injection surface is one table row.

### Phased implementation plan

- **P0 — skeleton.** `cmd/bring` package, `shell.Shell`/`Detect`/`Quote` with unit tests
  (adversarial names: quotes, `;`, `$()`, backticks, newlines), templates embedded, both
  subcommands wired into the tree (return stubs). Builds with `GOWORK=off go build ./...`.
- **P1 — single agent, no stack.** `aims bring` connects + reads + emits the payload; `shell-init`
  emits `bring()`/`leave()` for one active agent (env + prompt segment + `aimsi`), no nesting.
  End-to-end: `source <(aims shell-init zsh)` then `bring <id>` changes the prompt and `aimsi
  exec id` tasks the agent; `leave` restores. Manual + a Go test asserting emitted payload is
  correctly escaped for adversarial names.
- **P2 — nesting/stack.** Parallel-array stack, depth in the prompt, `leave` pops.
- **P3 — scoped completions.** carapace completions for `aimsi` (remote files/procs/tasks),
  live-queried by `AIMS_AGENT_ID`; consider tag-groups per the CLAUDE.md completion preference.
- **P4 — `Agent.Tool` dispatch.** `aimsi` (or a sibling) resolves the agent's `Tool` and hands
  off to the native controller with the agent pre-selected.

### Recommended resolutions to the open decisions

1. **Where `bring`/`leave` live** → the trust-split above: `aims shell-init` emits the trusted
   functions; `aims bring` emits only escaped data. This is the load-bearing decision and it
   settles the rest.
2. **Alias root** → `aimsi` for P1; trivially renamed since it's defined in one fixed template.
3. **AIMS-subcommand vs `Agent.Tool` shim** → start `aimsi = aims c2 task <id>` (P1), add
   Tool-dispatch in P4. Staged, not either/or.

## Open decisions

1. **Alias root name** — `aimsi`, or another short token. It becomes muscle memory, so worth
   deciding deliberately.
2. **Aliases = AIMS subcommands vs. shims over `Agent.Tool`** — how much of the control plane
   lives in `aims c2 task …` vs. delegated to the agent's native tool. Sets the whole balance of
   AIMS-as-catalog vs. AIMS-as-driver.
3. **Prompt integration** — slot into the operator's supplied PS1 / oh-my-posh (pending their
   code); keep the agent segment replaceable.
4. **Saved-state stack storage** — env-only vs. a per-PID temp file for nesting.
5. **Where `bring`/`leave` live** — pure generated shell (like carapace) vs. a hidden `aims`
   helper subcommand backing them.
