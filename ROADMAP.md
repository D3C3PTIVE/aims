# AIMS — Re-Entry Roadmap

> Written 2026-07-19. Companion to [`STATE.md`](./STATE.md) (where things are) and
> [`CLAUDE.md`](./CLAUDE.md) (architecture). This is the *plan to pick the project back up*
> after ~1 year: ordered phases, concrete tasks, and the reasoning behind the ordering.

## Guiding strategy

1. **Compile first, features second.** Nothing is verifiable until the tree builds. Step 0
   is an absolute prerequisite for everything else.
2. **The model layer is the asset — protect it.** The generated `pb` layer is mature and
   compiles. Never hand-edit generated code; change `.proto` + `make gen`. Keep all
   hand-written behavior in the domain root `<name>.go` files and the `server/`, `cmd/` layers.
3. **Finish one vertical slice before widening.** The **host** domain is the reference
   implementation (Read/Create + dedup + display + completions). Bring every other domain up
   to the host bar rather than starting new surface area.
4. **Small, releasable increments.** Each phase below should end at a compiling, runnable
   state. Prefer a working narrow tool over a broad broken one.
5. **Land the org migration early** so all later commits are already on `d3c3ptive`.

## Priority-ordered phases

### Phase 0 — Unblock the build ⛔ (do this first; ~half a day)

The tree does not compile: `github.com/maxlandon/gondor/maltego` is broken at the pinned
version, and every domain root package imports it (see STATE.md → Build status).

**Key fact that makes this cheap:** `AsEntity()` / `maltego.*` is **defined but never called**
anywhere in `server/`, `client/`, `cmd/`, or `db/`. The Maltego integration is currently dead
weight, so we can decouple it without losing any working functionality. Options, cheapest first:

- **(A) Isolate behind a build tag (recommended).** Move every `AsEntity()` method into
  `*_maltego.go` files guarded by `//go:build maltego`. Default builds drop the gondor import
  entirely and compile; the Maltego path is opt-in and can be repaired later. Lowest risk,
  reversible, preserves intent.
- **(B) Fork/vendor & fix gondor.** Point the module at a fixed fork (e.g. `d3c3ptive/gondor`)
  via `replace` and repair the compile errors (`undefined: base`, `getDirectory`,
  `configuration.Entity`, `getNamePlural`). More work, but keeps Maltego always-on. Fits the
  org migration (gondor is also `maxlandon`-namespaced).
- **(C) Delete the Maltego integration** outright (remove imports + `AsEntity`). Simplest, but
  throws away a stated secondary goal of the project. Only if Maltego is truly out of scope.

**Acceptance:** `GOWORK=off go build ./...` succeeds (allow first-run for the large
tailscale/gvisor download). Add a CI or a Makefile `build`/`test` target to keep it green.

> Sub-note: the full build pulls tailscale + gvisor via `reeflective/team`. If that transport
> weight is unwanted long-term, consider whether the teamserver transport should be optional.

### Phase 1 — Correctness & hygiene sweep (~half a day, right after it compiles)

Cheap fixes that remove confusion before building on top:

- **Untangle the c2 file/type swap.** `server/c2/channel.go` implements the Agent server and
  `server/c2/agent.go` the Channel server (`type channelServer`). Rename files/types to match
  contents and fix the mislabeled `Unimplemented` messages ("UpsertChannel" in the agent file,
  etc.). Do this *before* extending c2.
- **Remove debug leftovers:** `println(c.Type)` in `host/host.go` (`Purpose`); `fmt.Println(val)`
  and the empty `if head == "Purpose" {}` blocks in `cmd/display/details.go`.
- **Fix `cmd/display/defaults.go` `init()`:** the `stdoutTerm/stdinTerm/stderrTerm` assignments
  are crossed (stdout←os.Stderr, stderr←os.Stdin, stdinTerm never set). Table sizing reads
  `stderrTerm.Fd()` — verify it points at a real terminal.
- **Prune the stray `network` service stubs** copied from host (`ReadHost`/`ListHost`/
  `UpsertHost` in `server/network/service.go`) — dead, misleading methods.

### Phase 2 — Complete the gRPC CRUD (the core functional gap; ~1 week)

Read/Create exist for exercised domains; **Upsert and Delete are stubbed almost everywhere,
and two whole services (Users, Logins) are fully stubbed.** The RPC protos define
**Create / Read / Upsert / Delete** (List folds into Read via `*Filters`; Update via Upsert).

Use **`server/host/host.go` as the template** for every method. The pattern is:
PB→ORM (`ToORM`), build preload clauses (`WithPreloads`), query/write via GORM, ORM→PB (`ToPB`).

Task list (each = copy the host pattern + wire dedup/preloads):

| Domain/service | Implement | Reference / notes |
|---|---|---|
| host Hosts | `Upsert`, `Delete` | finish the commented-out bodies already sketched in `host.go` |
| host **Users** | all: `Create/Read/Upsert/Delete` | fully stubbed; mirror Hosts |
| network Services | `Create`, `Upsert`, `Delete` | Read/List done; reuse `identical.go` for dedup |
| credential Credentials | `Create`, `Upsert`, `Delete` | Read/List done |
| credential **Logins** | all | fully stubbed |
| scan Scans | `Upsert`, `Delete` | Create/Read done |
| c2 Agents/Channels | `Upsert`, `Delete` | after Phase 1 rename |

Cross-cutting for this phase:
- **Standardize the dedup story.** `internal/db.FilterNew` + per-domain `AreXIdentical`
  (`*/identical.go`) already exist for hosts/scans/services — extend to credentials/users so
  re-imports don't duplicate.
- **Decide List vs Read.** Some server types expose a `List` method not in the proto. Either
  add `List` RPCs to the protos and regenerate, or drop the extra methods for consistency.
- **Delete semantics.** Confirm GORM cascade behavior (README claims sane cascade defaults);
  add tests that deleting a Host removes its owned Ports/OS/Trace rows.

### Phase 3 — Wire the CLI actions (~2–3 days)

The command tree, flags, and completions exist, but several handlers are no-ops.

- **Implement the empty `RunE`s:** `hosts add` / `hosts rm` (they `return nil`), and audit the
  other domains' `add`/`rm`/`show` for the same. `add` should read `-f/--file`, unmarshal, and
  call the (now-real) `Create`/`Upsert`; `rm` should resolve the ID/hostname completion arg and
  call `Delete`.
- **Wire `import`.** `cmd/export/` has `ImportCommand` (JSON/XML via protoreflect) — hook it
  into each domain command alongside the working `export`, so nmap XML / saved objects can be
  loaded. This is the payoff of the "many tools feed one DB" thesis.
- **End-to-end smoke test:** `aims` teamserver up → `import` an nmap XML → `hosts list` /
  `hosts show` → `export`. This exercises the whole stack and validates the data model claims.

### Phase 4 — Finish the designed-but-empty APIs (backlog; scope as needed)

- **Credential scope helpers** (`credential/core.go`: `WhereLoggedInHost`, `WhereOriginIs`,
  `WhereOriginServiceForHost`, `WhereOriginSessionForHost`) — the Metasploit-style querying
  API. Implement as GORM scopes returning `func(*gorm.DB) *gorm.DB`.
- **Maltego** — repair whichever Phase-0 option was chosen; finish the stubbed `AsEntity()`
  (e.g. `network/service.go` returns an empty `maltego.Entity{}`). This delivers the "objects
  as Maltego entities" secondary goal.
- **Scan runner** — `git log` shows an "idea for running scans" (`scan/target.go`,
  `de2505f`). Decide whether AIMS *runs* scanners (nmap/sx/zgrab) or only *stores* their
  output. The README leans "storage/spec only"; a runner is a scope expansion to make deliberately.

## Cross-cutting workstreams (do alongside the phases)

- **Org migration to `d3c3ptive`.** Module path is already `github.com/d3c3ptive/aims`
  (good). When the GitHub repo moves: verify `buf.gen-*.yaml` `go_package_prefix` (already
  `d3c3ptive`), and resolve the **`maxlandon/gondor`** dependency (fork to `d3c3ptive/gondor`
  or drop) so no `maxlandon` trace remains — this dovetails with Phase 0 option (B).
- **Testing.** There are essentially no tests. Add, in priority order: (1) a build/`go vet`
  gate, (2) round-trip `ToORM`/`ToPB` tests per domain, (3) dedup (`AreXIdentical`) tests,
  (4) the nmap-XML → Host unmarshal path (the interoperability contract).
- **Doc drift.** Update `README.md`: no `vendor/` (module cache), generated code sits next to
  each `.proto` (not `proto/gen/`), codegen files are at repo root. Keep `CLAUDE.md`/`STATE.md`
  current as the source of truth.

## Suggested first sitting (if you only have a few hours)

1. Phase 0 option (A): build-tag the Maltego methods → get `go build ./...` green.
2. Phase 1: c2 rename + delete the debug prints + fix the `init()` swap.
3. Commit. You now have a compiling, coherent base to grow from — everything else is additive.
