# AIMS — Re-Entry Roadmap

> Written 2026-07-19. Companion to [`STATE.md`](./STATE.md) (where things are) and
> [`CLAUDE.md`](./CLAUDE.md) (architecture) and [`SCAN.md`](./SCAN.md) (scan model &
> scanner-plug substrate). This is the *plan to pick the project back up*
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

### Phase 0 — Unblock the build ✅ DONE

The tree builds and the `aims` binary runs. gondor/maltego was isolated behind `//go:build
maltego` (option A) and the Tailscale transport behind `//go:build tailscale`; the
`reeflective/team` v0.3.2 migration and the ~1-year dependency drift it masked are resolved.
`go build ./...` is green; `make build`/`make install` recipes exist. (Deferred: a
fixed `d3c3ptive/gondor` fork to make Maltego always-on — folds into the org migration below.)

### Phase 1 — Correctness & hygiene sweep ✅ DONE

Debug leftovers removed, the crossed `cmd/display/defaults.go` `init()` corrected, and the stray
copy-pasted `ReadHost`/`ListHost`/`UpsertHost` stubs pruned from `server/network/service.go`.
Only residual: the c2 Agents server is still the generic `type server` vs Channels' `channelServer`
— a cosmetic `server`→`agentServer` rename, not a blocker.

### Phase 2 — Complete the gRPC CRUD (the core functional gap; in progress)

**Done:** scan (**full CRUD**) and credential (**full CRUD**); host (Create/Read/Upsert). **Still
stubbed:** host Delete; network Create/Upsert/Delete; c2 Upsert/Delete;
and the entirely-stubbed Users and Logins services. The RPC protos define **Create / Read /
Upsert / Delete** (List folds into Read via `*Filters`; Update via Upsert).

Use **`server/credential/credential.go` (full CRUD)** and **`server/host/host.go`** as templates.
The pattern is: PB→ORM (`ToORM`), build preload clauses (`WithPreloads`/`db.PreloadAll`),
query/write via GORM, ORM→PB (`db.ToPBs`).

Remaining task list:

| Domain/service | Implement | Reference / notes |
|---|---|---|
| host Hosts | `Delete` | Upsert done (additive+idempotent fold + deep child enrichment `saveMergedHost`/`saveMergedPorts`); Delete has scaffolding ending in Unimplemented (`host.go:480`) |
| host **Users** | all: `Create/Read/Upsert/Delete` | fully stubbed; mirror Hosts |
| network Services | `Create`, `Upsert`, `Delete` | Read/List done; reuse the shared `host` fold for dedup |
| credential **Logins** | all | fully stubbed |
| scan Scans | ✅ **done** | Full CRUD. Create folds hosts via `host.IngestHosts` + `run_hosts` join (cross-run unification); Delete unlinks the shared join (hosts survive); Upsert idempotent; List delegates to Read. CLI `scan rm` with a running-scan guard. |
| c2 Agents/Channels | `Upsert`, `Delete` | mirror credential/host |

Cross-cutting for this phase:
- **Standardize the dedup story.** ✅ Largely done for hosts/scans: the canonical primitive is now
  the shared `host.MergeHost`/`host.SameHost` fold (`host/merge.go`) driving `host.IngestHosts`
  (DB-level, additive+idempotent), which replaced the old `FilterNew` drop-not-merge path on the
  host and scan servers. Remaining: extend the same fold to credentials/users so re-imports merge
  rather than duplicate.
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
- **Testing.** Growing from a small base. Done so far: the host ingest tests
  (`server/host/host_test.go`, Create/Upsert dedup+merge against the server struct) and an
  end-to-end transport test (`cmd/aims/roundtrip_test.go`) that boots the real in-memory
  reeflective/team teamserver + AIMS client over bufconn and round-trips Hosts/Scans through
  the teamclient — proving commands reach the DB only through the team client. Still to add, in
  priority order: (1) a build/`go vet` gate, (2) round-trip `ToORM`/`ToPB` tests per domain,
  (3) dedup (`AreXIdentical`) tests, (4) the nmap-XML → Host unmarshal path (the
  interoperability contract).
- **Benchmarks (scale + responsiveness).** AIMS is meant to be a *responsive* CLI over a
  possibly large object store; add `Benchmark*` tests to prove it scales with heavy data.
  Cover the hot paths: ingest dedup/merge (`host.MergeHost`/`SameHost` and the server
  `Create`/`Upsert` fold — these load every existing host per call, an O(n²) shape worth
  measuring), the `Read`→`ToPB` preload path on a large host table, and the `cmd/display`
  table/completion rendering at high row counts. Seed a big sqlite DB fixture and track
  latency/allocs so regressions in "feels instant" are caught.
- **Refactoring & cleanup sweep.** Do a repo-wide pass for reuse/simplification/dead-code:
  the cosmetic `server/c2` Agents `type server`→`agentServer` rename, stubbed handlers returning
  `nil`, the empty `credential/core.go` scope helpers, the dead `Client.conn` field and unchecked
  `client.New` error in `cmd/aims/root.go`, and the commented-out blocks left in
  `server/host/host.go` `Delete`. (Some PB↔ORM boilerplate has since been folded into
  `db.ToPBs`/`db.PreloadAll` and `cmd/display`'s `Headers()` builder.) Fold remaining shared
  shapes into helpers where the domains have diverged only cosmetically.
- **Doc drift.** Update `README.md`: no `vendor/` (module cache), generated code sits next to
  each `.proto` (not `proto/gen/`), codegen files are at repo root. Keep `CLAUDE.md`/`STATE.md`
  current as the source of truth.

## Suggested next sitting (if you only have a few hours)

Phases 0–1 are done; the base compiles and runs. Highest-leverage remaining slices, each
copyable from the credential/host CRUD templates:

1. **host `Delete`** — finish the scaffolded body (`server/host/host.go:480`), then wire the
   `hosts rm` CLI `RunE` (Phase 3) to it. Smallest end-to-end Delete slice.
2. **scan `Delete`/`List`** + a `scan rm` CLI command — Delete is the natural pair to the working
   ingest.
3. Then widen: network mutations, c2 Upsert/Delete, and the fully-stubbed Users/Logins services.
