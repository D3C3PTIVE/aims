# Scan Domain — Scanner-Plug Substrate (SCAN.md Part C)

> **Working plan — disposable.** Tracks the build-out of the scanner-plug substrate (SCAN.md
> Part C). Delete once the work lands and the permanent docs (SCAN.md / STATE.md / ROADMAP.md /
> CLAUDE.md) are updated.

## Context

Scan CRUD (`Create`/`Read`/`List`/`Upsert`/`Delete` + `scan list/show/rm`) is complete. The
remaining value in the scan domain is the **scanner-plug substrate** described in SCAN.md Part C:
turning AIMS from an nmap-XML parking lot into a **multi-tool scan orchestrator over a shared
object DB** — the literal payoff of the project's "many tools contribute to and consume the same
objects" thesis.

The **keystone is already done**: `Run.AddResult` (the universal `{Host,Address,Port,Service,Data}`
feeder fold, `scan/scan.go:94`) and `Run.AddHosts` (bulk, `scan/fold.go:37`) exist and are tested
(`scan/fold_test.go`), both delegating to the shared `host.SameHost`/`host.MergeHost` identity+merge
(`host/merge.go`). So the four remaining pieces build *on top of* a working fold, not around it.

Full sweep, one roadmap, in strict dependency order: Phase 1–3 are pure Go (no proto/codegen, each
independently shippable); Phase 4 is the heavy, codegen-gated streaming layer. **Recommended
checkpoint: stop and review after Phase 3** before committing to Phase 4.

Environment facts: `buf`/`protoc`/`protoc-gen-go`/`protoc-gen-gorm`/`protoc-gen-go-grpc` all
installed and `make gen` works (the provenance `Source` field is present in generated
`scan.pb.go`); the live-drivable Scanner is the already-wired nmap fork at
`~/code/github.com/maxlandon/nmap`; a zgrab2 fork (JSON output) sits at
`~/code/github.com/maxlandon/zgrab2` for the Phase-1 JSON→NSE demonstrator.

Standing constraints: build with `GOWORK=off go build ./...`; run tests one package at a time with
`GOFLAGS=-vet=off`; commit ONLY my own files (stage explicitly, never `git add -A` — other agents
edit the tree concurrently); completions/commands reach data ONLY through the teamclient RPC, never
the DB directly.

---

## Phase 1 — Ingestor interface + registry + generic JSON→NSE walker (pure Go)

**Goal:** formalize "any scanner's native output → a `*scan.Run`" as an interface with a registry
(the real deliverable), and validate it with **one** genuinely non-nmap tool. `nmap.FromXML`
(`scan/nmap/nmap.go:40`, one `xml.Unmarshal`) already *is* this shape. **Masscan is deliberately not
used** — its nmap-compatible XML teaches nothing over nmap; the leverage is the generic JSON walker.

- **New package `scan/ingest/`** (own package to hold interface + adapters together and avoid any
  domain/adapter import cycle — it imports `scan` (domain) and `scan/nmap`, neither of which imports
  it back):
  - `ingest.go`: `type Ingestor interface { Name() string; Ingest(raw []byte) (*scanpb.Run, error) }`,
    plus a small registry (`Register(Ingestor)`, `Get(name) (Ingestor, bool)`, `Names() []string`).
  - `nmap.go`: register an nmap ingestor wrapping `nmap.FromXML` (the reference adapter; stamps
    `Scanner="nmap"` if empty).
  - `jsonscript.go`: the philosophy-true payoff — a **single generic `jsonToScript(name string, v
    any) *nmap.Script`** walker (SCAN.md §D) that maps arbitrary decoded JSON into the recursive
    `nmap.Script{Elements[], Tables[]}` tree: object field → child `Table{Key}`, scalar →
    `Element{Key,Value}`, array → indexed `Table`. Written once, it serves **every** JSON scanner
    (all zgrab2 modules, nuclei, httpx, testssl) with no per-tool schema.
  - `zgrab.go`: register a zgrab2 ingestor as the concrete demonstrator — parse zgrab's
    newline-delimited `ScanResponse{Status, Protocol, Result}` per target, build a
    `Result{Address, Port, Service:{Name:Protocol}}`, hang `jsonToScript("zgrab.<module>", Result)`
    on the port, and feed through `scan.Run.AddResult`. Validated against the fork's output at
    `~/code/github.com/maxlandon/zgrab2`.
  - **Decision:** keep the zgrab2 wrapper as the demonstrator (a registry with only nmap doesn't
    validate the multi-tool interface; the fork is already in the tree, the wrapper is thin). The
    `jsonToScript` walker is the durable asset; the wrapper is trivially removable if it doesn't
    earn its keep.
- **CLI wiring:** thread the registry into the existing import path (`cmd/scan/commands.go`
  `importScan`, line 302). Add a `--scanner <name>` flag to `scan import` (default: sniff `nmap` XML,
  else pick by flag) so `aims scan import --scanner zgrab2 -f out.json` folds via the ingestor and
  reuses the existing `Scans.Create` dedup/merge store path. No new RPC.
- **Tests** (`scan/ingest/ingest_test.go`): a fixture zgrab2 JSON blob → assert it yields a `Run`
  whose host:port carries the expected `Script/Table/Element` tree; a `jsonToScript` unit test over
  nested object/array/scalar JSON; and idempotence (ingest+fold the same bytes twice → host count
  stable). No external binary needed — ingest is bytes→Run, fixtures suffice.

**Verify:** `GOWORK=off go build ./...`; `GOFLAGS=-vet=off go test ./scan/ingest/`.

---

## Phase 2 — Hosts-as-targets bridge + Scanner interface (pure Go)

**Goal:** close the loop — derive scan `Target`s from *stored* hosts, and define the driver
interface so a scanner can be run against them. `scan.Target{Address,Domain,Tag,Port}`
(`scan.proto:163`) exists as an input type but has no bridge.

- **New `scan/targets.go`:** `TargetsFromHosts(hosts []*host.Host, opts) []*scanpb.Target` — map each
  host's `Addresses` (`network.Address.Addr`) / `Hostnames` / `Ports` into `Target`s. Plus
  `TargetSpecs([]*Target) []string` (address/host tokens ready to hand a scanner as args).
- **`scan/drive/scanner.go`** (NOT `scan/scanner.go`): the `Scanner` interface + nmap adapter.
  **Design correction:** the AIMS-native nmap fork imports the `scan` domain package, so `scan`
  cannot import the fork without a cycle. The interface + adapter therefore live in a new leaf
  package `scan/drive` (imports fork + scan, nothing imports it — same shape as `scan/ingest`).
  ```go
  type Scanner interface {
      Scan(ctx context.Context, targets []*scanpb.Target, args ...string) (
          <-chan *scanpb.Result, <-chan *scanpb.TaskProgress, error)
  }
  ```
  `Nmap` is the reference adapter. It drives the **synchronous** `Run()` and surfaces hosts
  (as `Result{Host}`) + progress on the channels — because the fork's async `RunAsync`/
  `YieldHosts`/`YieldProgress` path is broken (see Phase-4 prerequisite below). Real incremental
  streaming is Phase 4's job.
- **CLI `--from-db` deferred to Phase 4.** `aims scan run nmap` has `DisableFlagParsing` (raw
  passthrough), so an aims-owned `--from-db` flag is awkward to add now, and the whole `run`
  command is reworked for foreground/detached streaming in Phase 4 — the natural place to wire
  `TargetsFromHosts` → target specs onto the (then non-passthrough) run path.

**Done:** `scan/targets.go` (`TargetsFromHosts`/`TargetSpecs`, tested in `scan/targets_test.go`)
and `scan/drive/scanner.go` (`Scanner` + `Nmap`, `scan/drive/scanner_test.go` covers the
no-targets guard; the live nmap path needs the binary, deferred like `run_integration_test.go`).

**Verify:** `GOWORK=off go build ./scan/ ./scan/drive/`; `go test ./scan/` and `./scan/drive/`.

---

## Phase 3 — Run-to-run diff (pure Go)

**Goal:** native `ndiff` across *all* scanners at once (attack-surface drift), nearly free given
timestamped Runs + host dedup.

- **New `scan/diff.go`:** `DiffRuns(a, b *scanpb.Run) *RunDiff` reusing `host.SameHost`/`host.SamePort`
  (`host/merge.go`) for identity so diff and fold agree. `RunDiff{ NewHosts, GoneHosts []*host.Host;
  Changed []HostDelta }`; `HostDelta{ Host; NewPorts, GonePorts []*host.Port; ChangedServices [...] }`.
  Pure comparison, no DB.
- **CLI:** `aims scan diff <idA> <idB>` in `cmd/scan/` — resolve both by ID-prefix (reuse the
  `scan show`/`scan rm` prefix-match pattern in `cmd/scan/commands.go`), `con.Scans.Read` each via
  the teamclient, compute `DiffRuns`, render.
- **Display:** a diff renderer in `cmd/scan/` (added=green `+`, removed=red `-`, changed=yellow `~`),
  built on the existing `cmd/display` primitives (Table/Details) — no new engine.
- **Tests** (`scan/diff_test.go`): two hand-built Runs with a known new host, a newly-open port, and
  a changed service version → assert each lands in the right bucket.

**Verify:** build; `GOFLAGS=-vet=off go test ./scan/`; live: import two overlapping nmap XML runs
into the dev DB, `aims scan diff <a> <b>`.

> **CHECKPOINT — review/commit here.** Phases 1–3 are a complete, self-contained, low-risk increment
> (no proto/codegen, no server streaming) that fully validates the multi-tool + orchestration +
> drift thesis. Phase 4 is a larger, riskier commitment.

---

## Phase 4 — Streaming scans + job model + live view (proto + codegen)

**Goal:** long scans run **server-side**, survive the operator's terminal, stream progress, and are
visible to every operator — with **I/O parity** (identical path for in-process teamserver vs remote
teamclient). Heaviest phase: the only one touching proto/codegen and the teamserver.

> **PREREQUISITE (structural, discovered in Phase 2): the nmap fork's async path is broken.**
> `RunAsync()` starts the process, but `YieldHosts()`/`YieldProgress()` spin goroutines that select
> on an internal `s.done` channel **nothing ever closes** (`Wait()` only calls `cmd.Wait`), so they
> never terminate and their channels never close — and `YieldHosts` even `close(s.done)`s a channel
> it only reads. Genuine incremental streaming (progress/hosts as nmap runs) requires fixing the
> fork at `~/code/github.com/maxlandon/nmap` (signal/close `done` on completion + ctx-cancel; drop
> the erroneous close). Until then the server-side job can only stream *after* a sync `Run()`
> completes, which defeats the point. Fix the fork first, then build the streaming RPC on it.

- **Proto (`scan/pb/rpc/scans.proto`) + `make gen`:** add a server-streaming RPC,
  `rpc Run(RunScanRequest) returns (stream RunScanUpdate)`, where `RunScanUpdate` is a oneof
  `{ TaskProgress progress; repeated host.Host hosts; scan.Run final }`, plus `RunScanRequest
  { string Scanner; repeated string Args; repeated scan.Target Targets; }`. Run `make gen`
  (`buf generate` ×2 + `maltego-tags.sh`) and **smoke-test regen end-to-end before building on it**;
  never hand-edit `*.pb.go`/`*.pb.gorm.go`.
- **Server (`server/scan/`):** implement streaming `Run` — exec the scanner server-side via the
  Phase-2 nmap adapter (`RunAsync` + `YieldHosts`/`YieldProgress`), fold hosts into a `Run` as they
  arrive, stream `RunScanUpdate`s to the client, and persist via the existing `Create` fold on
  completion (optionally persist incrementally each tick so `scan show` reflects live state). Track
  active scans in a **lightweight in-server job registry** (`map[id]*scanJob` with a `context.CancelFunc`)
  — note: `reeflective/team`'s job model (`server/jobs.go`) is listener-oriented, so a small scan-job
  registry is cleaner than forcing scans into team's listener jobs; revisit reuse during
  implementation.
- **Client (`client/`):** a `Scans.Run` streaming wrapper over the generated stream client.
- **CLI (`cmd/scan/`):**
  - `scan run nmap <args>` → **foreground** (default): stream `TaskProgress`, block to completion,
    show result; **Ctrl-C detaches** (job keeps running), does not kill.
  - `scan run nmap <args> -d/--background` → submit, print job ID, return.
  - `scan jobs` (list running), `scan attach <id>` (reattach to stream), `scan stop <id>` (cancel).
  - `watch -n1 aims scan show <id>` → live view for free (the stored Run keeps updating). Keep
    `scan show` stateless/single-shot; share its exact renderer, don't fork it.
  - **I/O parity:** foreground streaming MUST go through the team RPC/stream layer uniformly — no
    in-process function-call shortcut for the all-in-one binary.
- **Tests:** extend `cmd/aims/roundtrip_test.go` (boots the real in-memory teamserver + client over
  bufconn) with a streaming `Run` round-trip using a fake/fast scanner (or the nmap fork against
  `localhost`), asserting progress frames arrive and the final Run persists.

**Verify:** `make gen` clean; build; per-package tests; live: `aims scan run nmap -sT -p22
scanme.nmap.org` streams progress then stores; `-d` returns a job ID; `scan jobs`/`attach`/`stop`
work; `watch aims scan show <id>` refreshes during a run.

---

## Cross-cutting

- **Preserve the four Part-A primitives** (evidence/confidence, summarize-the-boring, run provenance,
  schemaless NSE) — do not flatten them for convenience.
- **One identity everywhere:** all new matching reuses `host.SameHost`/`host.SamePort`/`host.MergeHost`
  and `Run.AddResult`/`AddHosts`; never a parallel comparator.
- **Docs:** flip the SCAN.md Part-B "latent" rows (Ingestor / hosts-as-targets / streaming / diff) to
  done as each phase lands; update STATE.md/ROADMAP.md/CLAUDE.md scan sections and the
  `aims-scan-display-rework` memory pointer.
- **`Result` stays a feeder** (not a stored row) per its proto contract; the persistent tree is `Run`.

## Backlog / follow-ups (non-structural — revisit at the end)

A running list of "kind-of-not-structural" issues to come back on once the substrate phases are
in. Grow it as more surface; do NOT stop the build-out to fix these. They are correctness unknowns
in the shared persistence/display layer that non-nmap ingest is the first to stress — track, don't
assume, defer.

**Phase-4 follow-ups (streaming):**
- **Live view `watch scan show` needs incremental persistence.** The streaming server persists the
  run only at completion (`consume` → `persistRun` once), so `scan show` during a run shows nothing
  until it finishes. The live view today is the foreground stream / `scan attach`. For the
  poll-based `watch scan show` view (SCAN.md), persist the run incrementally (upsert on each
  host/progress tick) so the stored Run reflects live state.
- **jobs/attach/stop need a persistent teamserver.** ✅ *Job-model logic validated*
  (`TestJobsAttachStopLive`: background scan → Jobs lists it → Attach streams it → Stop cancels it,
  against one persistent server). The all-in-one `aims` binary still boots an ephemeral in-process
  teamserver per command, so a `--background` job dies when that process exits — `scan jobs`/
  `attach`/`stop` are only *useful* against a long-running `aims teamserver` daemon. Remaining: a
  real daemon + teamclient smoke test (deployment, not logic).
- **nmap fork async reads `s.stdout` concurrently with `io.Copy` writes.** `YieldHosts`/
  `YieldProgress` poll `s.stdout.Bytes()` (a `bytes.Buffer`) while `RunAsync`'s copier writes it —
  a data race (`go test -race` would flag). Pre-existing design; a proper fix wraps the buffer in a
  mutex. Works in practice (1s polling, burst writes).
- **Codegen unblock is a workaround, not a fix.** `buf generate` is blocked on BSR auth; scans.pb.go
  was regenerated with local `protoc` (gorm proto from the module cache, M-mapped go_package). Fine
  for scans (no ormable messages), but any proto change touching gorm-ormable messages still needs
  buf (BSR) or a vendored gorm proto. See the `aims-provenance-source-domain` memory.

- **Host display is not nil-safe for non-nmap hosts.** `host/host.go` `DisplayFields` dereference
  `h.Status.State` (lines 100/131–137) and `h.OS.Matches` (line 169) with no nil-guard. nmap hosts
  always carry `Status`/`OS`, so this never fired; a service scanner like zgrab legitimately yields
  hosts with neither, and `aims hosts list` then panics (SIGSEGV). Mitigated on the ingest side (the
  zgrab adapter now stamps `Status{up}` + port `State{open}` evidence, clearing the `Status` sites),
  but the **`h.OS.Matches` deref still crashes** OS-less hosts. Fix belongs in the host-domain display
  (guard nil `OS`/`Status`), which an agent is actively editing (`c609f7c`) — coordinate, don't clobber.
- **Dedup / cascade / relationships at Upsert/Delete — ✅ VERIFIED cross-tool** (`345feb0`,
  `server/scan/crosstool_test.go`): a zgrab host merges into an existing nmap host for the same IP
  (union ports/scripts, nmap evidence preserved); a re-observed host tree across two distinct runs
  is DB-level idempotent (one host/port/script, both runs link the shared row); deleting one tool's
  run unlinks only its `run_hosts` join and leaves the shared host + both tools' ports/scripts.
  No bugs found — the fold + `run_hosts` unification + Delete-unlink behave correctly across tools.
  (Note: `SamePort` keys on (proto, number); the tests use `Protocol:"tcp"` on both sides — a tool
  that spells the protocol differently would still be a mismatch, but no such tool is wired.)
- **`server/scan.Read` loaded hosts UNSCOPED.** ✅ *Fixed* (`24b6bfd`): the per-run
  `database.Find(&run.Hosts)` (whole-table Find → every run got all hosts) is replaced by preloading
  the host subtree through the `run_hosts` many2many in the main query (`Preload("Hosts")` scopes per
  run; `Hosts.<assoc>` pulls the nested tree; explicit `Hosts.Addresses`). `TestReadScopesHostsPerRun`
  + live `scan diff` now report real drift. This also un-gates stored-run diff for DISJOINT-host
  runs; the *shared-host* snapshot limitation below still stands.
- **Cross-run unification vs. run diff (design tension).** Ingest MERGES a host observed by N runs
  into ONE shared row (the `sharedRunCount` insight), so even with the Read bug fixed, two runs that
  saw the same physical host both point at the *merged* current state — per-run host/port snapshots
  are not preserved, so `scan diff` can't show same-host drift (new/gone whole hosts still work).
  For true drift, either snapshot per-run observations (heavier model) or diff in-memory Runs before
  the fold. `scan.DiffRuns` itself is correct and immediately useful on in-memory/pre-fold Runs and
  on disjoint-host runs; only the *stored shared-host* diff is limited. Decide the model deliberately.

## Critical files

- `scan/scan.go:94` (`AddResult`), `scan/fold.go` (`AddHosts`/`foldHost`), `host/merge.go`
  (`SameHost`/`SamePort`/`MergeHost`) — the fold/identity primitives everything reuses.
- `scan/nmap/nmap.go:40` (`FromXML`) — the reference Ingestor shape.
- `scan/target.go`, `scan.proto:163` (`Target`) — Phase 2 bridge base.
- `~/code/github.com/maxlandon/nmap/nmap.go` (`NewScanner`/`Run`/`RunAsync`/`YieldHosts`/
  `YieldProgress`) — the live Scanner.
- `scan/pb/rpc/scans.proto`, `server/scan/scan.go`, `client/client.go:55`, `server/server.go:76`,
  `cmd/scan/commands.go`, `cmd/scan/run.go`, `cmd/scan/run_complete.go` — Phase 4 wiring surface.
