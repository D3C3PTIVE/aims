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

Standing constraints: build with `go build ./...`; run tests one package at a time with
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

**Verify:** `go build ./...`; `GOFLAGS=-vet=off go test ./scan/ingest/`.

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

**Verify:** `go build ./scan/ ./scan/drive/`; `go test ./scan/` and `./scan/drive/`.

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

## Phase 5 — Run lifecycle: cleanup / tombstone / history (proto + Go) — ✅ DONE (`4af9c31`)

Repeated runs of the same scan definition (a cron scan of the same hosts) accumulate near-duplicate
`Run`s. Phase 5 collapses each *series* onto one visible head **without** losing the drift history
`scan diff` (Phase 3) depends on.

**Governing distinction:** *identical output* (byte-equal `RawXML` — a re-import, safe to delete) vs
*identical definition* (same scanner+args+targets, drifting output — must be **tombstoned**, never
deleted, or `scan diff` loses exactly the runs it needs). Tombstone is primary; hard-delete is opt-in
(`--prune`) for the byte-identical subset only.

- **Proto (ormable regen):** `Run.SupersededBy` (Id of the surviving head; "" == head), `Run.FormerRuns`
  (monotonic count of absorbed siblings — the indicative trace, survives `--prune`), `Run.ResumedFrom`
  (Phase-6 seed). `RunFilters.IncludeSuperseded` / `RunFilters.SupersededBy` for server-side scoping.
- **`scan/lifecycle.go` (pure Go):** `seriesKey` (arg-order-normalized, profile-aware), `pickHead`
  (never demotes a clean `done` under a later `failed`/`interrupted`), `ComputeCleanup` (idempotent,
  chain-flattening, monotonic FormerRuns), `Prunable` = byte-identical only.
- **Server `Cleanup` RPC:** applies the plan with **column-scoped** writes (`UpdateColumn`, so a
  tombstone never bumps the `UpdatedAt` heartbeat — else a stale interrupted run would masquerade as
  running) in a transaction; `--prune` hard-deletes via Delete's `run_hosts`-unlink path so shared
  hosts survive. Server `Read` default hides tombstones (heads only); `IncludeSuperseded` /
  `SupersededBy` let `history`/`show`/`rm`/`diff` reach any run **server-side** (the `history` series
  is one scoped query, not read-all-and-triage — a design ask from the user).
- **CLI:** `scan cleanup [--prune] [--yes]` (dry-run default), `scan history [id]`, `scan list --all`,
  a `Series` (+N) column; completions offer heads only.
- **Tests:** `scan/lifecycle_test.go` + `server/scan/cleanup_test.go` (persist+filter+idempotence+
  shared-host survival + heartbeat-not-bumped; prune hard-delete). **Live-verified** on the dev DB
  (dry-run grouped 21 real runs → 3 series heads), which surfaced and fixed the heartbeat-bump bug now
  guarded by a regression test.

> **Codegen note:** the ormable `scan.proto` regen used the **offline buf recipe** (BSR auth-walled):
> vendor `infobloxopen/protoc-gen-gorm@v1.1.5/proto/{options,types}`, comment the BSR dep + blank
> `buf.lock`, `buf generate --template buf.gen-gorm.yaml --path scan/pb/scan.proto`, `maltego-tags.sh`,
> sed the vendored-options import back to `infobloxopen/...`, restore. **Validated byte-identical**
> against the committed output before adding fields. The rpc `scans.proto` (non-ormable) used the
> lighter direct-`protoc` recipe. See `aims-provenance-source-domain` memory.

---

## Phase 6 — `scan resume` for interrupted runs — DESIGN (AIMS-owned target-diff)

> **Design only (not built).** Pivoted from the original "native + derived" plan after discussion:
> make **AIMS-owned per-target tracking + command reforging** the *primary* mechanism, native
> `nmap --resume` a *deferred refinement*. Rationale below.

**Why AIMS-owned beats scanner-native as the foundation.** The streaming fold already sees every
result as it lands and persists incrementally, so AIMS can own an authoritative record of which
targets produced results. That signal is **uniform across every scanner** (no per-tool checkpoint
format — nmap's `-oG` log, masscan's `paused.conf`, nothing for zgrab2/httpx), and it **survives a
SIGKILL** that would destroy a scanner's own un-flushed checkpoint. It is the substrate thesis run
backwards: AIMS knows the targets, so AIMS reforges the command.

**Granularity — the honest boundary.** AIMS-owned tracking is **target-granular** (re-scan only the
hosts/targets that produced nothing); it is **not port-granular** (a scan killed mid-host re-scans
that whole host — fold-idempotent, just repeated work). Native `nmap --resume` picks up mid-host; that
is its *sole* advantage and the only reason it stays on the roadmap.

**Primary mechanism (no new driver interface, no new ormable field):**
1. **Per-target completion tracking.** As `consume` folds each `Result`, match its Host back to the
   run's `Targets` (by address/hostname) and mark `Target.Status = done` — a *down* host counts as
   done (it was scanned); `Targets − Hosts` would wrongly re-scan down hosts. **Wiring needed:**
   `consume` must carry `job.targets` onto the run and persist Status as results land (it does not
   today).
2. **Interrupt-aware final persist.** `consume` always writes `Stats.Finished{success}` today (→
   `done`) even when cancelled. It must instead check `jobCtx.Err()` and, if cancelled, persist the
   partial run **without** `Finished` so the heartbeat goes stale → `stateInterrupted` (the resumable
   state). Pass `jobCtx` into `consume`.
3. **Reforge + run.** `scan resume <id>` → server `Resume(ResumeScanRequest{Id})`: load the interrupted
   run, `remaining = Targets with Status != done`, reforge `Scanner + Args + TargetSpecs(remaining)`,
   drive via the existing `drive.Scanner.Scan`, stream like `Run`, fold into a new run with
   `ResumedFrom = oldId`, and **tombstone the parent** (Phase-5 `SupersededBy`) — a resume chain is a
   series.

**Honest limitation — structured targets required.** Target-diff needs the run to carry *structured*
`Targets`. The `--from-db` path (Phase 2) provides them; a raw `scan run nmap -sT 10.0.0.0/24` keeps
targets inside `Args`, so there resume can only re-run the whole command (fold-idempotent) until a
follow-up parses specs out of `Args`. Report which mode was used.

**Guard:** only `stateOf ∈ {interrupted, failed}` resume; error on running/done.

**Codegen:** only a `Resume(ResumeScanRequest{string Id}) returns (stream RunUpdate)` RPC on the
non-ormable `scans.proto` (light direct-`protoc` regen). **No** ormable change — `ResumedFrom` and
`Target.Status` already exist; the pivot drops the `Run.Checkpoint` field the old plan wanted.

**Deferred refinement — native `nmap --resume` (NOT this slice):** for port granularity, later add an
always-on `-oG <tmpfile>`, capture the partial log on interrupt, `nmap --resume <file>`. The fiddly,
weakly-testable path (nmap's all-or-nothing `--resume` args, temp-file lifecycle, masscan needing
SIGINT not SIGKILL for `paused.conf`). Worth it only after the target-diff core is proven, and only
where sub-target granularity matters.

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
- **Live view `watch scan show`** — ✅ *done* (`71c02bc`): `consume` snapshots the run (upsert by
  job id, `persistRun` OnConflict UpdateAll) as hosts arrive; run id = job id; final persist marks
  Stats.Finished so a done scan reads "done". `TestRunSnapshotVisibleMidScan` confirms the run is
  readable mid-scan. Remaining nicety: mid-scan state shows "queued" (no Begin/Progress persisted —
  task-stream children would duplicate on upsert); hosts still appear live, which is the signal.
- **jobs/attach/stop need a persistent teamserver.** ✅ *Validated at both levels*:
  `TestJobsAttachStopLive` (server struct) and `TestScanJobsOverTeamClient` (full transport —
  client → teamclient → bufconn → teamserver → server/scan → drive → nmap). Background scan →
  Jobs → Attach → Stop, run persists under the job id. The all-in-one `aims` binary still boots an
  ephemeral in-process teamserver per command, so a `--background` job dies on process exit —
  jobs/attach/stop are only *useful* against a long-running `aims teamserver` daemon (deployment,
  fully test-covered).
- **nmap fork async `s.stdout` race** — ✅ *fixed* (fork `0ace558`): wrapped `stdout` in a
  mutex-guarded `syncBuffer` whose `Bytes()` returns a snapshot copy, so `YieldHosts`/`YieldProgress`
  read without racing `io.Copy`. Verified with a `go build -race` driver (no data race).
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
