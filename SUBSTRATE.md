# Scan Domain — Scanner-Plug Substrate (SCAN.md Part C)

> **Working plan — collapsed 2026-07-21.** All six phases landed (v0.1.0 → v0.3.0); the
> phase-by-phase build instructions have served their purpose and are gone. What remains here is
> the record of *what shipped* plus the one open design tension and the critical files. The
> permanent docs carry the substance now: [`SCAN.md`](./SCAN.md) (scan model & substrate),
> [`STATE.md`](./STATE.md) (maturity), [`CLAUDE.md`](./CLAUDE.md) (architecture).

## What the substrate is

Turning AIMS from an nmap-XML parking lot into a **multi-tool scan orchestrator over a shared
object DB** — the literal payoff of the "many tools contribute to and consume the same objects"
thesis. Everything builds on one keystone: the universal `Run.AddResult` /`Run.AddHosts` feeder
fold (`scan/scan.go`, `scan/fold.go`) delegating to the shared `host.SameHost`/`host.MergeHost`
identity+merge (`host/merge.go`).

## What shipped (all done)

| Phase | Delivered | Landmark |
|-------|-----------|----------|
| 1 — Ingestor interface + generic JSON→NSE walker | `scan/ingest/` (`Ingestor` + registry, nmap/zgrab adapters, `jsonToScript` walker that maps arbitrary JSON into the recursive `Script{Elements,Tables}` tree); `scan import --scanner` | — |
| 2 — Hosts-as-targets bridge + `Scanner` interface | `scan/targets.go` (`TargetsFromHosts`/`TargetSpecs`); `scan/drive/scanner.go` (`Scanner` + `Nmap` adapter) | — |
| 3 — Run-to-run diff | `scan/diff.go` (`DiffRuns`/`RunDiff`, reuses `host.SameHost`/`SamePort`); `aims scan diff <a> <b>` | — |
| 4 — Streaming scans + job model + live view | server-streaming `Run` RPC; in-server job registry; `scan run`/`jobs`/`attach`/`stop`; live `watch scan show`; nmap-fork async path fixed | — |
| 5 — Run lifecycle: cleanup / tombstone / history | `scan/lifecycle.go` (series/head/supersede); `Cleanup` RPC; `scan cleanup`/`history`/`list --all` | `4af9c31` |
| 6 — `scan resume` for interrupted runs | AIMS-owned per-target completion tracking + interrupt-aware persist + reforge-and-stream `scan resume <id>`; native `nmap --resume` left as a deferred port-granular refinement | `7a66eb2`, `05c199a` |

Also shipped since: the **nuclei** driver + ingestor + templates completer (`scan run nuclei`,
server-side, findings fold via the same `jsonToScript` path).

## Open design tension (the one thing still deliberately unsettled)

**Cross-run unification vs. run diff.** Ingest MERGES a host observed by N runs into ONE shared
row (the `sharedRunCount` insight), so two runs that saw the same physical host both point at the
*merged* current state — per-run host/port snapshots are not preserved. Consequences:
- Whole-host drift (new/gone hosts) and **disjoint-host** run diff work correctly, including for
  *stored* runs (`server/scan.Read` now preloads the host subtree scoped through `run_hosts` —
  fixed in `24b6bfd`; `TestReadScopesHostsPerRun`).
- **Same-host drift between two stored runs is not visible** — both runs resolve to the merged
  row. `scan.DiffRuns` itself is correct and immediately useful on in-memory / pre-fold Runs and
  on disjoint-host runs; only the *stored shared-host* case is limited.
- To get true stored same-host drift, either snapshot per-run observations (a heavier model) or
  diff in-memory Runs before the fold. **Decide the model deliberately** — this is the design call
  the substrate leaves open, not a bug.

Related caveat: `SamePort` keys on (proto, number); everything wired spells the protocol `"tcp"`,
so a tool that spelled it differently would falsely mismatch — no such tool is wired.

## Cross-cutting invariants (keep holding)

- **Preserve the four Part-A primitives** (evidence/confidence, summarize-the-boring, run
  provenance, schemaless NSE) — do not flatten them for convenience.
- **One identity everywhere:** all matching reuses `host.SameHost`/`host.SamePort`/`host.MergeHost`
  and `Run.AddResult`/`AddHosts`; never a parallel comparator.
- **`Result` stays a feeder** (not a stored row) per its proto contract; the persistent tree is `Run`.
- **Completions/commands reach data ONLY through the teamclient RPC**, never the DB directly.

## Critical files

- `scan/scan.go` (`AddResult`), `scan/fold.go` (`AddHosts`/`foldHost`), `host/merge.go`
  (`SameHost`/`SamePort`/`MergeHost`) — the fold/identity primitives everything reuses.
- `scan/ingest/` (`Ingestor` + registry + `jsonToScript`), `scan/nmap/nmap.go` (`FromXML`) — ingest.
- `scan/targets.go`, `scan/drive/scanner.go` — the hosts-as-targets bridge + driver interface.
- `scan/diff.go`, `scan/lifecycle.go` — diff + run-series lifecycle.
- `scan/pb/rpc/scans.proto`, `server/scan/`, `client/client.go`, `cmd/scan/` — the RPC/CLI surface.
