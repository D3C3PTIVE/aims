# AIMS — Refactor / Perf / Cleanup Investigation

> Consolidated from four parallel investigation swipes (client, server, domain-strings,
> benchmarks) run 2026-07-20 on `dev`@`8b2c9f5` (== `main` == v0.2.0). Investigation only —
> no code changed. Grouped into tiers; each tier closes with a context-doc update pass.

## Executive summary — the five cross-cutting themes

1. **The whole-DB-read-per-operation is THE performance story**, and it shows up on both sides:
   - Server: host **ingest is O(n²)** — `loadHostsPB` reloads the entire host table + child tree on *every* `ingest()`/`Create()`, and `scan.Create` does it once *per run*.
   - Client: every cold-Tab completion triggers a full-table server `Read` (no prefix filter, no cap). Benchmarks quantify it: **services completion N=10000 cache-miss = 3.27 s / 523 MB / 6.9 M allocs**.
   Same root cause, two symptoms; fixing the server read/scoping fixes both.
2. **`MaxResults` is honored only for `==1`** (`server/host/host.go:68`, `server/scan/scan.go:314`) — every other value silently loads the whole table. No `.Limit`/`.Offset` anywhere in `server/`. This is the cheapest high-impact fix and directly caps the completion-miss blowup above.
3. **Zero DB indexes** on any identity/lookup/scope column (tree-wide grep for index tags = nothing). Prerequisite for making any narrowed query actually fast.
4. **Massive shape-duplication** — 5 domain servers hand-roll the same PB↔ORM CRUD shim; 9 domain completers hand-roll the same connect/read/format shell (and, worse, skip `Guard` panic protection). Both are cleanly extractable behind helpers that already exist in embryo (`db.ToPBs`, `completers.cachedCompleter`).
5. **Domain string literals**: the two domains that have protobuf enums (`provenance.SourceType`, `credential.PrivateType`/`PublicType`) already use them cleanly — no enum-merge work needed. The repeated *state/protocol/scanner* literals map onto proto fields that are deliberately `string` (nmap-XML contract), so the fix is **Go string consts, not enums**.

---

## Tiered action plan

### Tier 1 — High impact, low/medium effort (do first)
- **T1.1 Cap reads with `MaxResults`** `[S]` — `if n := req.GetMaxResults(); n > 0 { db = db.Limit(int(n)) }` in every server List/Read; add `.Offset` for paging. Kills the completion-miss blowup. (`server/host/host.go:68`, `server/scan/scan.go:314`, + peers.)
- **T1.2 Fix O(n²) ingest** `[S→M]` — index existing hosts by identity key once per batch (`map[MAC]`/`map[addr]*Host`) instead of the linear `indexSameHost` scan; narrow `loadHostsPB` to the incoming batch's addresses/MACs; in `scan.Create`, load the candidate host set once and share across runs. (`server/host/host.go:160,202-209,438,447`; `server/scan/scan.go:125,130`.)
- **T1.3 Add DB indexes** `[S]` — index `sources.tool` + source-join FKs (`*_sources.*_id`), `runs.scanner`, `runs.superseded_by`, `addresses.addr`, and the host/credential identity columns. Via proto `(gorm.field)` / `@gotags`. Enables T1.2's narrowed query. (`provenance/source.go:96-110`, `db/schema.go`.)
- **T1.4 Guard the 9 domain completers** `[S]` — they run `display.Completions`/styling with no `recover`; a format panic silently hangs `_carapace`. Fold onto a shared helper that wraps `Guard`. (see T2.2.)

### Tier 2 — Structural refactors (medium effort, big readability/robustness win)
- **T2.1 Generic server query tail** `[M]` — extract `queryToPBs[O,P](ctx, query, single)` capturing `First`/`Find` + `ErrRecordNotFound`→nil + `db.ToPBs`; rewrite the ~20-line×5 Read/List bodies on top. (`internal/db/db.go:88` already has the ORM→PB half.)
- **T2.2 Generic completer helper** `[M]` — export `completers.CachedList[T](con, name, label, read, render)` bundling cache+Guard+ConnectComplete (today `cachedCompleter` is unexported, only `values.go` uses it); collapse the 9 domain completers (~15→~3 lines each, ~120 lines removed) and get T1.4 for free.
- **T2.3 Domain string consts** `[S-M]` — new const blocks (highest-count first):
  - port state `"open"/"closed"/"filtered"/…` (~25 occ across host/network/scan + 3 cmd pkgs) → `host.PortOpen` etc.
  - host status `"up"/"down"` (~10 occ) → same block.
  - scanner keys `"nmap"/"masscan"/"zgrab2"` (~15 occ, **correctness risk** — cross-package join key) → shared `scan/drive`+`scan/ingest` const.
  - lower value if touching: `"success"` exit, `"ipv4"/"ipv6"/"mac"`, `"tcp"/"udp"`.
  - Keep string-typed (nmap XML contract); do **not** invent enums.
- **T2.4 Ingest atomicity + uniqueness** `[M]` — wrap a whole `ingest` batch in one `s.db.Transaction`; add a unique index/`OnConflict` on host & credential natural keys so concurrent Create/Upsert can't double-insert. (`server/host/host.go:159-192,233,259`; `server/credential/credential.go:122-169`.)

### Tier 3 — Smaller correctness/cleanup (opportunistic)
- **T3.1** c2 `Create` swallows `ToORM` error (real bug) — `server/c2/agent.go:29`, `channel.go:29`.
- **T3.2** `client/client.go:277` `isOffline` tests `ts != nil` where it means `tc != nil` (logic bug).
- **T3.3** Secret/Username completers: overlap the independent `Creds.List` ∥ agent-host resolution with an `errgroup` (`cmd/completers/values.go:468,624`).
- **T3.4** Split "list" (shallow preload) vs "detail read" (deep preload); give network a consistent preload set (`credential.go:69,215`, `server/c2/agent.go:69`, `server/network/service.go:47,73`).
- **T3.5** c2 `type server`→`agentServer` rename; `NewLoginServer` missing `UnimplementedLoginsServer` init; `userServer` value-vs-pointer receiver; dead `filters` param at `c2/agent.go:100`; host `exportCommand` duplicate Read (`cmd/hosts/hosts.go:215-261`); scan completer "filter outside cache" tail dup (`cmd/scan/commands.go:117,154`).
- **T3.6** host completers pass `nil` Filters → thin description column (`cmd/hosts/hosts.go:165,194`).

### Deferred / out-of-scope-for-refactor (design changes)
- Server-side **prefix filter** (`LIKE`) on completion Reads — the real fix for cold-Tab latency; needs a proto/RPC change. Client-side concurrency is second-order until this exists.
- Server-side **agent→host join RPC** to collapse `agentctx.CurrentHost`'s forced 2-RPC serial resolve.
- Finish stubbed services: network Create/Upsert/Delete, host Delete, host Users (all 5), credential Logins (all 5), c2 Upsert/Delete.

---

## Benchmark health (measured this run)

**All existing benchmarks compile and run; numbers are healthy where expected, and confirm the perf theses.**
(The harness prints "FAIL (unknown)" wrappers — that's the no-test-pass-event artifact, not a real failure; judge by ns/op.)

| Benchmark | Size | ns/op | B/op | allocs/op | Read |
|---|---|---|---|---|---|
| Table | 100 / 1k / 10k | 1.45 ms / 12.4 ms / 108 ms | 0.25 / 2.45 / 25.5 MB | 6.0k / 59k / 590k | **linear — healthy** |
| Details | 1 | 8.3 µs | 3.4 KB | 54 | healthy |
| CompleteServices miss | 100 / 1k / 10k | 47 ms / **307 ms** / **3.27 s** | 4.7 / 49 / **523 MB** | 71k / 688k / 6.9M | **whole-DB read, no cap → blowup** |
| CompleteServices hit | 100 / 1k / 10k | 1.1 ms / 9.7 ms / 133 ms | 0.14 / 1.97 / 22.4 MB | 1.6k / 15k / 150k | cache saves ~25× |
| CompleteCredentials miss | 1k | 53.9 ms | 11.1 MB | 180k | same shape |
| CompleteCredentials hit | 100 / 1k | 0.48 ms / 2.45 ms | 64 / 517 KB | 565 / 5068 | healthy |

**Headline:** the cache-**hit** path is cheap and scales fine; the cache-**miss** path is the whole-DB-read cost (services 10k miss = **3.27 s**). T1.1 (`MaxResults` cap) + a server-side prefix filter collapse this directly.

### Proposed new benchmarks
1. **Server CRUD over N rows** — `BenchmarkRead/List/Upsert` per domain (host/credential/scan) at 100/1k/10k; the direct measure T1.1/T1.3 target (no completion/teamserver overhead).
2. **`ScopeBySource` query cost vs N** — provenance join with/without the T1.3 index, to prove the index win.
3. **Credential & scan merge/dedup fold** — only host ingest is benched; add `BenchmarkMergeCore` and `BenchmarkScanIngest` (the per-run host-fold amplifier).
4. **Scan diff engine** — `scan/diff.go` `findHost`/`findPort` are O(n·m) linear scans; bench `Diff` on two N-host runs (drift is a headline v0.2.0 feature, currently unmeasured).
5. **Drift-timeline / port-digest render** — `cmd/scan/history_view.go` (`renderSeriesHistory`, sparkline/digest) over K history entries — new hot render path, unbenched.
6. **Real domain Table render** — current `BenchmarkTable` uses a synthetic row; add host/scan `DisplayFields` benches to catch per-domain field-func cost.

---

## Per-area detail
See the four sub-reports for full file:line anchors. Key entry points:
- **Server:** O(n²) `server/host/host.go:202`; `MaxResults` `:68`; scope-join no-index `provenance/source.go:96`; CRUD dup extractable via `internal/db/db.go:88`.
- **Client:** completer dup+Guard-gap across the 9 `CompleteBy*`; serial RPC chains `cmd/completers/values.go:468,624`; `agentctx.go:95`; connection reuse is fine (`sync.Once`), don't optimize there.
- **Domain strings:** enum inventory + literal table — port-state cluster is #1 by count, scanner keys #1 by correctness risk; enums already used cleanly.
