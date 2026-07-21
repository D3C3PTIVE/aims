# Server-side investigation — AIMS

> Agent report, 2026-07-20. Scope: `server/{host,network,credential,scan,c2,transport}`,
> `server/server.go`, `internal/db/db.go`, `host/merge.go`, `credential/merge.go`,
> `provenance/source.go`, and the scan ingest path. Read-only; no files changed.

## Top findings (highest impact first)

1. **O(n²) host ingest — whole-table reload per call** (`server/host/host.go:202`, called from `:160`, `:103`, and per-run from `server/scan/scan.go:130`). Confirmed.
2. **Zero DB indexes anywhere** on identity/lookup/scope columns (whole-tree grep for `gorm:"…index…"` returns nothing). Hits `SameHost` narrowing, `ScopeBySource`, scan `scanner`/`superseded_by`, and every `.Where(orm)` identity read.
3. **Ingest read-modify-write is not serialized and has no unique constraint** → concurrent Create/Upsert race to insert duplicate hosts/credentials (`host.go:159-192`, `credential.go:122-169`). Batch `ingest` also isn't a single transaction.
4. **`MaxResults` is only honored for `==1`** (`host.go:68`, `scan.go:314`) — any other value silently loads the entire table; no `.Limit`/`.Offset` anywhere in `server/`.
5. **Five domain servers duplicate the same PB↔ORM Read/List/Create/Upsert/Delete shim** — extractable behind the already-generic `db.ToPBs`.

---

## Perf / concurrency (DB)

### P1 — O(n²) ingest fold `[L]` — highest impact — ✅ DONE (2026-07-21, part b; a/c noted)
- Fixed: `loadHostsPB` (whole-table reload) is replaced by `loadCandidateHostsPB(ctx, in)`
  (`server/host/host.go`), which loads only the stored hosts sharing a MAC or address with the
  incoming batch — resolved via a `host_addresses`-join query for addresses + a `LOWER(mac) IN`
  query for MACs, then a single narrowed `id IN (…)` preload. Both `ingest()` and `Create()` call
  it. The returned set is a safe superset (SameHost still does the exact matching), so semantics are
  unchanged — verified by the existing host server tests + the `BenchmarkIngestHosts` guard.
- Measured (pure-Go sqlite, `-benchtime=1x`): the O(n²) `incremental-1by1` path collapses — N=500:
  **26.03 s → 1.34 s (19.4×)**, allocs **54.0 M → 520 k (104×)**, bytes **3.57 GB → 68 MB (52×)**;
  N=200: 4.77 s → 0.52 s; N=50: 521 ms → 79 ms. `fresh-batch`/`reingest-dup` unchanged, as expected.
- Part (b) — narrow-the-reload — was the whole O(n²) win, so (a) the map-index and (c) the
  per-`persistRun` shared candidate set were left undone: `existing` is now tiny per call, so the
  linear `indexSameHost` is no longer a bottleneck (and a correct map-index is fiddly given
  SameHost's MAC/address asymmetry), and each `persistRun` now narrow-loads only its own run's
  candidates rather than the world. (a)/(c) would need the P2 `addresses.addr`/`mac` indexes to
  matter and touch the concurrently-churning scan path — deferred.
- Original problem (for reference): `loadHostsPB` did `db.Preload(s.db, ingestPreloads()).Find(&dbHosts)` — loaded the **entire** host table with full child tree (OS, ports, services, scripts, trace…), then ORM→PB-converted all of it.
- It runs at the top of **every** `ingest()` (`host.go:160`) and **every** `Create()` (`host.go:103`). Matching is then a linear `indexSameHost`/`findSameHost` scan (`host.go:438`, `:447`) — O(existing) per incoming host.
- The cross-call amplifier: `server/scan/scan.go:125` `persistRun` calls `hosts.IngestHosts(ctx, tx, …)` which does `New(gdb).ingest` → a **fresh whole-table reload per run**. `scan.Create` (`scan.go:76`) loops runs, so importing K runs reloads the host tree K times. The 1-by-1 CLI/scan-import path is the genuinely O(n²) case the `BenchmarkIngestHosts` `incremental-1by1` mode (`ingest_bench_test.go:133`) is built to expose.
- **Fix (S→M):** (a) index existing hosts by identity key once — build `map[MAC]` / `map[addr]*Host` before the loop, replacing the linear `indexSameHost` scan → O(n) matching. (b) Narrow the reload to the batch: `WHERE` on the addresses/MACs present in the incoming hosts instead of loading the world. (c) For `scan.Create`/`Upsert` looping multiple runs, load the candidate host set once and share it across the batch rather than reloading per `persistRun`.
- **Impact:** the documented hot path; dominates import/scan latency as the DB grows.

### P2 — No indexes on lookup/identity/scope columns `[S]`
- Confirmed zero `gorm` index tags tree-wide; `db/schema.go` `AutoMigrate` creates only PK indexes.
- Uncovered lookups: `provenance/source.go:101-109` `WhereContributedBy` joins on `sources.tool` and the m2m FK (`host_sources.host_id`, …) — none indexed; `scan.go:300` `Where("scanner = ?")` and `:306-309` `superseded_by`; credential/network/c2 `Read` do `.Where(orm)` on identity columns (public/private/realm, service fields) — none indexed.
- **Fix:** add index tags (via the proto `(gorm.field)` options / `@gotags`) on `sources.tool`, the source join FKs, `runs.scanner`, `runs.superseded_by`, and `addresses.addr`. Prerequisite for the P1 narrowed-query fix to actually be fast.
- **Impact:** every scoped read and the future narrowed ingest query.

### P3 — Ingest concurrency + missing transaction/uniqueness `[M]`
- `host.go:159-192` `ingest`: `loadHostsPB` (read) → in-memory match → `insertHost`/`saveMergedHost` (write). The load is outside any transaction and there is **no DB unique constraint** on host identity, so two concurrent Upserts/Creates both load, both miss, both insert → duplicate host rows that the in-memory dedup can't catch. Same shape in `credential.go:122` `Upsert` and `Create`.
- The batch itself isn't atomic: `insertHost` (`host.go:233`) is a bare `Create`; `saveMergedHost` (`host.go:259`) opens its **own** per-host transaction. A batch that fails on host N leaves hosts 1..N-1 committed.
- **Fix:** wrap a whole `ingest` batch in one `s.db.Transaction`; add a unique index on the host natural key (or `OnConflict` clause) so the DB is the arbiter under concurrency. `scan.persistRun` already models the single-tx pattern (`scan.go:128`).
- **Impact:** correctness under concurrent operators/tools — the core "many tools, one store" use case.

### P4 — `MaxResults` ignored except `==1`; no pagination `[S]` — ✅ DONE (2026-07-21)
- Fixed: both `server/host/host.go` `Read` and `server/scan/scan.go` `Read` now cap with `.Limit(MaxResults)` for any `MaxResults>1` (==1 keeps the `First` fast-path, <=0 loads all). Regression test `TestReadMaxResultsCaps` (`server/host/host_test.go`) locks the 2/1/all behavior. credential/network/c2 servers don't expose a `MaxResults` filter, so nothing to cap there.
- Not done: `.Offset` paging (no `Offset` field on the filters yet — a proto add), and the server-side `LIKE` prefix filter for completions (the real completion-latency lever; also a proto/regen change).

### P5 — Read paths over-preload / bare-load `[S-M]` — ◑ DONE (2026-07-21, c2 + network; credential re-scoped)
- Done — c2 agent: `List` now uses a new shallow `listPreloads` (`server/c2/agent.go`, immediate
  associations only) instead of the deep `Preloads`, so the nested `Host.Trace.Hops`/`Host.Distance`
  route subtree is no longer pulled for every list row; detail `Read` keeps the deep set.
- Done — network: `server/network/service.go` `Read`/`List` now `db.PreloadAll` so services carry
  their provenance `Sources` (their only association) instead of coming back bare — consistent with
  host/credential.
- Re-scoped — credential: inspection showed `CoreORM`'s associations are exactly Public/Private/
  Realm/Sources, which is precisely what the credential **list** renders (Origin ← primarySource ←
  Sources); there is no heavier sub-tree to drop, so `List`'s `PreloadAll` is correct as-is —
  trimming it would blank the Origin column. Its real gap is the missing list `LIMIT` (P4/P2), not
  preload depth. Left unchanged deliberately.
- Original text: split "list" (shallow) from "detail read" (deep) preload sets; give network a consistent preload set. Pair with P4 limits.

### P6 — credential `Upsert` blanket `FullSaveAssociations` `[note]`
- `credential.go:139` uses `Session{FullSaveAssociations:true}.Save(match)` — the exact pattern `host.saveMergedHost` (`host.go:243-253`) documents as duplicating children after a PB→ORM roundtrip. Here `match` is loaded ORM-side (`loadAll`) and `MergeCore` operates on ORM directly, so FKs are intact and it's currently safe — but it's a latent trap if credential ever routes through PB. Worth a comment or the same guarded-append treatment. Low priority.

---

## Refactor / cleanup

### R1 — Duplicated CRUD shim across 5 servers `[M]` — ◑ DONE (2026-07-21, stable servers; scan deferred)
- Done exactly as proposed: added `db.QueryToPBs[O pbConvertible[P], P any](ctx, query, single)`
  (`internal/db/db.go`) capturing the `First`/`Find` + `ErrRecordNotFound`-swallow + `ToPBs` tail.
  Folded credential `Read`/`List`, network `Read`/`List`, c2 agent `Read`/`List`, and c2 channel
  `Read`/`List` onto it — each Read/List is now ~6 lines and the per-domain code keeps only its
  typed request/response marshalling + query build/scope/preload. Removed the now-unused
  `errors`/`gorm.ErrRecordNotFound` imports from the four servers.
- Deferred: host `Read` stays hand-rolled (its P4 `MaxResults` First/Limit/Find switch doesn't fit
  the single-bool shape), and the scan server was left untouched — it is under concurrent in-flight
  work (resume feature) and editing it now would collide. Fold scan `Read`/`List` when that settles.
- Original: each server hand-rolled the same `GetX().ToORM` → `Where` → (`ScopeBySource`) → `First`/`Find` → `ErrRecordNotFound`→nil → `db.ToPBs` → wrap body (~20 near-identical lines × 5 domains).

### R2 — Stubbed methods inventory `[tracking]`
`codes.Unimplemented` returns: network `Create`/`Upsert`/`Delete` (`service.go:44,94,98`), host `Delete` (`host.go:452`), host Users all 5 (`user.go:40-58`), credential Logins all 5 (`login.go:40-57`), c2 Agents `Upsert`/`Delete` (`agent.go:88,93`), c2 Channels `Upsert`/`Delete` (`channel.go:86,90`). Users and Logins services are entirely stubbed.

### R3 — c2 Create swallows conversion errors `[S]` (real bug) — ✅ DONE (2026-07-21)
- Fixed: `server/c2/agent.go` `Create` and `server/c2/channel.go` `Create` now propagate the `ToORM` error instead of discarding it.

### R4 — Inconsistent input validation & error mapping `[S]` — ◑ PARTIAL (2026-07-21)
- Done: empty-input `status.Error(codes.InvalidArgument, …)` guards added to the implemented mutating paths — credential `Create`/`Upsert` and c2 agent/channel `Create` — matching host. (network `Create`/`Upsert` are still `Unimplemented` stubs, nothing to guard.)
- Remaining: uniform gorm-error → gRPC-status wrapping on the read/write paths that still return raw gorm errors, and documenting the `ErrRecordNotFound`→nil convention.

### R5 — c2 type-name asymmetry + login/user init `[S, cosmetic]` — ✅ DONE (2026-07-21)
- Fixed: `server/c2/agent.go` `type server`→`agentServer`; `server/credential/login.go` `NewLoginServer` now initializes the embedded `*UnimplementedLoginsServer`; `server/host/user.go` receivers switched value→pointer to match peers.

### R6 — Dead parameter `[S]` — ✅ DONE (2026-07-21)
- Fixed: dropped the unused `filters *c2.AgentFilters` param from `server/c2/agent.go` `Preloads`; both callers updated.

---

### Key file:line references
- O(n²) reload: `server/host/host.go:202-209`, `:160`, `:103`; amplified at `server/scan/scan.go:130`.
- No-index scope join: `provenance/source.go:96-110`.
- Non-atomic/unserialized ingest: `server/host/host.go:159-192`, `:233`, `:259`; `server/credential/credential.go:122-169`.
- MaxResults: `server/host/host.go:68`, `server/scan/scan.go:314`.
- Error swallowed: `server/c2/agent.go:29`, `server/c2/channel.go:29`.
- Generic ORM→PB already present: `internal/db/db.go:88` (`ToPBs`), reusable for R1.
