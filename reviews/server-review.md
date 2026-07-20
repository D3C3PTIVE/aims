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

### P1 — O(n²) ingest fold `[L]` — highest impact
- `server/host/host.go:202-209` `loadHostsPB` does `db.Preload(s.db, ingestPreloads()).Find(&dbHosts)` — loads the **entire** host table with full child tree (OS, ports, services, scripts, trace…), then ORM→PB-converts all of it.
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

### P4 — `MaxResults` ignored except `==1`; no pagination `[S]`
- `host.go:68` and `scan.go:314` branch `MaxResults == 1` → `First`, else `Find` with **no `.Limit`**. A `MaxResults=50` request loads the whole table. No `.Offset` anywhere.
- **Fix:** `if MaxResults > 0 { db = db.Limit(int(MaxResults)) }`; add offset for paging.
- **Impact:** unbounded reads/completions as the DB grows.

### P5 — Read paths over-preload / bare-load `[S-M]`
- `credential.go:69` `List` / `:215` `loadAll` use `db.PreloadAll` (= `clause.Associations`, every sub-credential) and load the whole table — heavy for a list view.
- `server/c2/agent.go:69` `List` uses the same `Preloads` (nested `Host.Trace.Hops`, `Host.Distance`) as `Read` — a full host-route subtree pulled for every row of a list.
- Inverse inconsistency: `server/network/service.go:47,73` `Read`/`List` **preload nothing** — services come back bare while other domains over-preload.
- **Fix:** split "list" (shallow preload) from "detail read" (deep) preload sets; give network a consistent preload set. Pair with P4 limits.

### P6 — credential `Upsert` blanket `FullSaveAssociations` `[note]`
- `credential.go:139` uses `Session{FullSaveAssociations:true}.Save(match)` — the exact pattern `host.saveMergedHost` (`host.go:243-253`) documents as duplicating children after a PB→ORM roundtrip. Here `match` is loaded ORM-side (`loadAll`) and `MergeCore` operates on ORM directly, so FKs are intact and it's currently safe — but it's a latent trap if credential ever routes through PB. Worth a comment or the same guarded-append treatment. Low priority.

---

## Refactor / cleanup

### R1 — Duplicated CRUD shim across 5 servers `[M]`
- `host/network/credential/c2-agent/c2-channel` each hand-roll the same body: `GetX().ToORM` → `Where` → (`ScopeBySource`) → `First`/`Find` → `ErrRecordNotFound`→nil → `db.ToPBs` → wrap response. Read+List alone is ~20 near-identical lines × 5 domains. `internal/db/db.go` already generalizes the ORM→PB half (`ToPBs`, `:88`).
- **Proposal (viable):** add a generic `queryToPBs[O db.pbConvertible[P], P any](ctx, query *gorm.DB, single bool) ([]*P, error)` capturing the `First`/`Find` + `ErrRecordNotFound`-swallow + `ToPBs` tail. The per-domain wrappers keep only their typed request/response marshalling. Full generic CRUD is blocked by the distinct request/response/filter types per domain, but the query tail is cleanly extractable. Effort M, removes the most-copied block.

### R2 — Stubbed methods inventory `[tracking]`
`codes.Unimplemented` returns: network `Create`/`Upsert`/`Delete` (`service.go:44,94,98`), host `Delete` (`host.go:452`), host Users all 5 (`user.go:40-58`), credential Logins all 5 (`login.go:40-57`), c2 Agents `Upsert`/`Delete` (`agent.go:88,93`), c2 Channels `Upsert`/`Delete` (`channel.go:86,90`). Users and Logins services are entirely stubbed.

### R3 — c2 Create swallows conversion errors `[S]` (real bug)
- `server/c2/agent.go:29` and `server/c2/channel.go:29`: `horm, _ := h.ToORM(ctx)` discards the error, then bulk-inserts possibly-zero ORM values. Every other server checks `ToORM` err. Fix: propagate the error.

### R4 — Inconsistent input validation & error mapping `[S]`
- `host.Create`/`Upsert` (`host.go:99,132`) return `status.Error(codes.InvalidArgument, …)` on empty input; network/credential/c2 Create do no such validation and return raw gorm errors (not gRPC status). `ErrRecordNotFound`→nil is handled in the five Read paths but not uniformly documented. Standardize on gRPC status codes across servers.

### R5 — c2 type-name asymmetry + login/user init `[S, cosmetic]`
- `server/c2/agent.go:16` `type server` vs `server/c2/channel.go:16` `type channelServer` (the documented wart; rename `server`→`agentServer`).
- `server/credential/login.go:37` `NewLoginServer` does **not** initialize the embedded `*UnimplementedLoginsServer` (every other `New` does) — nil embedded pointer; harmless today because all 5 methods are defined, but a future proto method → nil-panic.
- `server/host/user.go` uses value receivers `(userServer)` while all peers use pointer receivers — minor stylistic drift.

### R6 — Dead parameter `[S]`
- `server/c2/agent.go:100` `Preloads(database, filters *c2.AgentFilters)` never reads `filters`; both callers pass `&c2.AgentFilters{}`. Drop the param or use it.

---

### Key file:line references
- O(n²) reload: `server/host/host.go:202-209`, `:160`, `:103`; amplified at `server/scan/scan.go:130`.
- No-index scope join: `provenance/source.go:96-110`.
- Non-atomic/unserialized ingest: `server/host/host.go:159-192`, `:233`, `:259`; `server/credential/credential.go:122-169`.
- MaxResults: `server/host/host.go:68`, `server/scan/scan.go:314`.
- Error swallowed: `server/c2/agent.go:29`, `server/c2/channel.go:29`.
- Generic ORM→PB already present: `internal/db/db.go:88` (`ToPBs`), reusable for R1.
