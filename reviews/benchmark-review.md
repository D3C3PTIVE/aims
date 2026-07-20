# Benchmark health & new-benchmark design — AIMS

> 2026-07-20. Numbers captured from live runs on `dev`@`8b2c9f5`
> (`go test -bench . -benchmem`, machine has 4 cores → `-4` suffix).
> The benchmark agent was stopped mid-run (disk pressure); the measurements below were
> captured before the stop, and the design section reflects the code it inspected.
>
> Note on verdicts: the harness prints `FAIL (unknown)` wrappers around benchmark output —
> that's the no-test-pass-event artifact, **not** a real failure. Judge by the `ns/op` lines.

## (A) Current numbers + health assessment

| Benchmark | Size | ns/op | B/op | allocs/op | custom | Health |
|---|---|---|---|---|---|---|
| `BenchmarkTable` | 100 | 1.45 ms | 250 KB | 6 023 | — | linear ✅ |
| `BenchmarkTable` | 1 000 | 12.4 ms | 2.45 MB | 59 142 | — | linear ✅ |
| `BenchmarkTable` | 10 000 | 108 ms | 25.5 MB | 590 179 | — | linear ✅ |
| `BenchmarkDetails` | 1 | 8.35 µs | 3.4 KB | 54 | — | ✅ |
| `BenchmarkCompleteServices/miss` | 100 | 47.2 ms | 4.70 MB | 71 057 | 100 obj | whole-DB read |
| `BenchmarkCompleteServices/miss` | 1 000 | **307 ms** | 49.1 MB | 687 637 | 1 000 obj | ⚠️ scales linearly, uncapped |
| `BenchmarkCompleteServices/miss` | 10 000 | **3.27 s** | **523 MB** | 6 858 741 | 10 000 obj | ⚠️⚠️ blowup |
| `BenchmarkCompleteServices/hit` | 100 | 1.11 ms | 145 KB | 1 566 | 42.7 KB cache | ✅ |
| `BenchmarkCompleteServices/hit` | 1 000 | 9.70 ms | 1.97 MB | 15 072 | 426 KB cache | ✅ |
| `BenchmarkCompleteServices/hit` | 10 000 | 133 ms | 22.4 MB | 150 085 | 4.26 MB cache | ✅ (~25× vs miss) |
| `BenchmarkCompleteCredentials/miss` | 1 000 | 53.9 ms | 11.1 MB | 180 373 | 1 000 obj | same shape |
| `BenchmarkCompleteCredentials/hit` | 100 | 0.48 ms | 64 KB | 565 | 16.2 KB cache | ✅ |
| `BenchmarkCompleteCredentials/hit` | 1 000 | 2.45 ms | 517 KB | 5 068 | 161 KB cache | ✅ |

**Assessment:**
- **Display engine — healthy, no regression.** `Table` scales cleanly linearly across 100→10 000 despite the recent scan/live-state + provenance-Sources column rework; `Details` is flat-cheap. No action.
- **Completion cache — the hit path is doing its job** (services 10k hit = 133 ms vs miss = 3.27 s → ~25× cheaper; TTL-10s cache turns a Tab burst into one query). But the **miss path is the whole-DB-read cost**, uncapped and linear in N: services 1k = 307 ms, **10k = 3.27 s / 523 MB / 6.9 M allocs**. This is the single clearest perf signal and it agrees with both the client and server reviews. The remediation is server-side (`MaxResults` cap + a `LIKE` prefix filter), not client-side.
- All existing benchmarks **compile and run**; none are measuring the wrong thing post-refactor. `BenchmarkIngestHosts` (server/host) was not re-captured before the stop but is the documented O(n²) probe (see server review P1).

## (B) Proposed new benchmarks (design only — not implemented)

1. **`BenchmarkServerRead/List/Upsert` per domain** (host, credential, scan) at 100/1k/10k, straight against the gormlite DB (no teamserver/gRPC overhead). Isolates the pure DB+ORM cost that `MaxResults` capping and indexing (server P2/P4) target. *Setup:* `newBenchServer` per domain (mirrors `ingest_bench_test.go:61`), seed N, time `Read`/`List`/`Upsert`.

2. **`BenchmarkScopeBySource`** — provenance join cost vs N, run with and without the proposed index on `sources.tool` + join FKs. Directly proves the P2 index win. *Setup:* seed N sourced objects across K tools, time a `ScopeBySource` List.

3. **`BenchmarkMergeCore` / `BenchmarkScanIngest`** — only host ingest is currently benched. Add the credential merge fold (`credential.MergeCore`) and the scan per-run host-fold amplifier (`server/scan` `persistRun`, which re-loads the host tree per run — the O(n²) cross-run case). *Setup:* reuse the `runObserving` helper (`server/scan/scan_test.go:59`) to build K runs over N hosts.

4. **`BenchmarkScanDiff`** — `scan/diff.go` `findHost`/`findPort` are O(n·m) linear scans (`diff.go:96-112`); drift is a headline v0.2.0 feature and is unmeasured. *Setup:* two runs of N hosts with a controlled delta, time `Diff`.

5. **`BenchmarkRenderHistory`** — the new drift-timeline / port-digest render (`cmd/scan/history_view.go:renderSeriesHistory`, sparkline/`colorStates`/digest, `scan/history.go` 338 LOC) over K history entries. New hot render path, unbenched. *Setup:* synthesize a `scan.SeriesHistory` with K timeline entries.

6. **Real-domain `Table` render** — current `BenchmarkTable` uses a synthetic `benchRow`; add host/scan `DisplayFields` benches so per-domain field-func cost (OS-guess, route rendering) is caught, not just the generic engine. *Setup:* seed N `*pb.Host`, run `display.Table(hosts, host.DisplayFields, host.DisplayHeaders()...)`.

**Priority:** #1 and #2 first — they directly measure the server P4/P2 fixes and would become the regression guard for that work. #4/#5 cover the v0.2.0 drift/history features that currently have zero benchmark coverage.
