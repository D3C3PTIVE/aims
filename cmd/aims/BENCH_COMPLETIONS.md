# Completion-latency benchmark — findings

`BenchmarkCompleteHosts` (in `cmd/aims/complete_bench_test.go`) is the repo's first
completion-latency benchmark. It reproduces the body of the `hosts show <TAB>` completion
callback (`cmd/hosts/hosts.go:CompleteByID`) over the in-memory bufconn stack
(`newInMemoryStack`, in `roundtrip_test.go`) — the real
`client → teamclient → teamserver → GORM` path — and measures the per-keystroke round-trip.

Each Tab press runs three steps:

```
client.ConnectComplete()   // pre-connect hooks + Teamclient.Connect() + Init()
client.Hosts.Read(...)     // gRPC Read: whole host set, full child-tree preload
display.Completions(...)   // format every host into (candidate, description) pairs
```

The Read pulls the **whole** host set with the full preload tree (ports + service + state +
scripts + trace) — there is no server-side prefix match and no result cap (see
`server/host/host.go:Read`; only `MaxResults == 1` is special-cased, and `Where(host)` is an exact
struct match, never a prefix `LIKE`). So latency and wire size grow with total DB size on **every**
keystroke. The sweep is `N ∈ {100, 1_000, 10_000}` to make that visible.

Three modes:

- **warm** — connect once before the timed loop (persistent-connection console / a completion
  daemon). Times `Read + format` only.
- **cold** — call `ConnectComplete()` *inside* the timed loop before each query (exec-once CLI,
  where every Tab is a fresh process that reconnects and re-runs `Init`).
- **hit** (`BenchmarkCompleteHostsCacheHit`) — drive the **real wired completion**
  (`cmdhosts.CompleteByHostnameOrIP`, wrapped in `cmd.CacheCompletion`) through carapace's `Invoke`,
  warm the on-disk cache once, then time only cache hits. Models every Tab after the first within
  `CompletionCacheTTL`: no connect, no gRPC, no format — just load + deserialize the cached candidate
  set from disk. `XDG_CACHE_HOME` is redirected to a temp dir so each `N` is isolated.

## Measured numbers

`GOWORK=off go test -run xxx -bench=BenchmarkCompleteHosts ./cmd/aims/` — run below at
`-benchtime=10x` on an AMD Ryzen AI 9 HX 370 (pure-Go wasm sqlite, in-memory DB):

```
BenchmarkCompleteHosts/N=100/warm-4        10    36332097 ns/op    100 candidates/op      97490 wirebytes/op     3992893 B/op     62925 allocs/op
BenchmarkCompleteHosts/N=100/cold-4        10    32521010 ns/op    100 candidates/op      95532 wirebytes/op     3995192 B/op     62930 allocs/op
BenchmarkCompleteHosts/N=1000/warm-4       10   275441627 ns/op   1000 candidates/op     968398 wirebytes/op    40981640 B/op    610012 allocs/op
BenchmarkCompleteHosts/N=1000/cold-4       10   358954781 ns/op   1000 candidates/op     970768 wirebytes/op    41053626 B/op    610032 allocs/op
BenchmarkCompleteHosts/N=10000/warm-4      10  2446190226 ns/op  10000 candidates/op    9696998 wirebytes/op   427854437 B/op   6086196 allocs/op
BenchmarkCompleteHosts/N=10000/cold-4      10  2242231603 ns/op  10000 candidates/op    9701832 wirebytes/op   427482850 B/op   6087107 allocs/op
```

(An earlier `-benchtime=5x` run agreed: warm 41.6 / 186.7 / 2431 ms, cold 25.0 / 283.4 / 2476 ms.)

## Reading

### Cold vs warm delta — the headline

The cold/warm delta is **within run-to-run noise and its sign flips with N**, so it is effectively
zero:

| N      | warm     | cold     | cold − warm | ratio |
|--------|----------|----------|-------------|-------|
| 100    | 36.3 ms  | 32.5 ms  | −3.8 ms     | 0.90× |
| 1 000  | 275 ms   | 359 ms   | +84 ms      | 1.30× |
| 10 000 | 2446 ms  | 2242 ms  | −204 ms     | 0.92× |

The decisive evidence that connect is not a real cost here is **allocs/op**: warm and cold are
identical to within a handful of allocations (62 925 vs 62 930; 610 012 vs 610 032; 6 086 196 vs
6 087 107) — a **< 0.02 %** difference. `ConnectComplete()` in the loop adds essentially nothing:
`Teamclient.Connect()` is guarded by a `sync.Once`, so after the first call it does no fresh dial,
and `Init()` merely re-assigns the gRPC stub structs. The ns/op differences are the variance of the
whole-DB GORM read, not connect cost.

### What dominates, and how it scales with N

The **query + format (the whole-DB fetch) dominates entirely**, and it scales linearly with the DB
size:

- **wire bytes**: 97 KB → 968 KB → 9.70 MB — exactly ×10 per ×10 hosts.
- **allocs/op**: 62.9 k → 610 k → 6.09 M — exactly ×10 per ×10 hosts.
- **candidates/op**: 100 → 1 000 → 10 000 — the whole DB, uncapped.
- **ns/op (warm)**: 36 ms → 275 ms → 2446 ms — ~7.6× then ~8.9× per ×10 (roughly linear, slightly
  super-linear from GORM preload assembly + proto marshalling of the growing tree).

So a single Tab already costs ~275 ms at 1 000 hosts and ~2.4 s at 10 000 hosts — and pays it on
*every* keystroke, because nothing is cached and the full set is re-fetched and re-marshalled each
time.

### Hypothesis: CONFIRMED or REFUTED?

Prior hypothesis: *connect + Init dominates; Read + format is noise.*

For what bufconn can measure, this is **REFUTED**: connect + Init is the noise (identical allocs,
zero measurable delta) and Read + format is the whole cost. **But** — see the caveat below — the
benchmark cannot measure the real-world connect cost, so the hypothesis is not refuted for the felt
CLI latency; bufconn simply shows that the *portion of connect it does exercise* (pre-connect hooks
+ `Init`) is free.

## Warm cache hit — the payoff of `CacheCompletion`

The host/service/credential completions are now wrapped in carapace's on-disk `Action.Cache` (via
`cmd.CacheCompletion`, TTL 10 s, keyed by teamserver scope + name + a mutation epoch). A cache **hit**
skips connect + Read + format entirely and just deserialises the stored candidate set. Measured in
the same consolidated `-benchtime=10x` run as the queries above:

```
BenchmarkCompleteHosts/N=100/warm-4              10    20472213 ns/op      100 candidates/op       97490 wirebytes/op    4155815 B/op    64537 allocs/op
BenchmarkCompleteHosts/N=100/cold-4              10    33837088 ns/op      100 candidates/op       97490 wirebytes/op    4154669 B/op    64552 allocs/op
BenchmarkCompleteHostsCacheHit/N=100/hit-4       10      189655 ns/op      100 candidates/op       10485 cachebytes/op     53896 B/op      465 allocs/op
BenchmarkCompleteHosts/N=1000/warm-4             10   363940572 ns/op     1000 candidates/op      968828 wirebytes/op   42802220 B/op   625200 allocs/op
BenchmarkCompleteHosts/N=1000/cold-4             10   226580348 ns/op     1000 candidates/op      968478 wirebytes/op   42831764 B/op   625189 allocs/op
BenchmarkCompleteHostsCacheHit/N=1000/hit-4      10     2762886 ns/op     1000 candidates/op      105085 cachebytes/op    411912 B/op     4068 allocs/op
BenchmarkCompleteHosts/N=10000/warm-4            10  2856204201 ns/op    10000 candidates/op     9693958 wirebytes/op  450858128 B/op  6237892 allocs/op
BenchmarkCompleteHosts/N=10000/cold-4            10  2404924896 ns/op    10000 candidates/op     9700530 wirebytes/op  450517580 B/op  6237834 allocs/op
BenchmarkCompleteHostsCacheHit/N=10000/hit-4     10    23743320 ns/op    10000 candidates/op     1060085 cachebytes/op   5977161 B/op    40078 allocs/op
```

| N      | warm query | cache hit | speed-up | allocs warm → hit |
|--------|-----------:|----------:|---------:|-------------------|
| 100    | 20.5 ms    | 0.19 ms   | ~108×    | 64 537 → 465      |
| 1 000  | 364 ms     | 2.76 ms   | ~132×    | 625 200 → 4 068   |
| 10 000 | 2 856 ms   | 23.7 ms   | ~120×    | 6 237 892 → 40 078 |

Two readings:

- **A hit is ~100–130× cheaper than the query at every N**, and does ~140× fewer allocations. In
  exec-once CLI mode a burst of Tabs within the TTL now pays the whole-DB query **once** (~2.4 s at
  10 k) and then ~24 ms per subsequent Tab, instead of ~2.4 s on *every* keystroke. Unlike the cold
  query number, this hit number is representative rather than a floor: the disk load is a real
  local-filesystem read. (It still omits OS process spawn, which the cache cannot help — a fresh
  `_carapace` process starts per Tab regardless.)
- **The hit cost still grows ~linearly with N** (0.19 → 2.76 → 23.7 ms, ~×14 per ×10): carapace loads
  and deserialises the *entire* cached candidate set (`cachebytes/op`: 10 KB → 105 KB → 1.06 MB — the
  whole set, since nothing is capped). Caching removes the network + GORM + proto-marshal cost but not
  the "proportional to the whole DB" shape. The structural fix — a **server-side prefix filter +
  `MaxResults` cap** (see below) — is still what would make a keystroke *sub*-linear; caching and that
  cap are complementary, not alternatives.

## Caveat: the cold number here is a FLOOR, not the felt CLI latency

The bufconn cold number **omits the two biggest real-world costs of an exec-once Tab press**:

1. **OS process spawn** — a real Tab launches a fresh `aims _carapace` process (Go runtime start,
   binary load, cobra/carapace tree build).
2. **Real transport handshake** — a real client dials a socket and does the mTLS handshake; here the
   dialer is an in-process `bufconn` with `insecure` credentials.

On top of that, `Teamclient.Connect()`'s `sync.Once` means even the in-process dial is paid only
once per stack, so cold re-runs only the hooks + `Init` re-registration. The true interactive cold
latency is therefore strictly higher than these numbers.

**Follow-up (not built here):** a real interactive figure needs a hyperfine-style shell benchmark of
the *compiled binary's* `_carapace` completion path over a real socket (spawn + TLS + connect + read
+ format end-to-end), compared against the same completion issued inside a long-lived console. That
is a separate harness from this in-process Go benchmark.

## Optional prefix/cap variant — not implemented (no server support)

The natural fix — push a prefix filter + a `MaxResults` cap to the server so completion fetches only
the matching prefix instead of the whole DB — cannot be quantified today. `server/host/host.go:Read`
matches the host argument as an **exact** GORM struct `Where` (no `LIKE`/prefix) and honours
`MaxResults` **only for the `== 1` case** (via `.First`); there is no general `LIMIT` and no
prefix-match RPC field. Quantifying the payoff of not fetching the whole DB requires a new
server-side prefix/cap RPC that does not exist yet — so no such variant was added (per the task's
"do not invent protos" constraint).

## Notes on the harness

- `newInMemoryStack` was widened from `*testing.T` to `testing.TB` (a one-line change in
  `roundtrip_test.go`) so the benchmark can reuse the exact production wiring; the existing tests
  pass `*testing.T`, which satisfies `testing.TB`, so they are unchanged.
- Seeding issues **one** `con.Hosts.Create` per stack. `Create` dedups by loading the entire host
  tree (`loadHostsPB`) on every call, so chunked seeding re-loads an ever-larger full tree per chunk
  and exhausts the wasm-sqlite linear memory before 10k; a single call loads that tree once against
  the empty DB.
- The completion Read requests full preloads (`Ports`/`Trace`/`Scripts`). `CompleteByID` passes
  `nil` Filters, but with `nil` Filters the server preloads nothing, so the read-back hosts would
  carry no hostnames/OS/ports and `display.Completions` would emit empty candidates — the preloads
  are both what the completion must display and what makes the whole-DB-fetch cost visible.
