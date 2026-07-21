# Client-side investigation — AIMS completion & gRPC client layer

> Agent report, 2026-07-20. Read-only over `client/`, `cmd/commands.go`, `cmd/cache.go`,
> `cmd/completers/`, `cmd/display/complete.go`, `cmd/agentctx/agentctx.go`, and every domain
> `CompleteBy*`. No files were edited.

## ✅ Resolution (2026-07-21)

The completion-refactor track is implemented:

- **New shared helpers in `cmd/completers/plumbing.go`:** extracted a non-agent-folding
  `listCompleter` core; added exported generic **`CachedList[T]`** (cache + **Guard** + connect +
  read + empty-check + render) and **`FilterSelected`** (the outside-cache `.Filter(c.Args...)` tail).
- **All 8 hand-rolled domain completers folded onto `CachedList`** — `cmd/hosts` (ByID +
  HostnameOrIP), `cmd/services` (ByID, `T=svcRow`), `cmd/c2` (agents + channels), `cmd/credentials`
  (`completeCredentials`, styled), `cmd/scan` (ByID + SeriesHead, via `FilterSelected`). This closes
  the **panic-hang gap** (they all get `Guard` now) and removes the copy-pasted connect/read/format
  shell. (A concurrent change further sub-grouped `scan CompleteByID` into running-vs-rest on top of
  the refactored form.)
- **host completer `nil` Filters fixed:** both host completers now pass a non-nil `&HostFilters{}`,
  which is what triggers the server's base preloads (`OS.Matches`/`Status`/`Hostnames`) — nil loaded
  only depth-1 and left the OS/status columns thin.
- **`exportCommand` dedup:** the two byte-identical `Hosts.Read` branches collapsed to one read + a
  branch on `len(args)`.
- **`display/complete.go` triple→pair reshape:** documented the 3-wide `CompletionsStyled` contract
  the walk relies on (short-tail groups are ignored, not mis-paired).
- **Secret/Username RPC chain parallelized:** new `credsWithAgentPromotion` runs `Creds.List`
  concurrently with the `CurrentHost`→`agentHostCredIDs` leg (a `sync.WaitGroup`, no new dep) —
  the two legs are independent, so this overlaps ~3 of the 4 RPCs on a cache miss. `-race` clean.

Full tree builds; 250 tests pass. **Not done** (out of client scope / needs proto work): the
`agentctx.CurrentHost` process-lifetime memo (latent, low value), and the server-side `LIKE` prefix
filter — the real completion-latency lever (the `MaxResults` cap half of it landed server-side, see
[[aims-code-sweep-audits]] P4).

## Top items (highest impact first)

1. **9 domain ID-completers hand-roll the exact cache/connect/read boilerplate that `cachedCompleter` already abstracts — and none of them get panic protection.** (Refactor, plus a real robustness gap.)
2. **`Secret`/`Username` completers serialize a 4-RPC chain where 2 RPCs are independent and could overlap** (`Creds.List` ∥ agent-host resolution). (Perf.)
3. **`agentctx.CurrentHost` costs 2 serial RPCs (`Agents.Read`→`Hosts.Read`) and is re-run inside every completer body rather than shared** — the dependency is real, but it's the dominant fixed cost of every agent-context completion. (Perf.)
4. **`hosts.CompleteByID` / `CompleteByHostnameOrIP` pass `nil` Filters** while services/scan pass explicit ones — inconsistent preload behavior, and per the bench doc the intended nested description data isn't fetched. (Refactor/correctness.)
5. **The structural cost documented in BENCH_COMPLETIONS.md — whole-DB fetch, no prefix match, no cap, on every keystroke** — is the real latency driver; client-side batching is second-order until that's addressed. (Perf, context.)

---

## Refactor / cleanup

**`cmd/hosts/hosts.go:158-183` & `:187-213`, `cmd/services/services.go:234-236`, `cmd/scan/commands.go:86-115` & `:125-152`, `cmd/c2/agents.go:120-143`, `cmd/c2/channels.go:115-138`, `cmd/credentials/credentials.go:300-333` — duplicated connect/read/format shell.**
Every one of these repeats the identical skeleton:
```go
aims.CacheCompletion(con, "<name>", carapace.ActionCallback(func(c) {
    if msg, err := con.ConnectComplete(); err != nil { return msg }
    res, err := con.X.Read(ctx, &req)
    if err = aims.CheckError(err); err != nil { return carapace.ActionMessage("Error: %s", err) }
    if len(res.GetY()) == 0 { return carapace.ActionMessage("no X in database") }
    ... display.Completions ... ActionValuesDescribed(...).Tag(...)
}))
```
This is *exactly* what `cmd/completers/plumbing.go:57 cachedCompleter` already bundles (cache + `Guard` + `ConnectComplete`), but `cachedCompleter` is unexported and only `values.go` uses it. Suggested change: export a generic helper (e.g. `completers.CachedList[T](con, name, label, read func() ([]T, error), render func([]T) carapace.Action)`) and rewrite the 9 domain completers on top of it, collapsing ~15 lines each to ~3. Effort: **M**. Impact: medium — removes ~120 lines of copy-paste and, more importantly, closes the panic gap below.

**Same 9 completers lack `Guard(...)`.** Grep confirms `Guard` is only wired in `cmd/scan/run_complete.go:56,264` and (via `cachedCompleter`) the value completers. The domain ID completers run `display.Completions` / styling directly in the callback with no `recover`; a formatting panic silently hangs the `_carapace` subprocess (the exact failure mode `Guard`'s doc-comment at `plumbing.go:42` describes). Folding them onto `cachedCompleter`/a shared helper fixes this for free. Effort: **S** (once the helper exists). Impact: medium — user-visible "completion just hangs" with no diagnostic.

**`cmd/hosts/hosts.go:165,194` — `nil` Filters on the completion Read.** Unlike `services.go:242` (`Filters: {Ports:true}`) and `scan/commands.go:94` (`Filters: {}`), the two host completers pass no `Filters`. `server/host/host.go:457 WithPreloads` returns nil for `from==nil`, so only `clause.Associations` (depth-1) loads — nested description data (OS matches, `Ports.Service`/`State`) is never fetched, which BENCH_COMPLETIONS.md:173-176 flags as producing thin/empty descriptions. Suggested: pass an explicit `HostFilters` matching what `host.DisplayFields` actually renders. Effort: **S**. Impact: low-medium (correctness of the description column).

**`cmd/scan/commands.go:117-119` & `:154-156` — identical "filter outside the cache" tail duplicated.** Both `CompleteByID` and `CompleteSeriesHead` wrap the cached action in `ActionCallback(func(c){ return cached.Filter(c.Args...) })`. Hoist to a one-liner helper (`filterSelected(cached)`). Effort: **S**. Impact: low.

**`cmd/hosts/hosts.go:215-261 exportCommand` — both `if`/`else` branches issue the byte-identical `Hosts.Read`** (same request, same filters); only the post-read prefix filtering differs. Collapse to one Read, then branch only on `len(args)`. Effort: **S**. Impact: low (readability; also halves the read in the no-arg path... it's already one read there, so purely dedup).

**`cmd/display/complete.go:30-34` — brittle triple→pair reshaping.** `Completions` calls `CompletionsStyled` then strips column 3 with `for i := 0; i+2 < len(triples); i += 3`. Works, but silently drops a trailing malformed group if the slice length isn't a multiple of 3. Minor; a comment or a length assertion would harden it. Effort: **S**. Impact: low.

**Stale-ish note:** `client/client.go:268-281 isOffline` has a copy-paste bug — the second block tests `ts != nil` (line 277) but should test `tc != nil`; `ts` is from the first `Find`, so the teamclient-import offline case is effectively gated on the wrong variable. Effort: **S**. Impact: low but it's a real logic bug (teamclient import may attempt a connect it shouldn't).

---

## Perf / concurrency

**`cmd/completers/values.go:468-479 (Secret)` and `:624-634 (Username)` — serial 4-RPC chain, 2 legs independent.**
Both do, in order: `Creds.List` (469/625) → `agentctx.CurrentHost(con)` (477/632, itself 2 RPCs) → `agentHostCredIDs` → `Logins.List` (489). `Creds.List` does not depend on the agent-host resolution, yet it blocks in front of it. Proposal: run `Creds.List` and `CurrentHost`+`agentHostCredIDs` concurrently with an `errgroup.Group` (or two goroutines + a `sync.WaitGroup`), join before `groupedSecrets`/`groupedUsernames`. That overlaps ~3 of the 4 RPCs. Effort: **M**. Impact: medium — these are the completers with the deepest RPC chain, so on a cache miss they're the slowest agent-context completions.

**`cmd/agentctx/agentctx.go:95` → `:113` — `Agents.Read` then `Hosts.Read`, unavoidably serial** (need the host id from the agent before reading the host). Can't be parallelized as-is; the real fix is a server-side join RPC (agent→host in one round trip). Out of client scope, but worth flagging: this 2-RPC resolve is paid inside *every* agent-context completer body (`cachedHostCompleter` at `plumbing.go:82`, `Secret`, `Username`). Because only the *whole completer output* is on-disk cached (`CacheCompletion`), there's no shared per-invocation memo of `CurrentHost` — if two completers ever ran in one `_carapace` process they'd each re-resolve. Effort to add a process-lifetime memo on `CurrentHost`: **S**; impact low today (see next point) but it removes a latent redundancy.

**Cross-completer batching has limited real-world surface — worth stating explicitly.** In carapace a single positional/flag slot dispatches to exactly one `Action`, so a Tab normally fires one completer; there is no N-completers-per-Tab fan-out to parallelize. The genuine "batch" opportunities are *within* a completer, and the good news is the value completers already do this right: `cachedTargets` (`values.go:86-95`) issues **one** `Hosts.Read` and fans it into `groupedTargets`+`groupedSubnets` via `carapace.Batch` — no double fetch. So the only intra-invocation redundancy left is the Secret/Username chain above. Net: the "parallel completion batching" lever is real but narrow — it's the two credential completers, not a general framework win.

**Connection setup is *not* re-paid per completer.** `client.go:159,195 Teamclient.Connect()` is `sync.Once`-guarded (confirmed by BENCH_COMPLETIONS.md:64-69: warm vs cold allocs differ <0.02%). `ConnectComplete` per completer only re-runs pre-hooks + `Init()` stub reassignment. So there is *no* re-dial-per-completer problem to fix; the felt cost is OS process spawn + the whole-DB read, not connection churn. Don't spend effort here.

**The dominant cost is structural, server-shaped (context, not a client fix).** BENCH_COMPLETIONS.md:73-84 measures ~275 ms @ 1k hosts and ~2.4 s @ 10k on every keystroke because `server/host/host.go:Read` fetches the entire set (exact `Where`, no `LIKE` prefix, `MaxResults` honored only for `==1`) and re-marshals it. `CacheCompletion` (TTL 10s, `cmd/cache.go:42,57`) already turns a Tab burst into one query + ~100× cheaper hits, which is the right client-side mitigation. Any client-side concurrency work is second-order until a **server-side prefix filter + `MaxResults` cap** exists; that's the real lever and it's an RPC/proto change, out of this client-side scope.

---

## Quick-reference anchors
- Shared substrate that domain completers *should* reuse: `cmd/completers/plumbing.go:42` (`Guard`), `:57` (`cachedCompleter`), `:73` (`cachedHostCompleter`), `:92` (`renderGroups`).
- Cache layer: `cmd/cache.go:42` (TTL), `:57` (`CacheCompletion`), `:105` (`InvalidateCompletionCache`).
- Connect: `client/client.go:146` (`ConnectRun`), `:188` (`ConnectComplete`), `:217` (`CompletionScope`).
- Serial RPC chains: `cmd/completers/values.go:468`, `:624`; `cmd/agentctx/agentctx.go:89`.
