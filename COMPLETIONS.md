# Sub-categorized completions — survey & design

> Written 2026-07-19. Read-only survey of every completion callback + the
> `cmd/display` plumbing, with a design for grouping candidates into
> sub-categories (locality / recency / provenance). Companion to
> [`DISPLAY.md`](./DISPLAY.md); realizes the "Design intent — sub-categorized
> completions" note in [`CLAUDE.md`](./CLAUDE.md).

## 1. Completion inventory

Every completion is a live-DB `carapace.ActionCallback`: it connects
(`ConnectComplete`), `Read`s objects over gRPC, feeds them through
`display.Completions` / `CompletionsStyled` (which reuse the domain's
`DisplayFields`), then wraps the flat result in a **single** `.Tag(...)`. None
split candidates into sub-groups today.

| Fn (file:line) | Object | Candidate field (`WithCandidateValue`) | Styled? | Grouping today |
|---|---|---|---|---|
| `cmd/hosts/hosts.go:155` `CompleteByID` | `pb.Host` | `ID` | no | 1 flat list, `.Tag("hostnames ")` |
| `cmd/hosts/hosts.go:180` `CompleteByHostnameOrIP` | `pb.Host` | `Hostnames`→`Addresses`, split `,` | no | 1 flat list, `.Tag("hostnames ")` |
| `cmd/scan/commands.go:71` `CompleteByID` | `scan.Run` | `ID` | no | 1 flat, `.Tag("scans").Filter` |
| `cmd/scan/run_complete.go:46` `completeRunNmap` | (target slot) | delegates to `hosts.CompleteByHostnameOrIP` | no | inherits host list |
| `cmd/scan/run_complete.go:67` `completeNSEScripts` | NSE names | (raw described) | no | **implicit 2-tier order**: categories before scripts, one Tag |
| `cmd/services/services.go:235` `CompleteByID` | `Port` (`svcRow`) | `ID` | **yes** (port state → colour) | 1 list, `.Tag("services (by id)")` |
| `cmd/credentials/credentials.go:295` `completeCredentials` | `credential.Core` | `ID` / `Public` | **yes** (secret present → colour) | 1 list, per-call Tag |
| `cmd/c2/agents.go:119` `CompleteByID` | `c2.Agent` | `ID` | no | 1 list, `.Tag("agents ")` |
| `cmd/c2/channels.go:113` `CompleteChannelByID` | `c2.Channel` | `ID` | no | 1 list, `.Tag("agents ")` ← **mislabeled** |

Two functions (services, credentials) already carry a **per-candidate
classifier** (`styleOf func(T) string`) driving colour via `CompletionsStyled`.
That is the precedent to generalize: grouping is a second per-object classifier
alongside `styleOf`.

## 2. Data available on the read object (per axis)

- **Locality** — `Host.Addresses[].Addr` is a raw IP string. `net.ParseIP(addr)`
  + `IsLoopback()`/`IsPrivate()`/`IsLinkLocalUnicast()` gives loopback / private /
  link-local vs routable-remote with **zero extra queries**. `Addresses[].Type`
  distinguishes `ipv4`/`ipv6`/`mac`. *On-subnet* (vs merely private) needs the
  client's own `net.Interfaces()` — self-contained, client-side, no RPC.
- **Recency / liveness** — `Host.Status.State` (`up`/`down`/other) is present and
  already drives the green ID. `Host.UpdatedAt` (top-level `timestamppb`) is the
  staleness proxy (wall clock at callback time is fine here). `c2.Agent.State` is
  the C2 liveness field.
- **Provenance** — every current completion reads only from the DB, so
  *everything is "in DB"*: this axis is **inert today**. It becomes real only for
  `completeRunNmap`, which could *additionally* inject local-interface addresses
  (`net.Interfaces()`) as **fresh, never-scanned targets** — a genuinely distinct
  provenance group from DB hosts.

## 3. Per-completion grouping recommendation

| Completion | Axis → groups | Lever | Cost |
|---|---|---|---|
| **Host (both)** | liveness × locality: `up · local`, `up · remote`, `down / stale` | **tags** | free — `Status.State` + `ParseIP(Addr)` |
| **scan run target** | inherits host groups **+** `local interfaces` (fresh) | **tags** | host part free; interface injection = client-side `net.Interfaces()` |
| **services** | port state: `open` / `filtered` / `closed·other` | tags *or* order (open-first) | free — already the `styleOf` axis |
| **credentials** | usability: `loot (has secret)` / `partial (username only)`; optionally by type/realm | tags | free — already the `styleOf` axis |
| **c2 agents/channels** | `Agent.State`: alive/active vs dead/stale | tags | free (also fix channel's `"agents "` tag) |
| **NSE scripts** | `categories` vs `scripts` | already ordered → promote to 2 tags | trivial |

Tags suit host/services/creds/c2 (headings are meaningful, sets small). Ordering
alone suits NSE and is the fallback wherever headings would feel heavy.

## 4. The architectural question — extending `cmd/display`

**Key constraint:** `cmd/display` imports **no carapace** —
`Completions`/`CompletionsStyled` return a plain `[]string`, and `.Tag()` is
applied by the call site on the whole `carapace.Action`. That boundary is worth
preserving (display stays render-lib-agnostic). Carapace tag *groups* require
**one `Action` per tag**, merged with `carapace.Batch(...).ToA()` — so the split
must produce N tagged sub-lists, and today nothing does.

**Smallest extension** — mirror the existing `styleOf` pattern with a `groupOf`
classifier, keeping the carapace-batch loop out of every call site:

**(A) In `cmd/display`** — bucket the existing emit loop instead of flattening it:

```go
// A tag heading + its already-formatted (candidate,desc[,style]) tuples.
type CompletionGroup struct {
    Tag    string
    Values []string
}

// groupOf classifies each value into a tag heading; groups are ordered by the
// tags passed to WithGroupOrder(...), unknown tags appended last. Column padding
// is computed per-group, so each heading aligns internally.
func CompletionsGrouped[T any](values []T, fields map[string]func(T) string,
    groupOf func(T) string, opts ...Options) []CompletionGroup

func CompletionsGroupedStyled[T any](values []T, fields map[string]func(T) string,
    groupOf func(T) string, styleOf func(T) string, opts ...Options) []CompletionGroup
```

This is the current `CompletionsStyled` body with one change: append each emitted
tuple to `buckets[groupOf(values[j])]` rather than to one `results`. Add
`WithGroupOrder(tags ...string)` to `settings.go` so group order is deliberate (Go
map order is random — this is required, not optional). Per-group padding is a
*bonus* the split gives for free.

**(B) In `cmd` (pkg `cmd`, imported as `aims`, already imports carapace)** — one
generic adapter, so no call site hand-rolls a Batch:

```go
func GroupedValues(groups []display.CompletionGroup) carapace.Action {
    batch := make([]carapace.Action, 0, len(groups))
    for _, g := range groups {
        batch = append(batch, carapace.ActionValuesDescribed(g.Values...).Tag(g.Tag))
    }
    return carapace.Batch(batch...).ToA()
}
func GroupedStyledValues(groups []display.CompletionGroup) carapace.Action // ActionStyledValuesDescribed
```

**(C) Per-domain classifier** lives beside `DisplayFields`/`styleOf` (e.g.
`host.CompletionGroup(*pb.Host) string`). A call site collapses to:

```go
groups := display.CompletionsGrouped(res.Hosts, host.DisplayFields, host.CompletionGroup, options...)
return aims.GroupedValues(groups)
```

Net: display gains ~1 struct + 2 functions + 1 option; the cmd pkg gains 2
adapters; each domain adds one classifier func. No carapace leaks into display; no
per-call-site batch boilerplate. Styling and grouping compose (both are just
`func(T) …` classifiers).

## 5. Ranked first targets

1. **`hosts.CompleteByHostnameOrIP`** (`cmd/hosts/hosts.go:180`) — highest
   leverage: reference completion, `scan run` inherits it for free, all grouping
   data already on the read object, exercises every part of the new API (grouped +
   split candidates).
2. **`services.CompleteByID`** (`cmd/services/services.go:235`) — already computes
   the exact classifier (`styleOf` on port state); proves the styled-grouped path
   (`CompletionsGroupedStyled`) with essentially no new domain logic.

(Credentials is the natural third — same "promote `styleOf` to `groupOf`" move.)

## 6. Mock output

**`scan run nmap <TAB>`** (host completer, grouped by liveness × locality):

```
up · local
   127.0.0.1       localhost   Linux
   10.0.0.5        db01        Linux 5.x
   192.168.1.20    printer

up · remote
   93.184.216.34   example     Ubuntu

down / stale
   198.51.100.7    old-vpn                 (down · seen 8d ago)

local interfaces          ← provenance: fresh, not yet in DB (scan-target only)
   192.168.1.42    eth0
```

**`services rm <TAB>`** (grouped by port state, candidate = short ID, coloured):

```
open
   a1b2c3d4   db01    5432   tcp   PostgreSQL 14
   e5f6a7b8   web01    443   tcp   nginx

filtered
   9a8b7c6d   web01   8080   tcp

closed / other
   1f2e3d4c   web01     25   tcp   smtp
```
