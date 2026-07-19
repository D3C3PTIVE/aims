# AIMS — Display & "Conditional Screen-Estate" Rendering

> Written 2026-07-19. Companion to [`CLAUDE.md`](./CLAUDE.md) (architecture),
> [`STATE.md`](./STATE.md) (build/impl state) and [`ROADMAP.md`](./ROADMAP.md) (re-entry plan).
> This doc explains **how the single generic display engine works** (Part A), then reflects on
> **the best single-entity info view for each object type** (Part B), and ends with a
> **gaps & recommendations** sweep grounded in the current code.

---

## Part A — How the display engine works

Everything user-facing renders through **one generic contract**: a
`map[string]func(T) string` mapping a **column/field name → a value generator** for an object
of type `T`. That same map feeds three renderers — **tables**, **detail views**, and
**completions** — so an object's presentation is defined exactly once, in its domain package.

```
DisplayFields  map[string]func(*T)string   ← the value generators (per domain)
DisplayHeaders()  []display.Options         ← weighted column set for TABLES
DisplayDetails()  []display.Options         ← weighted field set for DETAIL views
Completions()     []display.Options         ← weighted field set for COMPLETIONS
        │
        ├─► display.Table[T](values, DisplayFields, DisplayHeaders()...)      → cmd/display/table.go
        ├─► display.Details[T](value, DisplayFields, DisplayDetails()...)     → cmd/display/details.go
        └─► display.Completions[T](values, DisplayFields, Completions()...)   → cmd/display/complete.go
```

### The three renderers

**`Table[T]`** — `cmd/display/table.go:30`. For each value, for each header column, calls
`fields[column](val)` to build the row (`table.go:36-46`), then `populate()` (`table.go:52`)
runs a post-processing pipeline into a `jedib0t/go-pretty` table:

1. `removeEmptyColumns()` (`table.go:113`) — drops any column that is empty on **every** row.
   Default-on via `opts.removeEmpty` (`settings.go:46`). **This is the real workhorse** of
   responsive layout in practice.
2. `withWeight()` (`table.go:143`) — **currently a no-op**: it returns `raw, rows` unchanged.
   The weight map is not applied through this path.
3. Terminal-size adaptation — `term.GetSize(stderrTerm.Fd())` (`table.go:74`) reads the real
   terminal width/height (falling back to 80×80 on error), then `getMaximumWeight(width,height)`
   (`defaults.go:141`) maps width→max allowed weight via `terminalWeightSizes`
   (`defaults.go:134`): **weight 1 → ≥80 cols, 2 → ≥160, 3 → ≥240, 4 → ≥320**. Finally
   `adaptTableSize()` (`defaults.go:257`) truncates the (weight-ascending) header list at the
   first column whose weight exceeds `maxWeight`.

So the intended model is: **lower weight = higher priority = shown first = survives on narrow
terminals**. Narrow terminals shed high-weight (weight-3/4) columns; wide terminals show them.

**`Details[T]`** — `cmd/display/details.go:32`. A vertical `key: value` view for a single
object. Headers are **grouped by weight** (`details.go:39-52`), weights sorted ascending, and
each group is emitted by `displayGroup()` (`details.go:64`) with a **trailing blank line
between groups** (`details.go:95`). So here **weight doubles as a section/priority grouping
mechanism** — weight-1 fields form the top "essentials" block, weight-4 the deep-detail block
at the bottom. Fields whose generator returns empty/whitespace are silently skipped
(`details.go:81-83`), and an entirely-empty weight group emits nothing.

**`Completions[T]`** — `cmd/display/complete.go:27`. Turns objects into carapace
`value\ndescription` pairs. One column is the **candidate** (the value actually inserted on the
command line) chosen via `WithCandidateValue(header, fallback)` (`settings.go:90`); every other
column is concatenated (`formatDesc`, `complete.go:120`) into the aligned description. If the
candidate column is empty for a row, the `fallback` column is used
(`complete.go:99-107`). `WithSplitCandidate(sep)` (`settings.go:102`) explodes a list-valued
field (e.g. multiple hostnames joined by `\n`) into **separate candidates sharing one
description** (`complete.go:85-88`). Newlines in any cell are flattened to spaces
(`complete.go:112-115`).

> **Completions are live DB queries.** In each domain's `cmd/<domain>` package, the
> `CompleteByID` / `CompleteBy…` carapace callbacks connect to the teamserver, `Read` the
> objects, and feed them through `display.Completions(...)` reusing the **exact same
> `DisplayFields` map** as the tables. Presentation and completion never drift because they
> share the generators.

### Options & weighting (`cmd/display/settings.go`)

The functional-options `opts` struct (`settings.go:28`) carries `headers`, the `weights`
map, `style`, `removeEmpty`, and the completion `candidate`/`fallback`/`sep`. Key options:

| Option | File:line | Effect |
|---|---|---|
| `WithHeader(name, weight)` | `settings.go:75` | append a column `name` at `weight` 1–4. **The core layout primitive.** |
| `WithStyle(style)` | `settings.go:59` | pick a `go-pretty` table style |
| `WithAutoSmallID()` / `FormatSmallID` | `settings.go:67` / `:110` | truncate UUIDs to 8 chars |
| `WithCandidateValue(header, fallback)` | `settings.go:90` | choose the completion insert-value column |
| `WithSplitCandidate(sep)` | `settings.go:102` | split list-valued candidates into multiple completions |

### Styles & color (`cmd/display/defaults.go`, `color.go`)

- **`AIMSDefault`** (`defaults.go:174`) — borderless, no row separators, header underlined with
  `=` and title-cased; a clean minimal look. **`AIMSBordersDefault`** (`defaults.go:215`) is the
  `+`/`-`/`|` bordered alternative. A handful of go-pretty styles are also registered by name
  in `tableStyles` (`defaults.go:162`).
- Raw ANSI SGR constants are defined directly (`Bold`, `Dim`, `FgYellow`, 256-color helpers
  `Fmt(Fg+"214")`, …) in `defaults.go:58-132`. Detail **field names** get a gray-bg / orange-fg
  chip (`colorDetailFieldName`, `color.go:22`); **values** are bold (`colorDetailFieldValue`,
  `color.go:26`). Most domain generators additionally colorize through `fatih/color`
  (green = up/active, yellow = warning/behind-jitter, red = down/dead).

### Where per-object presentation lives

| Domain | File | Type param | Contract present? |
|---|---|---|---|
| Host | `host/host.go:112` | `*pb.Host` | ✅ Fields + Headers/Details/Completions |
| Service (really Port) | `network/service.go:128` | `*host.Port` ⚠️ | ✅ but keyed on Port, not Service |
| Scan/Run | `scan/scan.go:171` | `*scan.Run` | ✅ (+ nested task tables) |
| C2 Agent | `c2/agent.go:108` | `*c2.Agent` | ✅ |
| C2 Channel | `c2/channel.go:96` | `*c2.Channel` | ✅ (severe header/field name drift) |
| **Credential** | — | — | ❌ **none anywhere** |

---

## Part B — Best single-entity info display, per object type

Guiding principle for **weight bands** in the Details view:

- **Weight 1 — Identity & liveness** (always shown): what is it, is it alive/valid, its key
  handle. An operator scanning a list must resolve "which one, is it useful" here.
- **Weight 2 — Operational essentials**: the fields you act on next (addresses, checkin, status).
- **Weight 3 — Enrichment**: tool-derived detail (fingerprints, hops, scripts summaries).
- **Weight 4 — Deep/raw**: full scripts, certificates, raw args, comments — on demand only.

### Host  (nmap heritage — `host/host.go`)

| Weight | Proposed fields | Rationale |
|---|---|---|
| 1 | ID (up=green), Hostnames, OS Name (+accuracy), OS Family, Status (up/down) | at-a-glance "which box, alive?, what is it" |
| 2 | Addresses (IPv4/IPv6/MAC), Open-port count, Purpose, Arch | the operator's next decisions |
| 3 | Hops/Route, Uptime, OS accuracy breakdown, Extra Ports (filtered/closed summary) | nmap enrichment |
| 4 | Host scripts, OS fingerprint, Comment, Vendor/MAC, Users/Processes counts | raw detail on demand |

Heritage note: Host mirrors nmap's `<host>` element — `Status`, `OSMatch`/accuracy,
`Trace`/`Hop`, `ExtraPorts`, host `Script`s. The single-entity view should read like `nmap -A`
output condensed: identity + OS guess on top, route + scripts below. Ports belong in a **nested
sub-table** (as scan tasks already do), not as Host columns.

### Port / Service  (nmap heritage — currently `network/service.go`, keyed on `*host.Port`)

| Weight | Proposed fields | Rationale |
|---|---|---|
| 1 | Num/Proto (e.g. `443/tcp`), State (open=green/filtered=yellow/closed=red), Service name | the port line an operator reads first |
| 2 | Product + Version, Method (probed/table), Reason | service fingerprint essentials |
| 3 | Extra Info, Device type, CPE, TLS/tunnel | enrichment |
| 4 | Script output (nested, recursive `Script`→`Table`→`Element`), full fingerprint | deep detail |

Heritage note: this is nmap's `<port>`/`<service>`/`<script>` tree. The recursive script
printer already exists (`network/service.go:255 printScript` / `:288 printTable`) and is the
right model for weight-4. See the **gap** below: this contract is defined over `*host.Port`,
so the network `Service` object has no view of its own.

### Credential  (Metasploit heritage — **no contract exists yet**)

The Metasploit credential model is `Core` = **Public** (username/cert) + **Private**
(password/hash/key) + **Realm** (domain/db) + **Origin** (how obtained) + **Login**s (where it
worked). Proposed **Core** detail view:

| Weight | Proposed fields | Source proto |
|---|---|---|
| 1 | ID, Public.Username, Private.Type (Password/NTLMHash/Key/…), Realm (`Key=Value`) | `public.proto:19-21`, `private.proto:19`, `realm.proto:10-11` |
| 2 | Private.Data (masked/truncated; full hash for hashes), Logins count, JTR format | `private.proto:21-23`, `core.proto:8` |
| 3 | Origin.Type (Manual/Import/CrackedPassword/Service), Origin.SessionId, Cracker, Filename | `origin.proto:11-32` |
| 4 | Per-Login table: host/service, AccessLevel, Status (Successful=green/Denied=red/…), LastAttemptedAt | `login.proto:11-22`, `LoginStatus` `:37` |

Heritage note: mirror Metasploit's `creds` output — one row per `Core`, columns
`public | private (type) | realm | origin`, and the `show` view expands the **Login** set as a
nested table (which host/service this credential opened, and whether it still works). Mask
`Private.Data` for passwords in table context; reveal in `show`.

### Scan / Run  (nmap et al. heritage — `scan/scan.go`)

| Weight | Proposed fields | Rationale |
|---|---|---|
| 1 | ID (running=yellow/done=green), Scanner, Profile name, Hosts up/down, Finished? | "which scan, done?, what did it find" |
| 2 | Info (proto/type), Begin/End + elapsed, Tasks done/total, Targets summary | run essentials |
| 3 | Args, full Targets list (host:port), Stats | reproduce/inspect |
| 4 | Per-task tables (running vs done, with % progress), raw scanner output | live/deep detail |

Heritage note: `Run` generalizes nmap's `<nmaprun>` (`Stats`, `Finished`, `RunStats/hosts
up-down`, task progress). The nested **running-tasks / done-tasks** tables already implemented
(`scan/scan.go:338 formatTasks`) are exactly the right weight-4 pattern. `Script/Table/Element`
(the `scan/nmap` subtree) render through the same recursive printer as Port scripts.

### C2 Agent  (Sliver-like heritage — `c2/agent.go`)

| Weight | Proposed fields | Rationale |
|---|---|---|
| 1 | ID (alive=green/behind-jitter=yellow/dead=red), Tool, Name, User@Hostname, OS | "which implant, alive, where" |
| 2 | Last/Next check-in, Tasks done/total, Active channel (proto + direction + addrs) | operational status |
| 3 | Host ID, PID/PPID/owner/cmdline, Working directory | process context |
| 4 | Channel Details (nested channel table), Task history, Pivot route/graph | deep detail |

Heritage note: mirror Sliver's `sessions`/`beacons` — liveness colour driven by
next-checkin+jitter (`agent.go:118-124`), and a **nested channel table** for the transport
detail (`agent.go:228 "Channel Details"`). The pivot **Route** graph (`agent.go:233`) is a
stub and is the natural weight-4 capstone.

### C2 Channel  (Sliver-like heritage — `c2/channel.go`)

| Weight | Proposed fields | Rationale |
|---|---|---|
| 1 | # (order), ID (running=green), Connection (`local ==>/<== remote`), Protocol | "which transport, up, which way" |
| 2 | Try/Fails, Beaconing (interval +/- jitter) or `session`, Last/Next check-in | health & cadence |
| 3 | Proxy URL, Remote address detail, Status | routing detail |
| 4 | Comment, per-channel scripts/hops | on demand |

Heritage note: a Channel is one transport of an Agent; its detail view is what the Agent's
weight-4 "Channel Details" nested table expands. Direction arrows encode bind vs reverse.

---

## Gaps & recommendations

### Engine-level

1. **`withWeight` is a no-op** (`table.go:143-147`) — returns rows unchanged. Table
   responsiveness relies entirely on `removeEmptyColumns` + `adaptTableSize`. Either implement
   it or delete it to avoid the false impression that the weight map filters table columns here.
2. **`adaptTableSize` is off-by-one and order-dependent** (`defaults.go:257-291`): it
   increments `real` *before* the weight check and `break`s *after*, so it keeps the first
   over-max-weight column; the `weighted` counter is computed but unused; and it assumes headers
   are already in ascending-weight order (true by convention, fragile by contract). Rewrite to
   drop columns strictly `weight > maxWeight`, independent of ordering.
3. **Broken/placeholder color constants** (`defaults.go:47-56`): `ColorIDYellow`,
   `ColorIDRed`, `ColorIDOrange`, `detailsSection`, `ColorHintsDim` are all the bare byte
   `"\033"` (an ESC with no CSI body). Every helper built on them
   (`colorDetailFieldSubkey`/`colorHint`/`colorKeyName`/`colorKeyValue`, `color.go:30-44`) emits
   malformed escapes — currently harmless only because they're **unused/dead**. Fill in real SGR
   sequences or remove.
4. `formatDesc` (`complete.go:120`) concatenates description columns with no explicit
   separator beyond pre-applied padding — fine today, but brittle if a generator stops padding.

### Per-domain

5. **Credentials have no presentation at all.** No `DisplayFields`/`DisplayHeaders` in
   `credential/*`, and `cmd/credentials/credentials.go` `list`/`show`/`rm` are stubs that fetch
   then `return nil` without rendering (`credentials.go:44-84`). This is the **single biggest
   display gap** — the entire Metasploit-heritage model is invisible. Build the Core contract
   proposed above.
6. **"Service" display is actually a Port display.** `network/service.go:128` declares
   `DisplayFields map[string]func(*host.Port) string` — keyed on `host.Port`, not
   `network.Service`. `network.Service`'s own `AsEntity` is also a stub. Decide whether Service
   is a first-class displayable object or an alias of Port, and make the type match.
7. **Header ↔ generator name mismatches silently drop fields** (Details skips any header with
   no generator or an empty value). Confirmed cases:
   - Host: header **"Hosts scripts"** (`host.go:90`) has no generator (the generator is
     **"Scripts"**, `host.go:210`, which itself returns `""`); **"Status"** generator returns
     `""` (`host.go:142`); **"Virtual Host"** / **"Comment"** headers have no generators.
   - Scan: **"Finished"** generator returns `""` (`scan.go:241`) though it's weight-1 in table
     and details; **"Targets Details"** / **"Tasks Details"** generators exist but no header
     references them.
   - C2 Agent: detail header **"Tasks "** has a trailing space (`agent.go:79`) so it never
     matches the **"Tasks"** generator (`agent.go:197`).
   - **C2 Channel is the worst**: table header **"#"** (`channel.go:47`) has no generator (it's
     **"Order"**); the entire **detail** header set — "Status", "Remote Address", "Hops",
     "Comment", "Host scripts" (`channel.go:66-75`) — has **no** matching generators (fields are
     ID/Order/Protocol/Connection/Try-Fails/Beaconing/Last-Next/Proxy), so the channel `show`
     view renders **only the ID**. Completions likewise reference non-existent "State"/"Remote
     Address".
8. **Direction test is inverted** in both `c2/agent.go:214` and `c2/channel.go:112`:
   `strings.ToLower(h.Direction) == "Bind"` compares a lower-cased string to capitalized
   `"Bind"` → always false → every channel renders as reverse (`<==`).
9. **C2 Agent generator bugs**: "Host ID" returns `FormatSmallID(h.Id)` (the agent's own id,
   not `h.Host.Id`, `agent.go:138`); "User/Hostname" dereferences `h.Host.Hostnames` with no
   nil-check on `h.Host` (`agent.go:146`, panic risk); "Process" has format-verb bugs
   (`fmt.Sprintf("(P )", …)` with no verb, `%s` on a struct pointer, `agent.go:174-178`).
10. **Host `GetOperatingSystem` has inverted conditions** (`host.go:222-227`):
    `if h.OSName == "" { osName = h.OSName }` assigns the empty string; the direct-field OS path
    is effectively dead, so the nmap-guess path is always used even when exact OS is known.

### Recommended order (display-only slice)

1. Fix the **name-mismatch drift** (gap 7) and **direction/process bugs** (gaps 8–9) — cheap,
   high-impact, makes existing `show` views actually render.
2. Build the **credential presentation contract** (gap 5) — the largest missing surface.
3. Resolve **Service vs Port** typing (gap 6).
4. Repair or delete the **engine dead code** (gaps 1–3) so weight semantics are trustworthy.
