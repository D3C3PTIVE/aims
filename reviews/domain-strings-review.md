# Domain string-literal audit — AIMS

> Agent report, 2026-07-20. Investigation of bare, repeated domain string literals in the Go
> code, cross-checked against the Protobuf enum definitions. Read-only; no files changed.

## Enum inventory (the full set of `enum` in `**/pb/*.proto`)

| Enum | File | Values |
|------|------|--------|
| `SourceType` | `provenance/pb/source.proto:77` | Manual, Import, Cracked, Service, Scan, C2 |
| `PrivateType` | `credential/pb/private.proto:28` | Password, BlankPassword, ReplayableHash, NonReplayableHash, NTLMHash, PostgresMD5, Key, JWT |
| `PublicType` | `credential/pb/public.proto:36` | Username, BlankUsername, PublicKey, Certificate |
| `LoginStatus` | `credential/pb/login.proto:43` | Untried, DeniedAccess, Disabled, LockedOut, Sucessful, UnableToConnect |
| `Family` | `host/pb/os/families.proto:6` | OS families |
| `ICMPType` | `network/pb/packet.proto:77` | ICMP types |

Crucially: **host/port `State`, `Protocol`, address `Type`, and scan `Exit` are all plain `string` fields** carrying `xml:"state,attr"` / `xml:"proto,attr"` / `xml:"addrtype,attr"` / `xml:"exit,attr"` tags (e.g. `host/pb/host.pb.go:575`, `host/pb/port.pb.go:254`, `network/pb/network.pb.go:333`, `scan/pb/scan.pb.go:935`). **No enum exists for any of these**, and they are populated directly from nmap XML — the string values are an external contract.

## Findings table

| literal(s) | # occ. (non-test) | example locations | existing enum? | recommendation |
|---|---|---|---|---|
| **`"up"` / `"down"`** (host status) | ~10 | `host/host.go:100,132,134,302,375,377`; `scan/scan.go:572`; `cmd/scan/live.go:230,320,322`; `scan/ingest/zgrab.go:108` | none (`Status.State` is `string`, nmap `xml:"state,attr"`) | **New Go const block** (`host` domain). Keep string-typed (must equal nmap XML values), but replace the scattered `"up"`/`"down"` literals with `StateUp`/`StateDown` consts. |
| **`"open"` / `"closed"` / `"filtered"`** (port state) | ~25 | `host/host.go:387`; `network/service.go:117-121,207-212,336,373-377`; `scan/history.go:147,178,203`; `cmd/services/services.go:218-222,286-288`; `cmd/scan/history_view.go:164-166`; `cmd/completers/values.go:339,873`; `cmd/scan/live.go:277`; `scan/ingest/zgrab.go:123` | none (`State.State` is `string`, nmap `xml:"state,attr"`) | **New Go const block** (`host` domain: `PortOpen`/`PortClosed`/`PortFiltered`, plus `unfiltered`/`open|filtered` variants nmap emits). Highest-count cluster in the codebase; consolidating removes duplicated color/switch logic in host, network, scan, and 3 cmd packages. |
| **`"nmap"` / `"masscan"` / `"zgrab2"`** (scanner identity keys) | ~15 | dispatch `server/scan/run.go:422,424`; `Name()` `scan/ingest/nmap.go:34`, `scan/ingest/zgrab.go:62`; run stamp `scan/ingest/nmap.go:43`, `scan/ingest/zgrab.go:66`; `cmd/scan/run.go:93,103`; `scan/drive/masscan.go:77,118`; completion guards `cmd/scan/run_complete.go:56,264` | none | **New Go const block** (shared by `scan/drive` + `scan/ingest`). These are the join keys tying driver ↔ ingestor ↔ provenance `Tool` ↔ completion-guard together; a `"zgrab2"` vs `"zgrab"` typo silently breaks ingest lookup. Medium-high value. |
| **`"tcp"` / `"udp"` / `"sctp"`** (protocol) | 2 (Go logic) | `scan/ingest/zgrab.go:119,120` (only place hardcoded; `Protocol` is `string`, nmap `xml:"proto,attr"`) | none | **New const** (low priority — only zgrab hardcodes; a `ProtoTCP` const is cheap and worthwhile if a const block is created anyway). Note `server/transport/tailscale.go:109` `"tcp"` is a net-layer arg, unrelated — leave raw. |
| **`"ipv4"` / `"ipv6"` / `"mac"`** (address type) | 3 | `scan/ingest/zgrab.go:161,163`; `cmd/completers/values.go:725,768`; `cmd/scan/run_complete.go:540,580` | none (`Address.Type` is `string`, nmap `xml:"addrtype,attr"`) | **New const** (small; `network` or `host` domain). Low-medium value. |
| **`"success"`** (nmap runstats exit) | 2 logic | write `server/scan/run.go:281`; compare `scan/scan.go:188` (+ zgrab status `scan/ingest/zgrab.go:100`) | none (`Finished.Exit` is `string`, nmap `xml:"exit,attr"`) | **New const** `ExitSuccess`. Low-medium — the produce/consume pair splits the literal across two packages. |
| **SourceType values** ("Manual"/"Import"/"Cracked"/"Service"/"Scan"/"C2") | 0 raw literals | correctly used as enum: `cmd/credentials/credentials.go:163`, `server/scan/scan.go:183`, `credential/core.go:85,92`, `credential/display.go:382-399` | **`provenance.SourceType`** | **Already consolidated — no action.** Hand-written code uses `provenance.SourceType_*` throughout; no raw strings found. |
| **Credential type values** (Password/NTLM/hash/key/JWT/Certificate) | 0 raw literals | correctly used as enum: `credential/password.go:38`, `credential/nonreplayable-hash.go:35`, `credential/display.go:127-129,267-296` | **`credential.PrivateType` / `PublicType`** | **Already consolidated — no action.** This is the reference example of the target state. |
| **Scan run-state** (running/interrupted/done/failed/queued) | 0 logic literals | `scan/scan.go:165-173` — already a typed `runState int` with `stateCreated/stateRunning/stateDone/stateFailed/stateInterrupted` consts; `stateOf()` classifies | none needed (internal derived state, not persisted) | **Already consolidated — no action.** The `"running"`/`"interrupted"`/`"queued"` tokens that appear are only prose in comments and display strings (`stateToken` at `scan/scan.go:227`), not logic literals. |

## ✅ Resolution (2026-07-21)

Implemented the three top consolidations as Go string consts (no enums — the values are the
nmap-XML contract):

- **`host/states.go`** (new) — `StateUp`/`StateDown` (host liveness) + `PortOpen`/`PortClosed`/
  `PortFiltered` (+ `PortUnfiltered`/`PortOpenFiltered`/`PortClosedFiltered`). All ~35 port-state
  and host-status comparison/switch/assign sites across `host`, `network`, `scan`, `scan/ingest`,
  `server/scan`, and `cmd/{services,scan,completers}` now reference these. `network`/`cmd` packages
  that only imported `host/pb` gained a `hostdomain "…/host"` import.
- **`scan/scanners.go`** (new) — `ScannerNmap`/`ScannerMasscan`/`ScannerZgrab2`. The identity
  join-key sites — ingestor `Name()` + `Run.Scanner` stamp (`scan/ingest/{nmap,zgrab}.go`), driver
  dispatch (`server/scan/run.go` `scannerFor`), completion guards (`cmd/scan/run_complete.go`),
  the `runScanner` arg (`cmd/scan/run.go`), and `capableScanners` (`cmd/bring/caps.go`) — all use
  the consts now.

**Deliberately left as literals** (a different concern than the driver↔ingestor identity key):
OS-binary lookup/exec (`scan/drive/{scanner,masscan}.go` `exec.LookPath`/`binary=`), the `_nmap`
zsh-completer name, the masscan progress-task label, the `--nmap` CLI flag name, and proto/prose
comments. The lower-value clusters (§4: `"success"` exit, address types, `tcp/udp`) were **not**
done — pick them up if touching those files.

Full tree builds; 234 tests pass. Reference pattern for future domain consts.

## Prioritized summary (highest-value consolidations)

1. **Port-state strings `"open"/"closed"/"filtered"` (~25 occurrences)** — the single biggest literal cluster, duplicated across `network/service.go`, `host/host.go`, `scan/history.go`, and three `cmd/*` packages, each re-implementing the same color/switch logic. Factor into a `host`-domain const block. No enum should be invented — the values are the nmap XML contract — but string consts (`host.PortOpen`, etc.) end the duplication and give one authoritative spelling.

2. **Host-status strings `"up"/"down"` (~10 occurrences)** — same story, same domain; do it in the same const block.

3. **Scanner identity keys `"nmap"/"masscan"/"zgrab2"` (~15 occurrences)** — highest *correctness* risk because the literal is a cross-package join key (driver dispatch in `server/scan/run.go:422`, ingestor `Name()`, run `Scanner` stamp, provenance `Tool`, completion guards). A shared const in `scan/drive`/`scan/ingest` prevents silent lookup breakage from a spelling drift.

4. **Lower-value, do-if-touching:** `"success"` exit (`ExitSuccess` const, 2-package split), address types `"ipv4"/"ipv6"/"mac"`, and protocol `"tcp"/"udp"` (only `scan/ingest/zgrab.go` hardcodes them).

**No enum-merge opportunities exist for the raw literals** — every repeated domain literal that warrants attention (states, protocols, address types, scanner names, exit) maps to a proto field that is deliberately a `string` (nmap-XML-driven), so the recommendation is Go string consts, never a new/existing enum. Conversely, the two domains that *do* have enums (provenance `SourceType`, credential `PrivateType`/`PublicType`) are already used correctly with zero raw-string leakage, and scan's lifecycle state is already a typed Go const set — these need no work and serve as the reference pattern.
