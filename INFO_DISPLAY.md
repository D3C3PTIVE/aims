# AGENT INFO — a situational-awareness display for `aims agent info`

> Design/plan doc. Drafted 2026-07-21. **Not yet built.** Companion to [`PROMPT.md`](./PROMPT.md)
> (the BRING shell-context design). This doc covers the on-demand expand: the rich display an
> operator gets with `aims agent info` (and, brought, `aimsi info`) — distinct from the passive
> one-line prompt segment `aims init` installs.

## Goal

Replace the flat, static key:value dump with a display that answers
the three questions a flat dump can't:

- **What's the state?** → a HUD status board (subsystem panes).
- **Where am I / what's my reach?** → a spatial situational-awareness tree.
- (Interpretation/opportunity is folded into both, not a separate mode.)

The controlling object is a `c2.Agent` (`c2/pb/agent.proto`): `Host` (full nmap host), `User`,
`Process`, `WorkingDirectory`, `Channels[]`, `Tasks`, checkins, `Tool`, `Arch`, `IsDead`, `Burned`,
`Source`.

## Chosen shape — HUD on top, SA tree below

Two stacked sections. The **top** is the cockpit (Design B): the same `Banner` + `InfoPanes`
renderer credentials/scan/hosts already use, so it is consistent with the rest of `aims` and cheap
to build. The **bottom** is the novel part: a situational-awareness tree organized on a spatial
spine — **↑ upstream (how I'm reached) · ◈ here (the box I'm on) · ↓ downstream (what I project)**.

```
  ◈  TENSE_ROADWAY   msf · linux/amd64 · pid 112268 · cwd ~                          ● live · ↑ 3m ago · ⇕1

  comms      mtls://localhost:9002  ● next 30s · 1m ±30s          activity   2 pending · 1 running
  ────────────────────────────────────────────────────────────────────────────────────────────────────────

  ↑ upstream  teamserver ── mtls://localhost:9002  ● next 30s

  ◈ here      doors      22 ssh OpenSSH 9.6 ●     80 http nginx 1.18 ●     3306 mysql ◐ filtered
              windows    → 10.8.0.1:9002 mtls established

  ↓ reach     networks   lo 127.0.0.1/8 · no external NIC
              tunnels    socks :1080      fwd :8000 → 10.0.0.9:80
              scanners   nmap 10.0.0.0/24 · 42%
```

Pivoted example (where the spine earns its keep — deep position, real reach):

```
  ◈  web01   msf · linux/amd64 · www-data · cwd /var/www                             ● live · ↑ 3m ago · ⇕1

  comms      mtls://10.8.0.1:9002  ● next 12s · 1m ±30s          activity   2 pending · 1 running · 1 socks · 1 fwd · 1 scan
  ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

  ↑ upstream  teamserver ── mtls://10.8.0.1:9002        dmz-gw ⇄ web01 · reverse pivot · 3 hops

  ◈ here      doors      22 ssh OpenSSH 9.6 ●     80 http nginx 1.18 ●     3306 mysql ◐ filtered
              windows    → 10.8.0.1:9002 mtls (our C2)     → 10.0.0.9:445 smb established

  ↓ reach     networks   eth0 10.0.0.5/24 ● up · 3 known 9 new      eth1 192.168.50.7/24 ⚑ new segment      tun0 10.8.0.6/24 ● C2 route
              tunnels    socks :1080      fwd :8000 → 10.0.0.9:80
              scanners   nmap 10.0.0.0/24 · 42%
```

The `networks` leaf is the payoff: **eth1 into `192.168.50.0/24` is a segment you can only see
from this box** — the `⚑ new segment` flag is the "dual-homed, new territory" moment no flat info
dump surfaces. "To whom" is a **count at rest** (`3 known · 9 new`); the full neighbor list is a
drill-down (`aims agent info --net eth0`), not clutter in the overview.

### Visual language — wide, not tall

Use the operator's terminal width; keep it short vertically. Rules of the layout:

- **Spread across the width, don't stack.** Short peer lists (doors, networks, tunnels) pack
  **horizontally** on one line — the eye reads a band left-to-right instead of scrolling a skinny
  column. The HUD's two blocks (`comms`, `activity`) sit side by side for the same reason.
- **One blank line between bands, and that's the air.** No box borders, no per-row separators; a
  single thin rule divides HUD from spine. The whitespace budget is one line per band, not three.
- **A fixed label gutter.** Quiet lowercase labels (`↑ upstream`, `doors`, `networks`) sit in a
  narrow left gutter; content flows right across the width from a common column.
- **Summarize at rest, detail on demand.** Neighbor lists collapse to counts + a flag (`3 known
  9 new`, `⚑ new segment`); the per-host lines and full traceroute appear only when asked
  (`--net eth0`, `--route`, `--wide`).
- **One glyph per meaning, loud only for exceptions.** A single state dot (`●`/`◐`) and one warning
  flag (`⚑`); no `├─│└─` thicket. Color/weight is spent on liveness and warnings; nominal stays
  quiet.

### Why the spatial spine (the "previously unseen" bit)

No C2 renders the agent as a **position with a reach**. The three-band axis is the situational
awareness: *upstream* answers "how do I get here / lose this if it dies", *here* is the box itself
(doors = listeners in, windows = connections out), *reach* is everything projecting outward through
this agent (networks it bridges, tunnels, scanners). It reads top-to-bottom as your operational
blast radius — with room to breathe between each.

## Element catalog (what feeds each band)

| Band | Element | Source | Status |
|---|---|---|---|
| HUD | liveness, C2 health, jitter/interval, first/last/next checkin | `Agent` + active `Channel` | ✅ |
| HUD | tasks pending/running | `Agent.Tasks` / counts | ✅ |
| ↑ upstream | route back to operator / pivot parents | `Agent.Channels[].PeerID`+`Direction`, `Host.Trace` | ✅ (assembly) |
| ◈ here — doors | **open/listening ports+services on this host**, enumerated + tinted by state | `Agent.Host.Ports`/`Services` | ✅ |
| ◈ here — windows | this host's outbound / established connections (where the box reaches out) | **none** (no netstat/connection object) | ⚠ model gap |
| ◈ here | host essentials: OS, user/uid, cwd, hostnames | `Agent.Host` | ✅ |
| ↓ reach — networks | **NICs this box bridges** (name/CIDR/gw/up) + who's on each subnet ("to whom") | `Host.Addresses` (flat addrs only) + cross-domain host-by-CIDR query | ⚠ interface model gap; neighbors via `agentctx` |
| ↓ reach — tunnels | SOCKS proxies, port-forwards | **none** (hinted by `Channel.ProxyURL`/`LocalAddress`) | ⚠ model gap |
| ↓ reach — scanners | scans pivoting through this agent | `scan.Run` has **no** agent FK | ⚠ model gap |
| opportunity | creds for this host/user | `credential.WhereLoggedInHost` (designed, unimpl.) | ◐ |

## Model gaps (Tier "live through me")

1. **Tunnels** — add `repeated Tunnel Tunnels` to `Agent` (`Kind` socks|portforward, bind/remote
   addr, `Running`, optional `ChannelID`). Until then the `tunnels` branch renders `—`.
2. **Scanners-via-agent** — add `AgentID` (and/or `ChannelID`) FK to `scan.Run` so "scanned through
   implant X" is expressible; the `scanners` branch joins live `scan.Jobs` filtered by that FK.
3. **Connections / netstat (the `windows` leaf)** — the host record only holds nmap-derived open
   *ports* (doors, external view). It has no object for the host's own **listening sockets** or
   **established/outbound connections**. Add a `host.Connection` (proto laddr/raddr/state/proc) —
   and note that an agent runs *on* the box, so it can report **real sockets** (incl. localhost-only
   services a scan never sees), making `doors` authoritative and `windows` possible.
4. **Interfaces (the `networks` leaf)** — `Host.Addresses` is a flat list of addresses with no NIC
   name, netmask/CIDR, gateway, or up/down. A dual-homed box's second segment can't be expressed.
   Add a `host.Interface` (name, addr, cidr, gateway, mac, up); an agent enumerates `ip addr`
   authoritatively. **"To whom"** then derives per interface: query stored hosts whose address ∈
   the NIC's CIDR (the `cmd/agentctx` relevance layer), split known / unscanned; flag a CIDR with
   no scanned hosts as `⚑ NEW SEGMENT`. Degrades to just listing `Host.Addresses` until the object
   lands (a /24 can be assumed to still surface neighbors, minus gateway/up state).

The `windows`, `networks`-detail, `tunnels`, and `scanners` leaves all degrade cleanly (to `—` or a
flat address list), so a first version ships — **doors fully enumerated** — without any proto work.

## Rendering

- HUD: reuse `display.Banner` + `InfoPanes`/`KVLines` (credential/scan pattern) — no new engine.
- SA tree: `go-pretty/v6/list` (already in the module cache) for connectors, or a hand-rolled
  fixed 3-band emitter (the bands are fixed, only leaves vary — a plain emitter may read cleaner
  than a generic tree). Tint via existing `display` SGR constants + `FormatSmallID`.
- Consider sub-grouping / ordering leaves by relevance (per CLAUDE.md completion preference):
  neighbors "on-subnet first", doors "open before filtered".

## Command surface

- `aims agent info [id]` — pure renderer over `Agents.Read(id)`; defaults to `$AIMS_AGENT_ID` when
  brought, so bare `aims agent info` means "the agent I'm in".
- `--panel` / `--wide` — HUD-only or expanded pane layout; `--brief` — one-paragraph header only.
- `bring` prints the `--brief` header on entry (the "you are now here" snapshot); `aimsi info`
  calls the full thing.
- Shares vocabulary with the passive prompt segment: the prompt is this display's Tier 0–1
  compressed to one line.

## Open decisions

1. **"doors & windows" semantics** — doors = inbound listeners, windows = working egress? (assumed).
2. **Model gaps now or later** — spec `Tunnel` + `scan.Run.AgentID` up front, or ship with `—`.
3. **Tree renderer** — `go-pretty/v6/list` vs. a fixed 3-band hand emitter.
4. **Neighbors source** — reuse the scan "filter up" / agent-context relevance layer (`cmd/agentctx`).
</content>
</invoke>
