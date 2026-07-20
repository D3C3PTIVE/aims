# Value-typed completers — cross-scanner backlog

Scanner arguments are mostly **typed values**: a host, a port, a username, a wordlist file, a
network interface. When AIMS can name the type, the value should borrow a single reusable completer
rather than being re-implemented per scanner. `--script-args` (nmap NSE) is the first consumer (see
`run_complete.go:nseArgValueKind`), but the same value completers should wire into every scanner we
integrate (masscan, nuclei, ffuf, hydra, tcpdump, …) — a scanner's flag/arg surface just classifies
each slot to a type, and the type owns the completer.

This file is the prioritized list of which type completers to build/wire next.

## How this list was ranked ("time-test")

Two axes, not one:

1. **Frequency** — measured against the 703 deduplicated NSE `@args` across the 604 locally
   installed scripts, as a stand-in for "how often does this value type actually appear". Snapshot:

   | kind      | count | status                                             |
   |-----------|------:|----------------------------------------------------|
   | freeform  |   634 | (breaks down below into the candidates)            |
   | file      |    26 | ✅ `carapace.ActionFiles()`                         |
   | host      |    22 | ✅ `completeTargets` (DB, locality-grouped)         |
   | username  |    21 | ✅ `credentials.CompleteByUsername`                 |

   Freeform, mined by the arg's last dotted/dashed segment:

   | shape                                   | ~count | candidate type            |
   |-----------------------------------------|-------:|---------------------------|
   | `url` / `uri` / `path` / `basepath`     |    ~84 | **web URL / endpoint**    |
   | `timeout` / `threads` / `limit` / `size`|    ~80 | numeric — *no completer*  |
   | `password` / `pass` / `passvar`         |    ~23 | **credential secret**     |
   | `domain` / `withindomain` / `domains`   |    ~21 | **domain**                |
   | `cmd` / `commands` / `method` / `query` |    ~32 | free-form — *no completer*|
   | `interface`                             |     13 | **network interface**     |
   | `ip` / `address` / `hostname` / `port`  |    ~18 | fold into **host** / **port** |

2. **Cross-scanner reuse × completability × latency.** Frequency alone over-weights web args (which
   are hard to complete well) and numeric args (which shouldn't be completed at all). A type earns a
   completer only if it is (a) reused by *several* scanners, (b) drawn from a knowable/finite set,
   and (c) cheap on the hot path — favor local or cached sources and avoid uncapped whole-DB reads
   (see `cmd/aims/BENCH_COMPLETIONS.md`: an uncapped host read is ~275 ms at 1k rows *per keystroke*
   without the cache).

## Shortlist — build these few

Ordered by (reuse × completability × frequency), highest first.

1. **Network interface** — `completeInterface()`, local `net.Interfaces()` (+ loopback/`any`).
   Freq 13, but the real case is reuse: essentially every packet tool has one (nmap `-e`, masscan
   `-e`/`-i`, tcpdump `-i`, arp-scan `-I`, bettercap `-iface`, responder `-I`). Finite local set,
   ~zero latency, no RPC. **Cheapest high-reuse win — do first.**

2. **Port / service — ✅ BUILT** (`completePortValue`, run_complete.go). Wired into `-p` and NSE
   `*.port`. Merges the **DB's known open ports** (aggregated by number, described by service +
   host-count) with a curated well-known set so it's useful against an empty DB. First real consumer
   of the relevance layer beyond targets: a port takes the highest relevance of any host exposing it,
   so ports open on the agent's host, then its subnet, float to the top ("what's open around here").
   Cached, cache key carries the agent id.

3. **Credential secret — ✅ BUILT** (`completeSecret`, run_complete.go). Wired into NSE
   `*.password`/`*.passphrase` (new "secret" kind); reusable by any auth/brute tool. Offers the
   plaintext secret as the value (that's the point of reuse — cf. Sliver's
   GetPlaintextCredsByHashType), grouped by credential type (PrivateType), described by who it
   belongs to. First `RelevanceOfHostID` consumer: credentials with a login on the agent's host
   (via the Logins service) are promoted to the top. Cached, key carries the agent id.

4. **Web URL / endpoint** — `completeWebURL(con)`. Highest frequency (~84) but hardest: synthesize
   `scheme://host:port/` from the DB's known **web services** (http/https ports on known hosts)
   rather than trying to complete free text. Reuse across web scanners (nikto, nuclei, ffuf,
   gobuster, sqlmap). Build after 1–3; more moving parts.

5. **Domain** — `completeDomain(con)`. Freq ~21; reuse across DNS/recon tools (dnsrecon, amass,
   fierce, NSE `dns-*`). Source: hostnames already in the DB, or a dedicated domain set. Lower
   urgency — partly served by reusing host/target candidates today.

## Explicitly *not* worth a completer

Numeric/duration (`timeout`, `threads`, `limit`, `size`, `maxdepth`) and free-text (`cmd`,
`method`, `query`, `format`, `mode`) — ~110 args combined. No knowable value set; a completer would
only get in the way. At most, offer a described hint of the default. Leave free-form.

## Wiring pattern

Each type is one scanner-agnostic function returning a `carapace.Action`; a scanner classifies its
slot to a type and dispatches — exactly as `nseArgValueKind` → `completeNSEArgValue` does for NSE.
Keep the classifier per-scanner (arg/flag names differ), the completers shared.

See also: `SCAN.md` (completion contract), `run_complete.go` (nmap consumer),
`cmd/aims/BENCH_COMPLETIONS.md` (latency budget for the DB-backed ones).

---

# Agent-context awareness — "filter-up"

When a context is loaded (`aims bring <agent>`), the relevant candidates should **float to the top**
of the completion lists — credentials for that host/user, hosts on the agent's subnet, that machine's
local services — rather than being lost in the full set. This is *promotion*, not filtering-out.

## Grounding (verified in the code — shapes the whole design)

- **There is no in-process "current agent".** `client.Client` holds only service stubs; nothing
  tracks a selected agent. The loaded context lives entirely in the **shell env** that the `bring()`
  function exports: `AIMS_AGENT_ID`, `AIMS_AGENT_NAME/TOOL/CWD/ROUTE/PENDING`, `AIMS_CONTEXT_DEPTH`
  (`cmd/bring/shell/templates/zsh.tmpl`). A completion runs as a subprocess of that shell, so it
  inherits them. `bring` pushes/pops a stack; `leave` pops.
- **Credentials are not a Host association.** They attach to a host through `login.HostId`
  (`credential/pb/login.proto`). Get a host's creds via the Logins/Creds service filtered by HostId,
  not by walking `Host.*`.
- **There is no CIDR/subnet field anywhere** — addresses are bare IPs (`network.Address` = Addr,
  Type, Vendor). "Same subnet" must be *derived* (assume a mask / compare prefixes). Route proximity
  is available instead via `Host.Distance` (hop count) and `Host.Trace.Hops`.
- The c2 read path (`server/c2/agent.go:Preloads`) loads `Agent.Host` but **not** `Host.Users/
  Addresses/Ports`. To use those either extend that preload set or take `Host.Id` and do a follow-up
  Hosts read (whose ingest preloads already reach Ports/Trace).

## Shape

1. **Cheap context reader** — `agentctx.Current() (Ctx, bool)`: pure `os.Getenv`, no RPC. Gives the
   id + the display snapshot (name/tool/cwd/route) for free.
2. **Host resolver** — `agentctx.CurrentHost(con)` (BUILT): `Agents.Read(id)` → `Host.Id` →
   `Hosts.Read`. The agent is the base — "the agent lies on a host". Callers cache by keying their
   completion cache on the agent id (as `completeTargets` does), so it's one fetch per context.
3. **Promotion, applied per completer** via the classification layer below:
   - **hosts / targets** → the agent's own host = a `this agent` group; same-subnet hosts (derived
     from the agent host's addresses) = `nearby (agent subnet)`; then today's locality groups.
   - **credentials / secret** → creds with `HostId == agentHost.Id` (or the agent's `User`) =
     `for this host/user`, first.
   - **services / port / URL** → the agent host's own ports / web endpoints promoted.
   - **interface** → the exception: not agent-context-dependent (see its design).

# The classification layer — BUILT (`cmd/agentctx/relevance.go`)

The shared relevance grouping is factored into agentctx so every context-aware completer promotes
identically:

- **Relevance** — `AgentHost` (the agent's host, or an entity attached to it) › `Nearby` (its
  subnet) › `Normal`. `RelevanceOfHost(h, agentHost)` classifies a host (id match, then the
  netmask-free subnet heuristic); `RelevanceOfHostID(id, agentHost)` classifies an entity that only
  references a host by id (a credential's HostId, a service's host) — AgentHost-or-Normal, since an
  id carries no address.
- **Tags & order** — `Relevance.Tag()` gives the shared group label (`this agent's host`,
  `agent subnet (nearby)`, or "" for Normal); `PromotedOrder(intrinsic…)` prepends the relevance
  groups to a completer's own group order, so they render first everywhere.
- **Chosen shape: dedicated relevance groups — not a `relevance ▸ group` composite, and not a
  post-hoc `TagF` decorator.** A relevant candidate goes into its relevance group; everything else
  keeps its intrinsic group. carapace `TagF` only sees the candidate *string* and overrides the tag,
  so it would clobber the intrinsic grouping and can't reach the domain object; instead the completer
  calls the classifier while *building* its groups (relevance tag if any, else its own). Simpler and
  correct. `completeTargets.targetTag` is the reference consumer.
- **Efficiency** — one cached agent-host fetch per context (not per keystroke); the subnet test is a
  prefix compare; no extra RPC on the hot path.

Consumers wired: `completeTargets` (host id + subnet), `completePortValue` (port takes the closest
host's relevance), and `completeSecret` (first `RelevanceOfHostID` user — creds with a login on the
agent host). Still to wire (same pattern): web-URL, subnet.

# Interface completion — local (built) + agent-host (design)

Two distinct sources, and the distinction is the point:

- **Local interfaces — built** (`completeInterface`, run_complete.go). `net.Interfaces()` on the box
  the completion process runs on, grouped up/down, described by addresses. This is the correct
  source for nmap `-e`, which selects a *local* interface to send from, and it is context-independent
  by nature — the loaded agent may be a remote machine, so its NICs are not the operator's. Wires
  into `-e` and NSE `*.interface`, and reusable by masscan/tcpdump/arp-scan/bettercap.
- **Agent-host source — design.** When a context is loaded, surface the *agent host's* network
  identity. Model caveat: hosts store `network.Address` (Addr/Type/Vendor) — **bare addresses, no
  interface names** — so the agent-host analog offers the host's addresses / subnet, not named NICs.
  That is really the host/address axis, so it is delivered by the classification layer **promoting
  the agent host's addresses** in the target/host/address completers (a target, a source address, an
  NSE host arg), rather than a second literal interface list.

So: `completeInterface` stays local. If AIMS later stores per-host interface *records* (names), it
gains an agent-host tag group (`local` vs `this agent's host`) and becomes a concrete consumer of
the Relevance×Group layer; until then, "the current agent's addresses" is served by address-valued
completers under context promotion.

# Design: web-URL completer

- `completeWebURL(con)` — synthesize `scheme://host:port/` from the DB's **web services** (http/https
  ports on known hosts; reuse `cmd/services` / `network`), rather than completing free text. Cap +
  cache. Add a `url` kind to `nseArgValueKind` so `*.url`/`*.uri`/`*.path` args route here.
- Context: promote the **current agent host's** web endpoints to the top, via the classification
  layer above.
- Highest frequency (~84 NSE args) but the most moving parts — build after interface + port.

# Design: smart subnet completer (context-aware)

Offer CIDR *subnets* as scan targets, not just single hosts — nmap/masscan/zmap all accept
`10.0.0.0/24`, and "sweep the network the agent sits on" is one of the most common pivot actions.
This reuses the netmask-free `sameSubnet` heuristic and the agent-host resolution already built for
target promotion.

- **Source — cluster the DB's known host addresses** into prefixes (/24 for IPv4, /64 for IPv6, the
  same heuristic `sameSubnet` uses). Each cluster becomes a candidate CIDR, described by
  "N known hosts · <locality>". So a partially-discovered network becomes a one-Tab full sweep.
- **Context seed & promotion** — the subnet(s) the **current agent's host** sits on float to the top
  (`agent subnet`), derived from the agent host's own addresses *even when few hosts are known there
  yet*, so you can sweep the pivot network before discovery. A second seed: the agent's last-hop
  gateway (`Host.Trace.Hops` / `AIMS_AGENT_ROUTE`) implies a subnet worth sweeping.
- **"Smart" ranking** — order by (1) contains the agent host, (2) host density (more known hosts =
  more confirmed-reachable), (3) locality (private nets are the juicy internal targets; a public /24
  is noisy — deprioritize). Tag via the Relevance×Group layer: `agent subnet` › `dense private` ›
  `sparse`.
- **Guardrail** — never fabricate an internet-wide sweep: cap the offered prefix (only /24-and-
  smaller for v4, /64 for v6) and `log()` anything dropped, so a broad candidate is never silently
  implied.
- **Wiring** — an alternative in the target slot (a CIDR is a valid nmap target) and any CIDR-taking
  flag (`--exclude`, target files). Cap + cache; classifier already routes address/target slots.

# Idea: type-list completers (enum vocabularies)

Some value slots take a token from a fixed vocabulary — a hash type, a protocol, an output format, a
service name. These make cheap, high-precision completers: a static described list, no DB, no
context. Worth harvesting a vocabulary we already have rather than hand-typing it.

- **Hash types — the motivating case.** AIMS's `completeHashType` offers 4 coarse tokens; the Sliver
  fork's `clientpb.HashType` enum is the full **hashcat-mode catalog (124 values: MD5=0, SHA1=100,
  SHA2-256=1400, …)**, and Sliver exposes `GetCredsByHashType` / `GetPlaintextCredsByHashType` /
  `CredsSniffHashType`. Rich and standard — but it lives in Sliver's protobuf, and AIMS is the
  *upstream* model, so it must not be imported downward. Options: (a) copy the (name → mode) list
  into an AIMS static table so an AIMS hash-type slot can offer all 124; (b) keep the rich hash-type
  completer on the Sliver side, where the enum already lives, and wire it into AIMS value slots
  there. `completeSecret` already groups by the coarse AIMS `PrivateType`; a mode-level completer is
  complementary, for slots that name a hashcat mode.
- **General pattern.** When a new scanner arg is a *type token*, first look for an existing
  enum/list (a proto enum, an `/etc/*` file, a tool's `--list` output) before hand-writing
  candidates. Describe each token; tag by family when the list is large (as the 124 hash modes
  would want).
