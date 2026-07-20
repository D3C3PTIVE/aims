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

4. **Web URL / endpoint — ✅ BUILT** (`completeWebURL`, run_complete.go). Wired into NSE `*.url`/
   `*.uri` (new "url" kind). Synthesizes `scheme://host[:port]/` from DB web services (scheme from
   the nmap `ssl` Tunnel / service name / TLS port; host from the service vhost, else a hostname,
   else an address; default port omitted, IPv6 bracketed). Named http/https services plus a guessed
   tier (open web-ish ports without a fingerprint, flagged). Grouped by scheme, agent host + subnet
   endpoints promoted; NoSpace('/') so the path can be extended. Cached, key carries the agent id.

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
host's relevance), `completeSecret` (first `RelevanceOfHostID` user — creds with a login on the
agent host), `completeWebURL` (endpoint takes its host's relevance), and `groupedSubnets` (subnets
via `SubnetOf` + agent/gateway seeds, folded into the target slot). All value types now wired.

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

# Web-URL completer — ✅ BUILT

Shipped scope (T1 + T2, vhost-preferred, paths deferred):
- **Sources** — T1 named http/https services (authoritative) + T2 guessed web-ish ports open without
  a fingerprint (tagged `web (guessed ports)`).
- **Scheme** — nmap `ssl` Tunnel / https-ish service name / well-known TLS port, else http.
- **Host** — service vhost (`Service.Hostname`) › a host hostname › an address; IPv6 bracketed;
  default port omitted.
- **Only `url`/`uri` route here.** `path`/`basepath` stay free-form — they want a path component,
  not a full URL.
- Grouped by scheme, agent host/subnet endpoints promoted via the relevance layer; `NoSpace('/')`.
- **T3 path enrichment — ✅ BUILT.** `pathsFromPort` pulls the paths NSE actually discovered from a
  port's `http-*` script output (mainly `http-enum`), in nmap's `|   /path: label` shape, and offers
  `scheme://host/path` under a `discovered paths` group (ranked just below the agent-context groups,
  above the synthesized roots). Restricted to `http-*` script Ids + the path shape to avoid false
  positives; deduped and capped at 40 so a big enumeration can't flood completion. Real known-good
  paths, not guesses — the highest-value URL candidates when a scan has run them.

# Smart subnet completer — ✅ BUILT (`completeSubnet` via `groupedSubnets`, run_complete.go)

Offers CIDR *subnets* as scan targets, **folded into the `scan run nmap` target slot** alongside
individual hosts (a CIDR is a valid nmap target) — `cachedTargets` batches host groups + subnet
groups. Reuses `agentctx.SubnetOf` (new /24-/64 companion to `sameSubnet`) and the agent-host
resolution.

- **Source** — cluster the DB's host addresses into /24 (v4) / /64 (v6) prefixes (`SubnetOf`); each
  cluster is a candidate CIDR described by host-count + locality. A partially-discovered network
  becomes a one-Tab sweep.
- **Agent seeds** — the agent host's own subnets *and* its last-hop gateway (second-to-last
  `Host.Trace.Hops`) are seeded and marked `agent subnets`, offered even with no other host known
  there ("sweep to discover").
- **Ranking** — `agent subnets` › `private subnets (dense)` (≥4 known hosts) › `private subnets` ›
  `routable subnets` (last); within a group, density desc.
- **Guardrail** — prefixes capped at /24 and /64 (`SubnetOf` never widens), so `<TAB>` can't propose
  an internet-wide sweep. Sparse public /24s are shown but sink to the routable group (no `--all`
  gate — with `DisableFlagParsing` there's no real bound flag to hang it on).
- Cached with the target read (one DB read, key carries the agent id).

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

## For / against (verdict: selectively worth it; the hashcat-124 case argues *against* copying)

**For:**
- **Precision** — a fixed vocabulary means every candidate is valid; no wrong suggestions.
- **Cheap** — static list, no DB/RPC/context, trivial latency, no cache.
- **Memory aid** — surfaces accepted values the operator won't recall (124 hashcat modes, output
  formats, scan types), each with a one-line description.
- **Cross-tool reuse** — one vocabulary serves many tools (hashcat modes → hashcat/john; protocols →
  many).

**Against:**
- **Drift** — a copied list chases upstream (hashcat adds modes every release); we'd own the
  staleness.
- **Dependency direction** — the richest list (Sliver's `HashType`) is *downstream*; AIMS is the
  upstream model and must not import it. Copying inverts ownership of the canonical list.
- **Marginal for common tokens** — for values the operator knows (`ntlm`, `tcp`) completion saves
  little; the value is in the obscure long tail only.
- **Noise** — a 124-item dump overwhelms unless tag-grouped by family — more design.
- **Redundant with the tool's own completion** — many tools ship completion (hashcat, carapace-bin
  specs) a bridge already taps (as we do for nmap's zsh `_nmap`); building our own duplicates it.

**Verdict.** Build a type-list completer only when (a) the vocab is stable/small *or* the value is
high (obscure tokens), (b) no existing tool completion covers it, and (c) it can live at the right
layer without a bad dependency. For **hashcat modes specifically: do not copy 124 values into
AIMS** — prefer a carapace-bin/bridge spec for hashcat, or a mode completer on the Sliver side where
the enum already lives. For **AIMS-native type slots** (its own `PrivateType`, nmap scan types,
output formats) a small hand-curated described list is worth it — exactly what `completeHashType`
(4 tokens) and the curated nmap flag set already do.
