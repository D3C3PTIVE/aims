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

2. **Port / service** — `completePortValue(con)`. Universal (`-p` on every port scanner, plus NSE
   `*.port`). Two sources to merge: named services (a static well-known list) and the **DB's known
   open ports** per host (`cmd/services` already models these) — the latter is genuine AIMS value.
   Must be capped/cached on the hot path.

3. **Credential secret** — `completeSecret(con)`. Freq ~23; reuse across every auth/brute tool
   (hydra, medusa, NSE `*-brute`). AIMS's whole point is credential reuse, so offering known
   passwords/hashes from the creds store is on-mission. Needs a creds-by-secret completer alongside
   the existing by-username/by-id. Sensitive — gate on the same RPC path, never touch the DB direct.

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
