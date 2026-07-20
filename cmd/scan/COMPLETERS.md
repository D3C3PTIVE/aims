# Value-typed completers — cross-scanner notes

Scanner arguments are mostly **typed values**: a host, a port, a username, a wordlist file, an
interface, a URL, a domain. When AIMS can name the type, the value borrows one reusable completer
instead of being re-implemented per scanner. `--script-args` (nmap NSE) is the first consumer
(`run_complete.go:nseArgValueKind` → `completeNSEArgValue`); the same completers should wire into
every scanner we add (masscan, nuclei, ffuf, hydra, …) — the scanner classifies each slot to a type,
the type owns the completer.

## Wiring pattern

Each type is one scanner-agnostic function returning a `carapace.Action`. A scanner classifies its
slot to a type and dispatches, exactly as `nseArgValueKind` → `completeNSEArgValue` does. Keep the
classifier per-scanner (arg/flag names differ), the completers shared. DB-backed completers go
through the teamclient RPC (never the DB directly), are cached (`aims.CacheCompletion`), and are
wrapped in `guard(...)` so a panic degrades to a message instead of hanging the shell.

## Built — the value types

All in `run_complete.go`, all cross-scanner:

| type          | function                     | source                                                        |
|---------------|------------------------------|---------------------------------------------------------------|
| file          | `carapace.ActionFiles()`     | filesystem                                                    |
| host / target | `completeTargets`            | DB hosts, locality-grouped, agent-promoted; excludes typed args |
| subnet        | `groupedSubnets`             | DB addresses clustered /24-/64 + agent/gateway seeds (folded into targets) |
| port          | `completePortValue`          | DB open ports (by number) + curated well-known set           |
| username      | `credentials.CompleteByUsername` | DB credentials                                            |
| secret        | `completeSecret`             | DB credential plaintext, grouped by type                     |
| interface     | `completeInterface`          | local `net.Interfaces()`, up/down (not agent-context — local NICs) |
| web URL       | `completeWebURL`             | synthesized `scheme://host[:port]/` from DB web services + http-enum paths |
| domain        | `completeDomain`             | parent zones of DB hostnames                                 |

Two cross-cutting mechanisms these share:

- **Agent-context promotion** (`cmd/agentctx`). When a context is loaded (`aims bring <agent>`), the
  relevant candidates float to the top — the agent host's own hosts/ports/creds/URLs/zones, then its
  subnet's — via the `Relevance` × `PromotedOrder` classification layer, not by filtering others out.
  The loaded agent lives only in shell env (`AIMS_AGENT_*`, exported by `bring`); `agentctx.Current`
  reads it, `agentctx.CurrentHost` resolves the host once per context (the cache key carries the
  agent id). Details in `cmd/agentctx/relevance.go`.
- **Sub-categorized groups.** Candidates carry sub-category tags (locality, scheme, credential type,
  registered-vs-subdomain, …) — the axis that costs the operator most to eyeball in a flat list.

## Not worth a completer

Numeric/duration (`timeout`, `threads`, `limit`, `size`) and free-text (`cmd`, `method`, `query`,
`format`) — no knowable value set; a completer only gets in the way. Leave free-form; at most hint
the default.

## Type-list completers (enum vocabularies) — noted, mostly *don't*

A value slot taking a token from a fixed vocabulary (hash type, protocol, output format) makes a
cheap, precise, static completer. Build one only when (a) the vocab is stable/small *or* the tokens
are obscure enough that completion earns its keep, (b) no existing tool completion already covers it
(many tools ship completion a bridge can tap, as we do for nmap's zsh `_nmap`), and (c) it can live
at the right layer without a bad dependency.

Motivating non-example: **do not copy Sliver's 124-value hashcat-mode `HashType` enum into AIMS** —
it is *downstream* of AIMS (the upstream model must not import it) and drifts every hashcat release.
Prefer a carapace-bin/bridge spec for hashcat, or a mode completer Sliver-side where the enum lives.
For **AIMS-native type slots** (its own `PrivateType`, nmap scan types, output formats) a small
curated described list is fine — what `completeHashType` and the curated nmap flag set already do.

See also: `SCAN.md` (completion contract), `run_complete.go` (nmap consumer),
`cmd/aims/BENCH_COMPLETIONS.md` (latency budget for the DB-backed completers).
