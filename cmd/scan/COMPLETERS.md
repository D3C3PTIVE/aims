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

## File layout

The completer code is split by role:

- `run_complete.go` — the scanner-specific glue: the nmap/masscan positional-tail dispatchers, the
  shared plumbing (`guard`, `cachedCompleter`, `cachedHostCompleter`, `renderGroups`), the curated
  flag sets, and the NSE script/args machinery (`nseArgValueKind` → `completeNSEArgValue`).
- `run_complete_values.go` — the scanner-agnostic value-typed completers below and their
  collect/group/desc helpers.

## Built — the value types

All cross-scanner, in `run_complete_values.go`:

| type          | function                     | source                                                        |
|---------------|------------------------------|---------------------------------------------------------------|
| file          | `carapace.ActionFiles()`     | filesystem                                                    |
| host / target | `completeTargets`            | DB hosts, locality-grouped, agent-promoted; excludes typed args |
| subnet        | `groupedSubnets`             | DB addresses clustered /24-/64 + agent/gateway seeds (folded into targets) |
| port (number) | `completePortValue`          | DB open ports (by number) + curated well-known set           |
| port (nmap `-p`) | `completePortSpec`        | the above + a "service names" group (nmap-services tokens; masscan/NSE stay numeric) |
| username      | `completeUsername`           | DB credentials, paired with their secret (type/realm), agent-promoted |
| secret        | `completeSecret`             | DB credential plaintext, grouped by type, agent-promoted     |
| MAC           | `completeMAC`                | DB `Host.MAC` + type=="mac" addresses (vendor-described), agent-promoted |
| interface     | `completeInterface`          | local `net.Interfaces()`, up/down (not agent-context — local NICs) |
| source address| `completeSourceAddr`         | local interface addresses (up, non-loopback) — nmap `-S`, masscan `--source-ip`/`--adapter-ip` |
| web URL       | `completeWebURL`             | synthesized `scheme://host[:port]/` from DB web services + http-enum paths |
| domain        | `completeDomain`             | parent zones of DB hostnames                                 |

The **username** and **secret** completers are the two halves of the credential pair: each describes
its counterpart (a username by the secret it carries; a secret by its owner) so either axis picks
the same login knowingly. **MAC** is consumed by nmap `--spoof-mac`, masscan `--router-mac`/
`--adapter-mac`/`--spoof-mac`, and NSE `*.mac`. The nmap `-p` **service-names** group is nmap-only —
masscan's `-p` is numeric, so it uses `completePortValue`. **interface** and **source address** are
local by design (they name the tooling box's NICs/IPs, not the possibly-remote loaded agent).

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

## Resolved design questions (closed — reopen only if the premise changes)

- **Agent-host interface source — closed.** The idea was, with a context loaded, to surface the
  *agent host's* named NICs. Hosts store bare addresses (`network.Address` = Addr/Type/Vendor), **no
  interface-name records**, so there is nothing to list as agent-host interfaces; the agent host's
  addresses/subnet are already promoted in the target, subnet and source-address completers.
  `completeInterface` stays local. Reopen only if AIMS starts storing per-host NIC records.

- **Type-list completers (enum vocabularies) — closed for the scan surface.** The rule stands: build
  a static described list only when the vocab is stable/small *or* the tokens are obscure, no existing
  tool completion covers it, and it sits at the right layer. In the scan surface no un-served slot
  remains — scan types and output formats already live in the curated nmap/masscan flag sets, and
  `PrivateType` in `completeHashType`. In particular **do not copy Sliver's 124-value hashcat-mode
  `HashType` enum into AIMS**: it is *downstream* (the upstream model must not import it) and drifts
  each hashcat release; a hashcat mode completer belongs to a carapace-bin/bridge spec or the Sliver
  side where the enum lives. Keep this as guidance for future scanners, not as pending work.

See also: `SCAN.md` (completion contract), `run_complete.go` / `run_complete_values.go` (nmap +
masscan consumers), `cmd/aims/BENCH_COMPLETIONS.md` (latency budget for the DB-backed completers).
