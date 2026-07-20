# Value-typed completers — cross-command notes

Command arguments are mostly **typed values**: a host, a port, a username, a wordlist file, an
interface, a URL, a domain. When AIMS can name the type, the value borrows one reusable completer
instead of being re-implemented per command. Each type is one scanner- and command-agnostic function
in this package (`cmd/completers`); a caller classifies its slot to a type and dispatches to the
shared completer. The scanners (`cmd/scan`) were the first consumers; the same completers now wire
into any command that has a typed slot (e.g. `credentials add --realm` → `completers.Domain`).

## Why this is its own package

The value types are not scan-specific — a realm *is* a domain, a `--source-ip` *is* a local address —
so the completers live in `cmd/completers`, a sibling of `cmd/display` / `cmd/agentctx`, importable by
every command subtree. This is ordinary Go package reuse: it is **not** what the carapace `_carapace`
bridge does. That bridge crosses *binary* boundaries (it exposes AIMS's completions to shells / other
carapace-aware tools, and lets AIMS consume an external binary's completion, e.g. `bridge.ActionZsh("nmap")`
in `cmd/scan`). Sharing a Go completer function between two AIMS subcommands is a package-level concern
the bridge has nothing to say about — hence this package.

## Wiring pattern

Each type is one exported function returning a `carapace.Action`. A caller classifies its slot to a
type and dispatches. The scanners keep a per-scanner classifier (arg/flag names differ) — nmap's
`nseArgValueKind` → `completeNSEArgValue`, masscan's preceding-token switch — while the completers
themselves are shared here. DB-backed completers go through the teamclient RPC (never the DB directly),
are agent-scoped cached (`aims.CacheCompletion`), and are wrapped in `Guard(...)` so a panic degrades
to a message instead of hanging the shell.

## File layout

- `plumbing.go` — the shared substrate: `Guard` (panic→message), `cachedCompleter` (agent-scoped
  cache + connect), `cachedHostCompleter` (adds the `Hosts.Read` + agent-host resolve), `renderGroups`
  (tag→ordered tagged groups → Batch). `Guard` is exported because the scan dispatchers wrap their
  top-level callback in it; the other three are internal to the value completers.
- `values.go` — the value-typed completers below and their collect/group/desc helpers.
- `cmd/scan/run_complete.go` — the scanner-specific glue that *consumes* this package: the nmap/masscan
  positional-tail dispatchers, the curated flag sets, and the NSE script/args machinery.

## Built — the value types

All exported from `cmd/completers`, all cross-command:

| type          | function                | source                                                        |
|---------------|-------------------------|---------------------------------------------------------------|
| file          | `carapace.ActionFiles()`| filesystem (not in this pkg — the carapace builtin)          |
| host / target | `Targets`               | DB hosts, locality-grouped, agent-promoted; excludes typed args |
| subnet        | `groupedSubnets`        | DB addresses clustered /24-/64 + agent/gateway seeds (folded into targets) |
| port (number) | `PortValue`             | DB open ports (by number) + curated well-known set           |
| port (nmap `-p`) | `PortSpec`           | the above + a "service names" group (nmap-services tokens; masscan/NSE stay numeric) |
| username      | `Username`              | DB credentials, paired with their secret (type/realm), agent-promoted |
| secret        | `Secret`                | DB credential plaintext, grouped by type, agent-promoted     |
| MAC           | `MAC`                   | DB `Host.MAC` + type=="mac" addresses (vendor-described), agent-promoted |
| interface     | `Interface`             | local `net.Interfaces()`, up/down (not agent-context — local NICs) |
| source address| `SourceAddr`            | local interface addresses (up, non-loopback)                 |
| web URL       | `WebURL`                | synthesized `scheme://host[:port]/` from DB web services + http-enum paths |
| domain        | `Domain`                | parent zones of DB hostnames                                 |

The **username** and **secret** completers are the two halves of the credential pair: each describes
its counterpart (a username by the secret it carries; a secret by its owner) so either axis picks the
same login knowingly. **interface** and **source address** are local by design (they name the tooling
box's NICs/IPs, not the possibly-remote loaded agent).

## Consumers (who dispatches to what)

- **`cmd/scan` nmap** — `--script`→NSE, `-e`→`Interface`, `-p`→`PortSpec`, `--spoof-mac`→`MAC`,
  `-S`→`SourceAddr`, target slot→`Targets`; NSE `key=value` values via `completeNSEArgValue`.
- **`cmd/scan` masscan** — `-p`/`--ports`→`PortValue`, `-e`/`--interface`/`--adapter`→`Interface`,
  `--router-mac`/`--adapter-mac`/`--spoof-mac`→`MAC`, `--source-ip`/`--adapter-ip`→`SourceAddr`,
  `--exclude`/`--range`→`Targets`, file flags→`ActionFiles`.
- **`cmd/credentials` add** — `--realm`→`Domain` (an AD/Kerberos realm is its DNS domain); `--username`
  and `--hash-type` keep their local credential completers.

Non-value completers wired alongside these: `bring <agent-id>` reuses `c2.CompleteByID` (the live
agents completer, so the id you Tab is the one `agents show` accepts); `hosts add --file` and
`import --format` are plain `ActionFiles` / described-enum flag completions.

Two cross-cutting mechanisms the value completers share:

- **Agent-context promotion** (`cmd/agentctx`). When a context is loaded (`aims bring <agent>`), the
  relevant candidates float to the top — the agent host's own hosts/ports/creds/URLs/zones, then its
  subnet's — via the `Relevance` × `PromotedOrder` classification layer, not by filtering others out.
  The loaded agent lives only in shell env (`AIMS_AGENT_*`); `agentctx.Current` reads it,
  `agentctx.CurrentHost` resolves the host once per context (the cache key carries the agent id).
- **Sub-categorized groups.** Candidates carry sub-category tags (locality, scheme, credential type,
  registered-vs-subdomain, …) — the axis that costs the operator most to eyeball in a flat list.

## Not worth a completer

Numeric/duration (`timeout`, `threads`, `limit`, `size`) and free-text (`cmd`, `method`, `query`,
`format` values, `--realm-key`, credential `--password`/`--hash`) — no knowable value set; a completer
only gets in the way. Leave free-form; at most hint the default. Bool flags need no completion (carapace
handles them).

## Resolved design questions (closed — reopen only if the premise changes)

- **Agent-host interface source — closed.** Hosts store bare addresses (`network.Address` =
  Addr/Type/Vendor), **no interface-name records**, so there is nothing to list as agent-host
  interfaces; the agent host's addresses/subnet are already promoted in the target, subnet and
  source-address completers. `Interface` stays local. Reopen only if AIMS starts storing per-host NICs.

- **Type-list completers (enum vocabularies) — closed for the scan surface.** Build a static described
  list only when the vocab is stable/small *or* the tokens are obscure, no existing tool completion
  covers it, and it sits at the right layer. Scan types and output formats already live in the curated
  nmap/masscan flag sets, `PrivateType` in `completeHashType`, serialization in `import --format`. In
  particular **do not copy Sliver's 124-value hashcat-mode `HashType` enum into AIMS**: it is
  *downstream* (the upstream model must not import it) and drifts each hashcat release; a hashcat-mode
  completer belongs to a carapace-bin/bridge spec or the Sliver side where the enum lives.

See also: `SCAN.md` (completion contract), `cmd/scan/run_complete.go` (nmap + masscan consumers),
`cmd/aims/BENCH_COMPLETIONS.md` (latency budget for the DB-backed completers).
