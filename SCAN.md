# AIMS — The Scan Domain & Scanner-Plug Substrate

> Written 2026-07-19. Companion to [`CLAUDE.md`](./CLAUDE.md) (architecture),
> [`STATE.md`](./STATE.md) (build/impl state), [`ROADMAP.md`](./ROADMAP.md) (re-entry plan)
> and [`DISPLAY.md`](./DISPLAY.md) (rendering). This doc explains **the scan data model and
> the philosophy nmap invented for it** (Part A), maps **what is built vs. what is latent**
> (Part B), and sketches **how to turn the model into a universal scanner-plug substrate**
> (Part C) — the untapped potential of this domain. It designs *plug points*, not a full API.

---

## Part A — The philosophy nmap invented (the thing to preserve)

nmap's XML output is not a "results file." It is a **timestamped record of a probing run
that carries its own evidence**. Four principles are baked into that format, and AIMS's
proto (`scan/pb/scan.proto`, `scan/pb/result.proto`, `scan/pb/nmap/nmap.proto`) already
mirrors all four — this is why the model is worth building on rather than replacing.

1. **Every assertion carries its evidence and its confidence.**
   A port is not `open` — it is `open` *because* `reason="syn-ack" reason_ttl=64`. An OS is
   not "Linux" — it is a ranked list of `OSMatch{Name, Accuracy}`. The model never states a
   bare fact; it states *fact + why + how-sure*.
   → In AIMS: `host.Status{State, Reason, ReasonTTL}`, `host.OSMatch.Accuracy`,
   `host.ExtraPort.Reasons[]`.

2. **Summarize the boring, detail the interesting.**
   nmap never enumerates 65,535 ports; it details the interesting ones and collapses the
   rest into `<extraports state="filtered" count="998">`. Scanning surfaces *signal*, it does
   not dump the world.
   → In AIMS: `host.Host.ExtraPorts` with counted `Reasons`.

3. **A scan is a temporal run with provenance, not a snapshot.**
   `<nmaprun>` records `scanner`, `args`, `version`, `start`, `scaninfo`; then emits
   `taskbegin` → `taskprogress` → `taskend` *as it runs*; then finalizes `runstats`.
   → In AIMS: `scan.Run{Scanner, Args, Version, Start, Info}` + `Begin[]` / `Progress[]` /
   `End[]` (`ScanTask` / `TaskProgress`) + `Stats.Finished` + `Stats.Hosts`.

4. **Extension is schemaless, via NSE.**
   Anything that does not fit host/port/service is hung off as a `<script>` containing an
   arbitrary recursive tree of `<table>` / `<elem>` key-values. nmap solved
   "structured output I did not anticipate" *once*, generically.
   → In AIMS: `nmap.Script{Elements[], Tables[]}` (recursive `Table`) plus the generic
   `scan.Result.Data` string field.

**The key realization:** this shape is already *scanner-agnostic*. `Run → Hosts → Ports →
Services`, with evidence/confidence on every node, a schemaless escape hatch, and a
task-stream, describes **any active scanner** — not just nmap. masscan literally emits
nmap-compatible XML; zgrab2 / nuclei / httpx / naabu just need their native output folded
into the same tree. The model was invented by nmap but it generalizes for free. Preserving
these four primitives is the non-negotiable constraint on anything built here.

---

## Part B — What is built vs. what is latent

The **data model is complete and faithful.** The **behavior that would make it a scan
*substrate* is almost entirely stubbed.** The noun (`Run` and its object tree) is
production-grade; the verbs (ingest-anything, target, stream, fold, diff) are the potential.

| Capability | State | Where |
|---|---|---|
| Parse nmap XML → `Run` | ✅ works | `scan/nmap/nmap.go` `FromXML` = one `xml.Unmarshal`; the `xml:"…"` tags do all the mapping |
| Store / read a Run (with host dedup) | ✅ works | `server/scan/scan.go` Create/Read; `db.FilterNew` + `AreScansIdentical` / `AreHostsIdentical` |
| **Fold async results into a Run** | ❌ empty stub | `scan.Run.AddResult`, `InitResult`, `AddTarget` all `return nil` — `scan/scan.go:69-94` |
| **Targets-from-DB (hosts-as-targets)** | ❌ absent | `scan.Target` type exists; no bridge from stored `Host`/`Service` → `Target` |
| **Any scanner other than nmap** | ❌ absent | no adapter interface; `Result.Data`'s *"add a branch case in the Go scan package"* (`result.proto:31-36`) was never written |
| Live / streaming scans | ❌ absent | `Scans` service is unary-only; yet `scan.go` `getTasks` already splits *running* vs *done* tasks for display |
| Run-to-run diff | ❌ absent | but Runs are timestamped + hosts dedup, so it is a query away |
| Upsert / Delete / List RPC | ❌ stub | `server/scan/scan.go:149-159` |

### The object catalog (for reference)

- **`Run`** (`scan.proto:18`) — the root. Invocation provenance (`Scanner/Args/Version/
  Start/StartStr`), `Info` (scan type/protocol/numservices), `Debugging`/`Verbose`,
  `Stats{Finished, Hosts}`, the task stream (`Begin`/`Progress`/`End`), `Targets[]`,
  `Hosts[]` (many-to-many), `PreScripts`/`PostScripts` (NSE), `Results[]`, `RawXML`.
- **`Result`** (`result.proto:22`) — the **feeder type**. Holds one `{Host, Address, Port,
  Service, Data}`; explicitly *"not meant to be saved in a database: only a feeder type for
  the scan.Run."* This is the universal adapter output (see Part C).
- **`Target`** (`scan.proto:157`) — dual-purpose: **input** (`Address/Domain/Tag/Port`) and
  **output** (`Specification/Status/Reason` — how nmap resolved it: `skipped/invalid/up`).
- **`ScanTask` / `TaskProgress`** — the temporal event stream (taskbegin/end vs. progress).
- **`nmap.Script/Table/Element`** — the recursive schemaless NSE tree.
- **`Stats/Finished/HostStats/Info/Verbose/Debugging`** — run metadata & totals.

---

## Part C — Turning the model into a scanner-plug substrate

Goal (from the project's own README ethos): *many tools contribute to and consume the same
database of the same objects.* For scans specifically that means **plug scanners, or their
results, into and out of this model.** Everything worth building hangs off **two small
interfaces** the model was clearly designed for but never got.

### Plug point A — results *into* AIMS (ingest side)

The `Result` feeder type **is** the universal adapter output. An ingestor is just:

```go
// Ingestor maps one scanner's native output into the shared model.
type Ingestor interface {
    Name() string                              // "nmap", "masscan", "zgrab2", "nuclei"
    Ingest(raw []byte) (*scan.Run, error)      // or emit a stream of *scan.Result
}
```

`nmap.FromXML` already *is* this shape. Candidates, cheapest first:
- **masscan** — emits nmap-compatible XML *and* JSON. Ideal first non-nmap adapter because
  it stresses both the "reuse nmap's shape" and the "fold a foreign format" paths.
- **naabu / rustscan** — open-port lists → `Result{Host, Port}`.
- **zgrab2** — JSON-per-service → `Result{Service, Data}`.
- **nuclei / testssl.sh** — findings → an NSE-style `Script{Table, Element}` tree.

**The real work is `Run.AddResult` — the fold.** It takes a `Result`, matches its
host/port/service against what is already in the Run *and in the DB*, and **merges rather
than duplicates**. The dedup comparators already exist (`host.AreHostsIdentical`,
`scan/identical.go`, `db.FilterNew`). This fold is the literal place where *"many tools
contribute to the same objects"* becomes true, so it is the **keystone** — build it first.

Fold sketch (behaviour-preserving with the existing comparators):

```
AddResult(res *Result):
  1. locate/instantiate the Host in Run.Hosts via AreHostsIdentical (else append)
  2. locate/instantiate the Port on that Host by (proto, number)     (else append)
  3. attach Service / Address to the Port/Host
  4. MERGE evidence, do not overwrite: keep the strongest Accuracy,
     keep both reasons if they disagree, and record which Run/Scanner
     asserted this observation (provenance — see below)
  5. hang scanner-specific extras on the NSE Script tree or Result.Data
```

### Plug point B — scans *driven by* AIMS (target side)

`Target` + the "hosts-as-targets" notion (`scan/target.go`) + a scanner interface:

```go
// Scanner drives a tool against AIMS-selected targets and streams results back.
type Scanner interface {
    Scan(ctx context.Context, targets []*scan.Target, opts any) (
        results  <-chan *scan.Result,
        progress <-chan *scan.TaskProgress,
        err error,
    )
}
```

Now the loop closes: **query stored `Host`/`Service` → derive `Target`s → run a scanner →
fold `Result`s back via `AddResult` → dedup → store**, with `TaskProgress` streamed to the
CLI (whose display already renders running-vs-done task tables). AIMS stops being an
nmap-XML parking lot and becomes a **scan orchestrator over a shared object DB** — the
`scan.Target{Address, Domain, Port, Tag}` input fields exist precisely for this bridge.

### Three capabilities this unlocks (true to the philosophy, not new philosophy)

1. **Provenance-first merge.** Run↔Host is many-to-many and every observation carries
   reason/accuracy, so folding can keep *which run asserted what, when, with what evidence*.
   Query: *"ports nmap called `filtered` that masscan called `open`."* Cross-tool
   disagreement becomes first-class — the attacker-side extension of nmap's single-tool
   epistemics.
2. **Delta scans / attack-surface drift.** Timestamped Runs + host dedup = native `ndiff`
   across *all* scanners at once: new hosts, newly-open ports, changed service versions
   between two runs. High value for recon and monitoring, nearly free given the model.
3. **NSE as the universal extension.** Any scanner's bespoke structured output goes into the
   recursive `Script{Table, Element}` tree or `Result.Data` — exactly as nmap does NSE — so
   adding a scanner *never* means new proto/DB columns. This keeps the "one shared database"
   promise honest as tools multiply.

### Recommended first vertical slice

Do **not** build the adapter registry, streaming RPC, or diff engine yet. Prove the thesis
with the smallest end-to-end thing:

> **Implement `Run.AddResult` (the fold + dedup) and one non-nmap `Ingestor` (masscan).**

That single slice validates that two tools can contribute to the same host/port/service
objects without duplication — the entire premise of the project. Streaming (server-streaming
RPC over the already-existing task model), hosts-as-targets, Upsert/Delete, and run-diffing
are all natural follow-ons once the fold is real.

### Guardrails when building here

- **Never hand-edit generated code** (`*.pb.go`, `*.pb.gorm.go`, `*.proto.gorm.go`). Change
  `scan/pb/*.proto` and run `make gen`. Keep Go-idiomatic behaviour in `scan/*.go`.
- **Preserve the four Part-A primitives.** Evidence/confidence, summarize-the-boring, run
  provenance, and schemaless NSE extension are the model's value — do not flatten them away
  for convenience.
- **Reuse the existing dedup layer** (`identical.go`, `db.FilterNew`) rather than inventing a
  parallel matching path; the fold and the DB-insert filter must agree on identity.
- **Keep `Result` a feeder, not a stored row** (per its own proto comment) unless a
  deliberate decision changes that — it is the transient bridge, the persistent tree is `Run`.

---

## Part D — The `run` subcommand & the scanner forks

Goal: `aims scan run <tool> …` to drive native scanners from AIMS. Two forks already exist
under `~/code/github.com/maxlandon/` and settle the two integration paths. **Not a priority —
per-scanner, incremental work; typed flag surfaces get built case-by-case.**

### nmap — already AIMS-native (ingest + drive done, ~90%)

`~/code/github.com/maxlandon/nmap` is a fork of **Ullaakut/nmap** retrofitted to emit AIMS
proto types directly. Its API *is* the `Scanner` plug point from Part C:

- `type ScanRunner interface { Run() (*scanpb.Run, warnings []string, err error) }` — returns
  our `scan.Run` directly, i.e. the exact type `aims scan import` already stores.
- `NewScanner(opts...)` with **104 typed `WithXxx` options** (`WithSYNScan`, `WithPorts`,
  `WithTraceRoute`, …) **plus** `WithCustomArguments(args...)` (raw passthrough),
  `WithBinaryPath`, `WithContext`, `WithFilterHost/Port` (`filters.go`).
- `RunAsync()` + `Wait()`, `YieldHosts() <-chan []*hostpb.Host`,
  `YieldProgress() <-chan scanpb.TaskProgress` — the live taskbegin/progress/end stream the
  `cmd/display` running-vs-done task tables were built to render.

**The one blocker:** the fork imports the *stale* `github.com/maxlandon/aims/proto/gen/go/
{host,scan}` layout. Current AIMS is `github.com/d3c3ptive/aims/{host,scan}/pb`. Retarget the
fork's imports to the new module path + `pb` layout — mechanical, not a rewrite — and
`aims scan run nmap …` is: build `nmap.Scanner` from flags → `Run()` → hand the `*scan.Run`
to `Scans.Create`. Ship **passthrough first** (`aims scan run nmap -- -sS -p1-1000 target`
→ `WithCustomArguments`), map typed cobra flags → the `WithXxx` options later per tool.

### CLI surface — raw passthrough, plus completion only where AIMS adds value

Two settled decisions for how `aims scan run <tool>` presents on the command line.

**1. Full passthrough with no `--` — use `DisableFlagParsing`.** cobra only forces the `--`
because its default parser errors on unknown flags like `-sS`. Set `DisableFlagParsing = true`
on the `run <tool>` command and every token after the tool name lands in `args` verbatim,
straight into `WithCustomArguments(args...)`:

```go
runNmap := &cobra.Command{
    Use:                "nmap [nmap args...]",
    DisableFlagParsing: true,           // `aims scan run nmap -sS -p1-1000 target` — no `--`
    RunE: func(cmd *cobra.Command, args []string) error { /* args → WithCustomArguments */ },
}
```

(Trade-off: cobra also stops handling `-h/--help` for that command, so either let `nmap --help`
fall through to nmap or check for it manually. For a passthrough wrapper, falling through is
usually what you want.) The alternative — keep parsing but `Flags().SetInterspersed(false)` +
`FParseErrWhitelist{UnknownFlags:true}` — is only worth it if you need a few *aims-owned* flags
interleaved with native ones; it's fiddlier (a value-taking flag like `-p 80` can confuse which
token is the positional). Force `-oX -` under the hood regardless of user args so we always get
parseable XML back — a correctness lever, independent of parsing mode.

**2. Don't mirror nmap's flags — type + complete only where AIMS knows more than nmap does.**
Mirroring hundreds of nmap flags is a maintenance treadmill the shell bridges already do (badly).
Spend completion effort *only* where the AIMS DB is the unique source:

- **Targets — the killer completion.** AIMS *has* the host store, so `run nmap <TAB>` should
  offer known hosts/addresses/hostnames. Reuse the existing live-DB carapace callback
  `host.CompleteByHostnameOrIP` (`cmd/hosts`) verbatim. No shell completer can ever do this — it
  is the demo that sells the subcommand.
- **NSE scripts.** Parse nmap's `scripts/script.db` (its shipped index: `Entry{filename,
  categories}`) for described, category-grouped `--script` completion; that same dir-read is the
  front half of the NSE→DB mapping below. Fallback: `nmap --script-help all`; resolve the dir via
  `nmap --datadir` / the standard `/usr/share/nmap/scripts` locations.
- **Everything else → raw passthrough**, optionally with carapace-bridge (`bridge.ActionZsh
  ("nmap")` / `ActionBash`) as a catch-all for the flag long-tail. Treat the bridge as a
  *fallback*, not the plan: it depends on the operator's shell having `_nmap` loaded, spawns a
  shell per completion, loses descriptions, and — decisively — cannot complete DB targets.

Because `DisableFlagParsing` turns off cobra's own completion, the way to get *both* raw
passthrough and rich completion is one carapace `ActionCallback` on the positional tail that
dispatches on `c.Args`: after `--script` serve NSE scripts, in target position serve DB targets,
else defer to the bridge. carapace hands you the full arg vector, so we own the logic.

### zgrab2 — NOT wired; the value is the NSE mapping (ingest only)

`~/code/github.com/maxlandon/zgrab2` is still `module github.com/zmap/zgrab2` (no AIMS
imports; scan/processing code refactored). Integration here is **result ingestion, not
linking**. zgrab emits newline-delimited JSON per target, keyed by module, each a:

```go
type ScanResponse struct {
    Status   ScanStatus  // → service up/responsive
    Protocol string      // "ssh"/"http"/"tls"… → network.Service name
    Result   interface{} // arbitrary per-module nested JSON  ← the NSE-style payload
}
```

**Key isomorphism:** AIMS's recursive `nmap.Script{Elements[], Tables[]}` tree is structurally
arbitrary JSON. So a *single generic* `jsonToScript()` walker maps **any** zgrab module (all
30+: ssh/http/tls/mysql/redis/mongodb/…) — and any JSON tool (nuclei, httpx, testssl) — into
the same `Script`/`Table`/`Element` DB rows nmap's own NSE scripts land in:

| zgrab JSON | AIMS NSE tree |
|---|---|
| module result (`ssh:{…}`) | `Script{Name:"zgrab.ssh"}` on the host:port |
| object field `key:{…}` | child `Table{Key:"key"}` |
| scalar `key:value` | `Element{Key, Value}` |
| array `key:[…]` | `Table{Key}` with indexed children |

Write the walker once; every module files itself into the exact NSE machinery for free — no
per-module schema, no new proto columns. This is the Part-A schemaless-NSE principle put to
work, and the "one shared DB, many tools" thesis realized for unstructured tool output.

Proto touch-point: `scan.Result` has no `Script` field (nmap hangs scripts on `Host`/`Port`).
Either attach the generated `Script` tree onto the Result's `Port`/`Host`, or add
`repeated nmap.Script Scripts` to `Result`. Quick first pass can stuff raw JSON into
`Result.Data` (its proto comment anticipates exactly this), but `jsonToScript` is the
philosophy-true route.
