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
| Store / read a Run (with host dedup) | ✅ works | `server/scan/scan.go` Create/Read; Create folds hosts through `host.IngestHosts` and links via the `run_hosts` join; run-level dedup via `AreScansIdentical` |
| **Fold results/hosts into a Run** (in-memory) | ✅ built + tested | `scan/fold.go` — `Run.AddResult` (feeder) + `Run.AddHosts` (bulk/import) → scoped keyed match + field-class merge; `scan/fold_test.go`. |
| **Fold *against persisted rows*** (DB-level idempotence) | ✅ **realized** | `host.IngestHosts`/`ingest` (`server/host/host.go`) loads existing rows by natural key, `host.MergeHost`-es in place, and `saveMergedHost`/`saveMergedPorts` persist only new evidence (incl. enrichment inside already-persisted children); `server/scan.Create` uses it |
| **Targets-from-DB (hosts-as-targets)** | ✅ done | `scan/targets.go` `TargetsFromHosts`/`TargetSpecs` (stored `Host` → `Target` → scanner args); `scan/drive` consumes them |
| **Any scanner other than nmap** | ✅ done | `scan/ingest` `Ingestor` interface + registry; nmap + zgrab2 adapters; generic `jsonToScript` walker maps any JSON tool into the NSE tree. CLI `scan import --scanner` |
| Live / streaming scans | ✅ done | `Scans.Run` is server-streaming (`RunUpdate` oneof) + a server-side job model (`server/scan/run.go`); `scan run nmap` streams server-side, Ctrl-C detaches, `--background`/`jobs`/`attach`/`stop`. (`watch scan show` live snapshot still needs incremental persistence — SUBSTRATE.md backlog) |
| Run-to-run diff | ✅ done | `scan/diff.go` `DiffRuns` + `scan diff` CLI (stored shared-host diff gated on the `server/scan.Read` host-scoping fix — SUBSTRATE.md backlog) |
| Upsert / Delete / List RPC | ✅ done | `server/scan/scan.go` — List delegates to Read; Delete removes by Id, clearing run_hosts (shared hosts survive); Upsert is idempotent insert-or-return-existing. Plus `scan rm` CLI (running-scan guard via `scan.IsRunning`) |

### DB-level fold — REALIZED (was: "in-memory only")

> **Corrected 2026-07-20.** This section previously described the fold as in-memory only, with
> persistence still duplicating known hosts. That is **no longer true** — verified against the code.

The DB-level, additive-and-idempotent fold (DEDUP.md §0 prime directive) is now wired end to end:

- **Shared merge primitive** (`host/merge.go`): `host.SameHost` (natural-key identity),
  `host.MergeHost` (field-class merge — fill-only scalars, unioned collections, observations kept
  not clobbered), `host.SamePort`. One merge, every ingest path agrees.
- **Persisted fold** (`server/host/host.go`): `host.IngestHosts` → `ingest` loads existing rows
  with their full tree (`loadHostsPB`), matches each incoming host by key (`indexSameHost`),
  `MergeHost`-es in place, and `saveMergedHost` persists **only new evidence** — updating scalars,
  appending new children, and even writing back enrichment landing *inside* an already-persisted
  child (`saveMergedPorts`: a new NSE script / filled `Service.Product` / new state reason on a
  known port). Unmatched hosts are inserted. `server/host.Create` (additive, skip-if-`SameHost`)
  and `Upsert` (merge path) both go through this — the old empty-`dbHosts`/`FilterNew` duplication
  bug is fixed.
- **Scan path** (`server/scan.Create`): folds each run's hosts through `host.IngestHosts` and links
  the run to the returned shared rows via the `run_hosts` many2many join (`tx.Omit("Hosts.*")`), so
  one physical host observed by N runs is ONE row linked to all N (the `sharedRunCount` insight
  surfaces this). Run-level dedup is RawXML-authoritative, `AreScansIdentical` as fallback.

Tests: `server/host/host_test.go`, `server/scan/scan_test.go`, `scan/fold_test.go`,
`scan/identical_test.go`. See DEDUP.md and the `aims-ingest-merge-fold` project note.

**Scan CRUD + the scanner-plug substrate (Part C) are now built** (2026-07-20, see SUBSTRATE.md):
the `Ingestor` interface + generic JSON→NSE walker (non-nmap ingest), the hosts-as-targets bridge +
`Scanner` driver, run-to-run diff, and server-side streaming scans + a job model (the nmap fork's
async path was fixed to enable it). What remains are the SUBSTRATE.md backlog items — chiefly
incremental persistence for the `watch scan show` live view, the `server/scan.Read` host-scoping bug
that gates stored-run diff, and per-tool dedup/cascade verification — not new capabilities.

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

### Live scan view — compose `scan show` with `watch`, don't build a blocking monitor

A running scan wants a live, refreshing view (progress, hosts/ports found so far, tasks
done-vs-todo). The instinct is a blocking `scan monitor <id>` command that owns the terminal
and redraws — but the cheaper, more Unix-composable answer is to keep a **stateless `scan show
<id>`** that renders the current snapshot once and exit, and let the operator wrap it:

```
watch -c -n1 aims scan show <id>
```

`scan show` already renders running-vs-done task tables (`scan.go` `getTasks`/`formatTasks`
split `Progress[]` vs `End[]`), so a live view is mostly *there* — it just needs the underlying
Run to keep updating (the streaming fold + `TaskProgress` from Plug point B). Composing with
`watch` gives refresh, color, and interval control for free, stays scriptable, and avoids a
bespoke render loop. A built-in `monitor` can come later as sugar if wanted; it should share the
exact `scan show` renderer, not fork it.

Open design question (either path): what the live view *shows* — raw scanner stdout passed
through, or AIMS's own summarized display (objects found so far, task done/todo counts, deltas
since last tick). The AIMS-native summary is the more valuable and philosophy-true option (it
reads the folded object tree, not the tool's console spew), but raw passthrough is a trivial
first cut. Lean summarized, fall back to raw.

### Scan execution model — server-side jobs; the client chooses whether to block

**Settled decision: the scanner process runs server-side.** The teamserver is the vantage
point that execs the scanner (so its host needs the tool + privileges + network reach to the
targets); clients are operator terminals. This matches the teamserver/Sliver model
`reeflective/team` gives us, and it is what makes a long scan *survivable* — the job outlives
the operator's terminal and is visible to every operator.

From that, two principles:

1. **Blocking is a client *presentation* choice over a server-side job — not a property of the
   scan.** The job always runs on the server; the client picks:
   - **foreground** (default): stream `TaskProgress`, block until done, show the result;
     **Ctrl-C detaches** (the job keeps running), it does not kill it.
   - **background** (`-d`/`--background`): submit, print a job ID, return immediately.
2. **I/O parity is a hard requirement.** A command must reach the *same* blocking/streaming I/O
   whether the `aims` binary runs as an **in-process teamserver** or as a **remote teamclient**
   over the wire. So foreground streaming MUST be built on the team RPC/stream layer uniformly —
   never a local in-process function-call shortcut for the all-in-one binary and a separate
   remote path. `reeflective/team`'s in-memory vs mTLS transports expose the *same* RPC surface
   precisely so this holds; build on that, do not special-case.

CLI shape (settled):

| Command | Behaviour |
|---|---|
| `aims scan run nmap <args>` | foreground: stream progress, block to completion; Ctrl-C detaches |
| `aims scan run nmap <args> -d` | detached: submit, print job ID, return |
| `aims scan jobs` | list running scan jobs + progress (maps to the teamserver job list) |
| `aims scan attach <id>` / `scan stop <id>` | reattach to a job's stream / cancel it |
| `aims scan show <id>` + `watch` | poll-based live view over the continuously-updated stored Run |

Enabling work (all follow-on):
- The `Scans` RPC is **unary-only** today (Part B) → add a **server-streaming** Run/Progress RPC.
- The fork already produces the stream: `RunAsync()` + `YieldProgress()`/`YieldHosts()`.
- The display already splits running-vs-done: `scan.go` `getTasks`/`formatTasks`.
- Hook the job into `reeflective/team`'s job model rather than inventing a parallel async layer.

> The current `scan run nmap` is a **client-side blocking exec** — a v0 stand-in. It becomes the
> *foreground* front-end of a server-side job once the streaming RPC + job wrapper land; the
> passthrough/fold machinery underneath is unchanged.

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

**Status: wired and working.** The fork was retargeted to `github.com/d3c3ptive/aims/{host,scan}/pb`
(a local `replace => ../nmap`), and `aims scan run nmap …` runs end-to-end: build `nmap.Scanner`
from args → `Run()` → hand the `*scan.Run` to `Scans.Create`. Current shape is **passthrough**
(`DisableFlagParsing` → `WithCustomArguments`) with `-oX -` forced under the hood; typed cobra
flags mapped to individual `WithXxx` options remain a per-tool follow-on. The remaining nmap gap
is **streaming/async** (see Part C — `Scans` is unary-only, so `run nmap` blocks to completion).

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
