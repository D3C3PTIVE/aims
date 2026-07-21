# AIMS — Client-Side Contribution & the Bridge

> Written 2026-07-21. Companion to [`CLAUDE.md`](./CLAUDE.md) (architecture) and
> [`SCAN.md`](./SCAN.md) (the scanner substrate, the first realized contributor).
>
> **The goal:** let *any* offensive-security tool — a Go program, a shell script, a client-side
> shell wrapping the `aims` CLI — contribute hosts / services / credentials / scans to the shared
> AIMS database with **one line**, and trust AIMS to own identity, dedup, merge, and provenance.
> No managing your own DB, no filling out request structs, no learning the object model.

## The principle: the server already owns correctness

AIMS's *server* is where reliable write logic lives — the host ingest fold (`host.IngestHosts`,
additive + idempotent, deep child enrichment), the credential merge, the scan host-unification. A
contributor must be able to hand an object over and **trust** that:

- re-adding the same recon output enriches rather than duplicates (`SameHost`/`SamePort` dedup),
- a service nmap already saw merges with the one zgrab just found (cross-tool fold),
- provenance is recorded, so a later `--source <tool>` read returns exactly what the tool put in.

So every contribution path here is **deliberately thin**: build a request, call one existing RPC,
plus a single provenance stamp. No new logic, no parallel comparators.

## The unifying insight: contribution is the completion bridge, run backwards

AIMS's completion layer is already a bridge in one direction. A foreign shell invokes the hidden
`_carapace` command; the exec-once `aims` process auto-detects its teamserver (system user config),
queries the DB, and emits candidates as shell code (`cmd/completers/plumbing.go`, `ConnectComplete`).

**Contribution is the same machine run backwards:** a tool invokes a hidden `aims _contribute <domain>`
command, pipes an object in on stdin (the JSON `cmd/export` already speaks), and that exec-once
process connects to the same teamserver and folds the object in. Same exec-once, same auto-detected
*local aims client*, same "the binary already knows how to reach the DB" — data flowing **in** instead
of candidates flowing **out**. This is the carapace-bridge analogue: a hidden command other tools
shell into, in both directions.

```
                 ┌──────────────── one handle: contrib.Session ─────────────────┐
 Go tool ───────►│  .As("tool")   .Hosts.Add / .Creds.Add / .Scans.Add / .List  │
                 └──────────────┬────────────────────────────┬──────────────────┘
                   transport A: │ linked (gRPC teamclient)    │ transport B: bridge (exec)
                                ▼                             ▼
 any non-Go tool ──JSON on stdin──►  aims _contribute <domain> --as tool  ──┐
                                                                            ▼
                        server-side fold (host.IngestHosts / Create / Upsert)
                        — owns identity, dedup, merge, provenance. Client trusts it.
                                ▲
 any shell ◄──shell code/JSON────  aims _carapace  /  aims <domain> export   (bridge OUT, exists)
```

## Build units

| Unit | What | State |
|---|---|---|
| **2. Linked Go facade** (`client/contrib`) | `Session.As(tool)` + per-domain `Add`/`Upsert`/`List`, thin wrappers over the existing RPCs. Provenance stamped client-side (host/cred) or via `Run.Scanner` (scan). | ✅ **done** — host/credential/scan; integration-tested through the full transport (`cmd/aims/contrib_test.go`). |
| **1. Bridge ingest endpoint** (`cmd/contribute`) | Hidden `aims _contribute <domain> --as tool` (machine contract) **and** `--as` on the `hosts`/`credentials` `import` verbs (human path). Both reduce to `contribute.Objects` → `export.ImportJSON` → the facade. | ✅ **done** — integration-tested (`cmd/aims/contribute_test.go`); `scan import --as` deferred (see note). |
| **3. Bridge transport backend** (**fallback only**) | Used *only when a tool has no in-code teamclient to hand the facade*: detect a local `aims` (system config, then `$PATH`) and route each contribution through unit 1's exec endpoint. Never preempts a linked connection. | ⏳ planned |
| **Event broker** (Phase 2) | An `aims`-provided broker: `Publish`/`Subscribe`, an `Events` stream RPC, and CRUD servers emitting `HostAdded`/… — so tools *react* to contributions (Sliver's `EventBroker` + `StartEventAutomation` auto-register pattern). Same bidirectional bridge treatment (`aims _events` emitting shell-consumable frames). | ⏳ planned |

## The facade today (unit 2)

```go
// one call: bootstrap a teamclient from good defaults, connect, ready to contribute
db, err := contrib.Dial()                // zero-config — discovers the operator's aims server
defer db.Close()
db.As("recon-x")                         // provenance name, stamped on everything below

db.Hosts.Add(&host.Host{ Addresses: addr("10.0.0.1"), Ports: ports(443) })  // additive + dedup
db.Hosts.Upsert(host)                                                        // merge in place
db.Creds.Add(&credential.Core{ /* ... */ })
db.Scans.Add(run)                                                            // whole run, host tree folds
hosts, _ := db.Hosts.List(nil)                                               // reads all contributors

// or, when the program already holds a connected client (a console, a test):
db := contrib.New(con).As("recon-x")
```

### Connection: a pure in-code teamclient, zero-config by default

`Dial()` is the "call the library once" path and its transport is a **pure, in-code teamclient
connection** — never an exec of the `aims` binary. It is **zero-configuration by deliberate design**:
the server is discovered from the current user's *system teamclient config* (`client.DefaultConfig`
→ the team API's on-disk config), so a contributing tool needs **no flag, env var, or JSON path of
its own** — it inherits whatever connection the operator already set up for `aims`. With no system
config there is nothing to contribute to, so `Dial` returns a clear error rather than hanging.

Under the hood `Dial` reduces to the new library `client.Connect()` (the coupling-free entry point
`ConnectRun`/`ConnectComplete` also reduce to: pre-hooks → `Teamclient.Connect` → register clients).
The exec bridge (unit 3) is a **fallback for programs that cannot link this client at all** — it
never preempts a live teamclient.

- **`Add`** → the domain's `Create` (additive, skip-if-identical). **`Upsert`** → `Upsert` (merge).
  **`List(nil)`** → `Read`/`List` (host has no `List` RPC; `Read` lists by default).
- **Provenance.** `As(tool)` stamps a `provenance.Source{Tool: tool, Type: Import}` on each contributed
  host (fanned onto its addresses/ports/services, mirroring the server-side scan stamp, since host
  `Create` does *not* auto-stamp) and on each credential. For scans it fills an unset `Run.Scanner`
  — the scan server derives provenance from `Scanner`, so that is the scan-domain equivalent.
- **Trust, verified.** `TestContribHostsAddThroughFacade` adds a host, re-adds an identical one and
  asserts **zero** new rows (server dedup), then reads `--source recon-x` back and asserts the stamp
  landed. `TestContribCredsAddThroughFacade` does the same for credentials.

## The bridge ingest endpoint today (unit 1)

```sh
# machine: any tool that can run a subprocess — no gRPC, no proto, no linking
echo '{"addresses":[{"addr":"10.0.0.1"}],"ports":[{"number":443,"protocol":"tcp"}]}' \
    | aims _contribute host --as recon-x          # prints the stored-object count
aims _contribute credential --as dump-tool creds.json

# human: the same fold, discoverable, attributed
aims hosts import --as recon-x findings.json
cat creds.json | aims credentials import --as dump-tool -i
```

- `aims _contribute <domain> [files...]` is **hidden** (a wire format, not an operator command),
  `MinimumNArgs(1)` (the domain), reads each file arg then piped stdin, prints the count stored. The
  connect pre-run every leaf gets has already reached the teamserver by the time it runs, so it
  inherits the exact auto-detect the completion path uses — the "any detected local aims client".
- `--as` (or `$AIMS_TOOL`) is the provenance name, threaded into `contribute.Objects` and stamped by
  the facade. `contribute.Objects` maps each domain to its enriching write (host/cred → `Upsert`,
  scan → `Add`/`Create`), so a re-contribution merges rather than duplicates.
- **Deferred, on purpose:** `scan import --as`. The scan CLI (`cmd/scan`) was under concurrent edit;
  rewiring its bespoke import runE (per-run "Saved …" output, one-Create batching) through
  `contribute.ImportRunE` was held back to avoid a merge collision. The hidden `_contribute scan`
  path already covers scan contribution; only the visible verb's `--as` is pending.

## Design calls made

- **Thin over clever.** No client-side dedup/merge — that would be a second, drifting source of truth.
  The facade's only non-plumbing act is the provenance stamp.
- **`Agent`/`Channel` carry no `Sources` field**, so c2 has no provenance axis yet; the facade omits
  c2 rather than fake it. Add it if/when c2 gains provenance.
- **Services are contributed *through hosts*** (a service hangs off a port), not as a standalone verb —
  matching the data model and the fact that the service `Create` RPC is a server-side stub.
- **Wire format = the existing JSON import path** (`cmd/export`, protobuf-reflection JSON). Don't
  invent an interchange format; AIMS already has one.

## For the parallel agent

If you own the **stubbed server CRUD** (`network` Create/Upsert, `c2` Upsert, credential `Logins`):
this facade is your first consumer — finishing those unlocks `db.Services.*` / c2 upsert here. If you
own **provenance/event plumbing**: the `As(tool)` stamp and any future broker must be *one* mechanism,
not two. The bridge (unit 3) is the *client* that feeds whatever server-side reactivity you build.
