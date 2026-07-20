AIMS — Attacked Infrastructure Modular Specification
====================================================

A **shared data model and object store for offensive-security tooling.** AIMS declares the
objects an attacker cares about — hosts, networks, services, credentials, scans, C2 agents —
and gives them first-class facilities so that *many different tools can contribute to and
consume the same database of the same objects.*

Think *MISP/STIX, but for the attacker's side* — with the emphasis on being easy to move
around, easy to store in SQL, and interoperable across languages and tools.

It ships as three things at once:

- a **specification** — Protobuf definitions that are the source of truth for every object;
- a **library** — generated Go types you can embed in your own tool, SQL-storable out of the box;
- a **binary** — `aims`, a teamserver + client + CLI to populate, query, and browse the store.

> **Status.** The data model and generated layer are mature. The user-facing server/CLI is a
> vertical slice that fills out domain by domain — see the [status matrix](#status) below and
> [`STATE.md`](./STATE.md) for the live detail. `GOWORK=off go build ./...` builds the whole
> tree and the `aims` binary runs.

---

## Quickstart

**Requirements:** Go 1.24+. The repo lives under a `go.work` context, so build with `GOWORK=off`.

```sh
# Build the binary
GOWORK=off go build -o aims ./cmd/aims

# The binary is a self-contained teamserver + in-process client + CLI.
# First run migrates the embedded database automatically.
./aims --help
```

Run a scan and browse what it found:

```sh
# Scan a subnet with nmap (args after `nmap` are passed straight through) and store the results
aims scan run nmap -- -sV -O 10.0.0.0/24

# List what's in the store
aims hosts list                 # discovered hosts (responsive, colored, weight-ranked columns)
aims services list              # network services across all hosts
aims scan list                  # scans, with live run-state

# Drill into one object by ID prefix
aims hosts show a1b2            # detail view; add --traceroute for the route
aims scan show 5f3c

# See what changed between two scans (attack-surface drift)
aims scan diff <id-a> <id-b>
```

Credentials and C2:

```sh
aims credentials list
aims credentials add            # Metasploit-style Private/Public/Realm/Origin model
aims agents list                # C2 agents
aims channels list
```

Completions are rich and **live** — a `Tab` on any `show`/`rm` queries the store and renders
described, aligned candidates (results are briefly cached so repeated `Tab`s are instant). Wire
them into your shell with carapace (`aims` is carapace-instrumented).

Multi-user / remote operation is available too: `aims` embeds a
[`reeflective/team`](https://github.com/reeflective/team) teamserver (extracted from Sliver),
so you can serve the store to remote operators over mTLS. See the `teamserver` command group.

---

## What it stores

Each domain mirrors the object model of a tool people already trust, so tool-native output maps
onto the types with little friction:

| Domain         | Core objects                                                                                   | Model heritage |
|----------------|------------------------------------------------------------------------------------------------|----------------|
| **Host**       | `Host`, `Hostname`, `Port`, `OS`/`OSMatch`, `User`, `Group`, `Process`, `FileSystem`, `Uptime` | nmap           |
| **Network**    | `Address`, `Service`, `Trace`/`Hop`, `Distance`, `TCPSequence`/`IPIDSequence`, packets          | nmap           |
| **Credential** | `Core` (Private/Public/Realm/Origin), `Login`, passwords, hashes, keys, certificates            | Metasploit     |
| **Scan**       | `Run`, `Info`, `Stats`, `Target`, `ScanTask`, `TaskProgress` (nmap `Script`/`Table`/`Element`)  | nmap et al.    |
| **C2**         | `Agent`, `Channel`, `Task`                                                                      | Sliver-like    |
| **Provenance** | `Source` — per-tool origin stamped on co-produced objects, for "give me only my data" queries   | —              |

Many host/network proto fields carry `xml:"…"` tags that map **directly onto nmap's XML
output**, so nmap results unmarshal straight into the types. Re-importing the same scan does not
duplicate rows — a shared merge/dedup fold folds new facts into existing objects.

---

## Status

The model + generated layer is solid. The server/CLI slice is filling out domain by domain;
read paths work broadly, mutation is landing service by service.

| Service                  | Read / List | Create      | Update / Delete / Upsert | Notes                                              |
|--------------------------|:-----------:|:-----------:|:------------------------:|----------------------------------------------------|
| **host** (Hosts)         | ✅          | ✅ (dedup)  | Upsert ✅ · Delete stub  | reference impl; deep in-place child merge on insert |
| **credential**           | ✅          | ✅          | Upsert ✅ · Delete ✅    | full CRUD; Delete resolves by identity             |
| **scan**                 | ✅          | ✅          | Upsert ✅ · Delete ✅    | full CRUD; cross-run host unification; live state   |
| **network** (Services)   | ✅          | stub        | stub                     | display/CLI slice done; server CRUD pending         |
| **c2** (Agents/Channels) | ✅          | ✅          | stub                     | Upsert/Delete pending                              |
| host Users · cred Logins | ❌          | ❌          | ❌                       | services scaffolded but stubbed                     |

Also in flight: a scanner-plug **substrate** (live/streaming scans, `Ingestor`/`Scanner` plug
interfaces, stored-object → `Target` bridge, run-to-run diff) and `bring` — sourcing a C2 agent
context into your live shell. See [`SUBSTRATE.md`](./SUBSTRATE.md), [`SCAN.md`](./SCAN.md), and
[`BRING.md`](./BRING.md).

---

## Architecture

One code-generation pipeline runs the whole repo: `.proto` → generated Go PB types → generated
GORM ORM types → hand-written helpers + per-domain gRPC services + CLI.

```
 proto definitions          generated code                    hand-written layers
 ─────────────────          ──────────────                    ───────────────────
 <domain>/pb/*.proto    ─►  *.pb.go       (protoc-gen-go)
                            *.pb.gorm.go  (protoc-gen-gorm)  ─►  server/<domain>/  gRPC CRUD
 <domain>/pb/rpc/*.proto ─► *_grpc.pb.go  (gRPC)             ─►  client/           client wrappers
                                                             ─►  <domain>/*.go     native helpers, display, dedup
                                                             ─►  cmd/<domain>/     cobra CLI + completions
```

- **Two representations per object** (via `infobloxopen/protoc-gen-gorm`): `pb.Host` (the
  user-facing Protobuf Go type) and `pb.HostORM` (the GORM-storable type), with `ToPB`/`ToORM`
  converters. Services convert PB→ORM to query/write, then ORM→PB to return.
- **Struct tags drive everything.** `// @gotags:` comments attach `xml:` (nmap ingest),
  `display:` (CLI columns), `readonly`, `strict`; GORM relations come from `(gorm.field)` proto
  options. IDs are UUID strings; relations cascade.
- **One generic display engine** (`cmd/display/`) — a type-parameterized
  `map[string]func(T) string` per object feeds tables, detail views, *and* completions, with
  weight-driven responsive column dropping. Define an object's presentation once.
- **Multi-user layer** built on `reeflective/team` — auth, transports (mTLS, optional
  Tailscale), and RPC plumbing.

---

## Documentation

The companion docs carry the detail:

| Doc                              | What it covers                                           |
|----------------------------------|---------------------------------------------------------|
| [`NAVIGATION.md`](./NAVIGATION.md) | Codebase map — directory roles + "where is X?" lookup  |
| [`CLAUDE.md`](./CLAUDE.md)       | Root context — architecture, pipeline, domain catalog   |
| [`STATE.md`](./STATE.md)         | Current state, build status, per-service maturity        |
| [`ROADMAP.md`](./ROADMAP.md)     | Re-entry plan / what to build next                       |
| [`SCAN.md`](./SCAN.md)           | Scan model & scanner-plug substrate                     |
| [`SUBSTRATE.md`](./SUBSTRATE.md) | Ingest / target / diff / streaming substrate            |
| [`DEDUP.md`](./DEDUP.md)         | Identity, dedup, and the merge fold                      |
| [`DISPLAY.md`](./DISPLAY.md)     | The generic table/detail/completion display engine       |
| [`COMPLETIONS.md`](./COMPLETIONS.md) | Live, cached, sub-categorized completions           |
| [`CREDENTIALS.md`](./CREDENTIALS.md) | The credential domain in depth                      |
| [`BRING.md`](./BRING.md)         | Sourcing a C2 agent context into the shell (design)      |

---

## Building & regenerating

- **Canonical module path:** `github.com/d3c3ptive/aims`. (The local checkout may sit under
  `maxlandon/aims`; that path is being migrated away — always use `d3c3ptive` imports.)
- **Build / vet:** `GOWORK=off go build ./...` (the `go.work` context requires `GOWORK=off`).
  First build pulls a large tree (gRPC, teamserver, nmap fork) — expect a slow initial download.
- **Optional build tags:** `-tags maltego` enables the `AsEntity()` Maltego integration;
  `-tags tailscale` enables the Tailscale transport. Both are opt-in and off by default.
- **Regenerate from proto:** `make gen` (buf: go + gorm + gotemplate, then go-grpc, then
  `protoc-go-inject-tag` for the `xml:`/`display:` tags). `make deps` installs the plugins.

When extending: prefer changing the **`.proto`** and regenerating over editing generated
`*.pb.go`/`*.pb.gorm.go` by hand; put Go-idiomatic behavior in the domain root `<name>.go`
files; wire new CRUD in `server/<domain>` + `client` + `cmd/<domain>`, following the **host**
domain as the reference implementation.

---

## License — GPLv3

AIMS is licensed under [GPLv3](https://www.gnu.org/licenses/gpl-3.0.en.html).
