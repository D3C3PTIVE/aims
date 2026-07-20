# AIMS — Codebase Navigation Map

> **Start here if you just arrived.** This file answers *"where does X live and what is each
> directory for?"* — a map, not a narrative. For the *why* and the architecture story read
> [`CLAUDE.md`](./CLAUDE.md); for *what's built vs. stubbed* read [`STATE.md`](./STATE.md).
> Last synced with the tree: 2026-07-20 (includes the client/server boot split + the gRPC
> transport factored into `reeflective/team`).

## The 30-second model

AIMS is a **shared data model + object store for offensive-security tooling**. One
code-generation pipeline drives the whole repo:

```
 <domain>/pb/*.proto  ──►  *.pb.go + *.pb.gorm.go (generated)  ──►  server/<domain>/  (gRPC CRUD)
 <domain>/pb/rpc/*.proto ─► *_grpc.pb.go (generated)           ──►  client/           (client wrappers)
                                                               ──►  <domain>/*.go      (native helpers/display/dedup)
                                                               ──►  cmd/<domain>/      (cobra CLI + completions)
```

The single `aims` binary is **both** a teamserver and a client (built on
[`reeflective/team`](https://github.com/reeflective/team)); which half runs is decided at boot
(see [Boot mode](#boot-mode-client-vs-server) below).

## Directory map

### Domain packages — the object catalog

Each of these is a self-similar vertical: `pb/` (proto defs + generated PB/ORM code),
`pb/rpc/` (gRPC service defs), and a root `<name>.go` holding **native wrapper types**
(`type Host pb.Host`) that hang Go-idiomatic behavior — display fields, dedup/identity,
merge — off the generated types without polluting them.

| Dir | Domain | Core objects | Heritage |
|-----|--------|--------------|----------|
| `host/` | Host | `Host`, `Hostname`, `Port`, `OS`/`OSMatch`, `User`, `Process`, `FileSystem` | nmap |
| `network/` | Network | `Address`, `Service`, `Trace`/`Hop`, `TCPSequence`, packets | nmap |
| `credential/` | Credential | `Core` (Private/Public/Realm/Origin), `Login`, hashes, keys, certs | Metasploit |
| `scan/` | Scan | `Run`, `Info`, `Stats`, `Target`, `ScanTask`; nmap specifics under `scan/nmap` | nmap et al. |
| `c2/` | C2 | `Agent`, `Channel`, `Task` | Sliver-like |
| `provenance/` | Provenance | `Source` — per-tool origin stamped on co-produced objects (for "give me only my data") | — |

**`host/` is the reference implementation** — the fullest domain (identity, deep merge fold,
rich display). Copy its patterns when building out another domain.

### `server/` — the gRPC backend

More than a couple of CRUD shims — this is where writes actually land in the DB.

| Path | Role |
|------|------|
| `server/server.go` | `server.New(grpcServer, WithDatabase(db))` — the aggregate registrar that binds **every** per-domain gRPC service onto one `*grpc.Server`. The one call the transport makes at serve time. |
| `server/<domain>/` | One package per domain (`host`, `network`, `credential`, `scan`, `c2`). Each is a **PB↔ORM CRUD service**: convert PB→ORM to query/write via GORM, ORM→PB to return. `server/host/host.go` is the canonical Read/Create/Upsert pattern; `server/credential/` is the worked Delete-by-identity example; `server/scan/` has the DB-level cross-run host fold. |
| `server/transport/` | **Teamserver construction + boot helpers** — NOT a hand-forked transport anymore. `NewTeamserver()` builds the team server + the shared `reeflective/team/transports/grpc` handler, wires the AIMS schema-migrate + `server.New` as a **PostServe hook** (`registerServices`), and pointedly does *not* prime the in-memory bufconn. `InMemoryClientOptions(handler)` primes the bufconn for the embedded console only. `tailscale.go` (`//go:build tailscale`) + `tailscale_stub.go` gate the optional tsnet variant. See `server/transport/README.md`. |

> **Where mutations get stubbed out:** several services return `Unimplemented`. The live matrix
> is in [`STATE.md`](./STATE.md#implementation-matrix-grpc-services) — check it before assuming a
> Create/Delete works.

### `client/` — the client-side gRPC surface

The consumer half of the split. `client/client.go` defines the `Client` struct that holds one
**typed gRPC service client per domain** (`Hosts`, `Creds`, `Scans`, `Agents`, …), plus the
`reeflective/team` teamclient and the shared `grpcclient.Dialer`.

Key responsibilities to know about:
- **Connection lifecycle:** `New(opts...)` builds the dialer + teamclient; `Init()` binds the
  typed service clients once a `*grpc.ClientConn` exists; `ConnectRun` (cobra pre-run) and
  `ConnectComplete` (completion pre-run) drive the actual connect. Connections are lazy — a
  command only dials when it needs the server.
- **Thin-client pinning:** `SetServerConfig(cfg)` / `teamConnectOptions()` pin a remote
  teamserver config so a client-mode boot connects deterministically to the detected system
  server (rather than prompting / auto-selecting).
- **Core team RPCs:** `Users()`/`VersionServer()` delegate to the teamclient, answered by the
  transport's core Team service (`WithCoreServices()` server-side).
- **Completion scoping:** `CompletionScope()` namespaces the on-disk completion cache by
  `user@host:port` so a multiplayer client never serves one server's objects while completing
  against another.
- `client/host/` holds host-specific client helpers; `client/files.go` file transfer.

### `cmd/` — the CLI, completions, and display

| Path | Role |
|------|------|
| `cmd/aims/` | **The `aims` binary.** `root.go` = `main()` + the boot dispatch (`runServer`/`runClient`, `isTeamserverCommand`). `commands.go` = `bindCommands` (groups the tree into *database* / *command & control* / *shell*) + `bindRunners` (attaches the lazy connect pre-run, skipping `teamserver` subtrees). Also holds the completion benchmarks + roundtrip/stream integration tests. |
| `cmd/display/` | **The single generic display engine.** A type-parameterized `map[string]func(T) string` per object feeds `Table` / `Details` / `Completions` alike — define presentation once. Weight drives responsive column dropping (tables) and section grouping (details). Styles/color in `defaults.go`/`color.go`. Deep-dive: [`DISPLAY.md`](./DISPLAY.md). |
| `cmd/<domain>/` | Per-domain cobra subtrees (`hosts`, `credentials`, `services`, `scan`, `c2`). Each exposes `Commands(client)` returning `list`/`add`/`rm`/`show`/`import`/`export`. `cmd/hosts/hosts.go` is the reference. `cmd/scan/` is the biggest (live scans, `diff`, `jobs`, drift history). |
| `cmd/completers/` | Shared completion plumbing + value completers (MACs, service names, source addresses, …). See `cmd/completers/COMPLETERS.md`. Completions are **live DB queries** reusing the same `DisplayFields`. |
| `cmd/bring/` + `cmd/agentctx/` | The `bring` feature — source a C2 agent's context into your live shell (env vars), so completions become agent-/host-aware. `agentctx` reads that env back (no in-process "current agent" state). Design: [`BRING.md`](./BRING.md). |
| `cmd/export/` | Reusable `import`/`export` subcommands (JSON/XML via protobuf reflection), hooked into each domain command. |
| `cmd/cache.go` | On-disk completion result cache (brief TTL so repeated Tabs are instant). |
| `cmd/commands.go` | Helpers: `BindGroup`, `BindFlags`, `CompleteFlags`, `CheckError` (gRPC status → plain error). |

### Supporting directories

| Dir | Role |
|-----|------|
| `db/` | `db/schema.go` `Migrate(db)` — the one big `AutoMigrate(...)` registering every `*ORM` type across all domains. UUID string PKs, cascading relations. Idempotent **across process restarts**, not if re-run in one process. |
| `internal/db/` | Generic persistence helpers: `FilterNew[T]` (dedup on insert), `Preload` (build association preload clauses from a filter map), per-domain `identical.go` comparators. The shared primitive the ingest fold reuses. |
| `internal/util/` | Small shared utilities. |
| `proto/` | **Codegen *support*, not the defs** (defs live in each `<domain>/pb/`). `proto/options/gorm.proto` (the `(gorm.field)` relation options), `proto/types/`, the `proto/template/…gorm.go.tmpl` gotemplate that emits the DB-helper files, and `proto/README.md`. The buf configs themselves are at the **repo root** (`buf.*.yaml`). |
| `contrib/` | Deploy tooling: `contrib/systemd/aims-teamserver.service` (systemd **user** unit) for running the teamserver as a persistent service. |
| `testdata/` | Fixtures (nmap XML, etc.) for ingest/roundtrip tests. |

## Boot mode: client vs. server

The binary decides at startup whether it is a server or a thin client, and **a thin client
never constructs the teamserver, opens the DB, or touches server-side state**:

- `cmd/aims/root.go main()` calls `boot.Run` (from `reeflective/team/boot`) with a `Server`
  and a `Client` callback. Mode resolution (in the team lib) probes for a **system client
  config** (`<app>_<user>_default.teamclient.cfg`, written by `aims teamserver user --system`).
- **Server mode** (`runServer`): the *only* path that builds the teamserver + DB. Two sub-cases —
  a bare `aims <cmd>` runs the **embedded console** (in-process client over a bufconn, served on
  first use); an `aims teamserver …` invocation (`ForceServer`) administers the real network
  daemon and must **not** prime the bufconn (else it would serve the in-memory pipe instead of
  binding TCP — a bug that was found and fixed).
- **Client mode** (`runClient`): builds only `client.New()` + `SetServerConfig(cfg)`; no
  teamserver, no DB. Server administration is unavailable (it lives under `teamserver`, which
  forces server mode).

The gRPC/mTLS transport itself now lives in **`reeflective/team/transports/grpc/{server,client}`**
(factored out of aims's old hand-fork; basis was Sliver's richer version). aims consumes it via a
`replace github.com/reeflective/team => ../../reeflective/team` in `go.mod` (interim, until team
is tagged). Background: memory `[[aims-team-transport-factoring]]`.

## "Where is …?" quick lookup

| I want to… | Look at |
|------------|---------|
| Add/change an object's fields | `<domain>/pb/*.proto`, then `make gen` — never hand-edit `*.pb.go` |
| Add a GORM relation | `(gorm.field)` options in the `.proto` (`belongs_to`/`many_to_many`/`type:uuid`) |
| Register a new table | add the `*ORM` type to `db/schema.go` `Migrate` |
| Implement/fix a CRUD method | `server/<domain>/<name>.go` (host = reference, credential = Delete example) |
| Change how an object renders (table/detail/completion) | that domain's root `<name>.go` `DisplayFields`/`DisplayHeaders`/`Completions`; engine in `cmd/display/` |
| Add a CLI command | `cmd/<domain>/*.go` `Commands()`, then wire in `cmd/aims/commands.go` `bindCommands` |
| Add a completion | `cmd/completers/` + the domain's `CompleteBy*` `ActionCallback`s (live DB queries; consider sub-category tags/order — a standing preference) |
| Touch dedup/identity/merge | `internal/db/` + domain `identical.go`; concepts in [`DEDUP.md`](./DEDUP.md) |
| Change transport/auth/mTLS | **`reeflective/team/transports/grpc/`** (not in this repo); aims-side wiring in `server/transport/server.go` + `client/client.go` |
| Change client-vs-server boot behavior | `cmd/aims/root.go` + `reeflective/team/boot` |
| Regenerate code from proto | `make gen` (buf ×2 + `protoc-go-inject-tag`); root `buf.*.yaml`; deps via `make deps` |
| Build / run | `go build -o aims ./cmd/aims` (deps published; a git-ignored local `go.work` shadows any ancestor workspace) |

## Documentation index

| Doc | Covers |
|-----|--------|
| [`README.md`](./README.md) | Public overview + quickstart |
| [`CLAUDE.md`](./CLAUDE.md) | Root context — architecture, pipeline, domain catalog, conventions |
| [`STATE.md`](./STATE.md) | Current state, build status, **per-service maturity matrix**, gotchas |
| [`ROADMAP.md`](./ROADMAP.md) | Re-entry plan / what to build next |
| [`SCAN.md`](./SCAN.md) | Scan model & scanner-plug substrate |
| [`SUBSTRATE.md`](./SUBSTRATE.md) | Ingest / target / diff / streaming substrate |
| [`DEDUP.md`](./DEDUP.md) | Identity, dedup, the merge fold |
| [`DISPLAY.md`](./DISPLAY.md) | The generic table/detail/completion display engine |
| [`COMPLETIONS.md`](./COMPLETIONS.md) | Live, cached, sub-categorized completions |
| [`CREDENTIALS.md`](./CREDENTIALS.md) | The credential domain in depth |
| [`BRING.md`](./BRING.md) | Sourcing a C2 agent context into the shell |
| `server/transport/README.md` | Teamserver construction + boot helpers |
| `proto/README.md` · `cmd/completers/COMPLETERS.md` · `cmd/aims/BENCH_COMPLETIONS.md` | Package-local notes |

## Gotchas worth knowing before you touch anything

- **Canonical import path is `github.com/d3c3ptive/aims`** even though the checkout sits under
  `maxlandon/aims` (org migration in progress). Always write `d3c3ptive` imports.
- **Plain `go build` works** — all deps are pinned to published versions (no local replaces). A
  git-ignored local `go.work` (`use .`) at the repo root shadows any ancestor workspace on the dev
  machine, so the build resolves against this module's `go.mod` directly.
- **Optional build tags:** `-tags maltego` (the `AsEntity()` integration; gondor dep still
  broken) and `-tags tailscale` (tsnet transport; breaks under new Go toolchains). Both off by
  default.
- **Prefer proto+regen over editing generated files.** Go-idiomatic behavior goes in the domain
  root `<name>.go`, not the generated `*.pb.go`/`*.pb.gorm.go`.
- **Whole-tree builds can flap** when multiple agents edit `cmd/scan`/`cmd/completers`
  concurrently — gauge your own work by building the packages you own in isolation.
