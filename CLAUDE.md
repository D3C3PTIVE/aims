# AIMS — Attacked Infrastructure Modular Specification

> Root context file. Discovered & written 2026-07-19. This is an exploration report
> for the repository plus working guidance for future sessions.
>
> **Companion docs:** [`STATE.md`](./STATE.md) — current state & what's broken ·
> [`ROADMAP.md`](./ROADMAP.md) — re-entry plan.
>
> ✅ **Build status (updated 2026-07-19): the AIMS core now compiles.** The `maltego`/`gondor`
> blocker was isolated behind a `maltego` build tag, and the heavy Tailscale transport (which
> dragged in gvisor and broke on Go 1.26) behind a `tailscale` build tag. Default
> `GOWORK=off go build ./...` now compiles every domain, the generated `pb` layer, all
> per-domain gRPC servers, the `client`, and all CLI packages. **The one remaining non-building
> package is `server/transport/` (a `reeflective/team` v0.3.2 API migration — slog loggers +
> `WithHandler`/`Handler` + changed config/auth signatures), and `cmd/aims` transitively.**
> See STATE.md → Build status for the current boundary.

## What this project is

AIMS is a **shared data-model and object store for offensive-security tooling**. It is
*specification-first*, not logic-first: the repo declares the objects an attacker cares
about (hosts, networks, services, credentials, scans, C2 agents/channels) and gives them
first-class facilities so that **many different tools can contribute to and consume the
same database of the same objects**.

Think of it as *"MISP/STIX, but for the attacker's side"* — except the emphasis is on being
easy to move around, easy to store in SQL, and interoperable across languages and tools.

The README states it directly: *"There is no functional logic code in the project: just
types and their own facilities."* (That is the aspiration; in practice there is now a thin
client/server/CLI layer built on top — see State below.)

### The driving ideas (why it exists)

- **Battle-tested, ubiquitous data models.** The schemas deliberately mirror the object
  models of tools people already trust:
  - **nmap** for network/host architecture — `Host`, `Port`, `ExtraPort`, `OS`/`OSMatch`,
    `Trace`/`Hop`, `TCPSequence`, `Uptime`, `Script`, etc. Many proto fields carry `xml:"…"`
    tags that map **directly onto nmap's XML output** so nmap results unmarshal straight into
    the types (see `host/pb/host.proto`).
  - **Metasploit** for credentials — the `credential.Core` model (Private / Public / Realm /
    Origin / Login) is lifted from Metasploit's Credential API (see `credential/pb/core.proto`).
  - Other tools contribute their own idioms where relevant.
- **One shared database, many contributors.** Any tool can push objects in and read objects
  out over a common gRPC API + SQL store, working with the *same* object instances.
- **One set of CLI/code utilities around these objects** — to consult them, and to use them
  as **"targets"** of other tools (the `scan/target.go` notion, hosts-as-targets, etc.).
- **Interoperable technology-wise.** Protobuf is the source of truth (good multi-language
  codegen); Go is the first generated/implemented target; GORM makes the objects portable
  across SQL backends; struct tags make them ingest tool-native formats (nmap XML, Maltego).

## Architecture & code-generation pipeline

The whole repo is organized around **one pipeline**: `.proto` → generated Go PB types →
generated GORM ORM types → hand-written user-facing helpers + gRPC services + CLI.

```
 proto definitions        generated code                 hand-written layers
 ─────────────────        ──────────────                 ───────────────────
 <domain>/pb/*.proto  ─►  *.pb.go        (protoc-gen-go)
                          *.pb.gorm.go   (protoc-gen-gorm, infoblox)  ─►  server/<domain>/  (gRPC CRUD services)
 <domain>/pb/rpc/*.proto ─► *_grpc.pb.go (gRPC services)              ─►  client/           (gRPC client wrappers)
                                                                      ─►  <domain>/*.go     (native-type wrappers,
                                                                                              display, dedup helpers)
                                                                      ─►  cmd/<domain>/     (cobra CLI subcommands)
```

Key mechanisms:

- **Two representations per object**, produced by `infobloxopen/protoc-gen-gorm`:
  - `pb.Host` — the user-facing Protobuf Go type.
  - `pb.HostORM` — the GORM-storable type, with `ToPB(ctx)` / `ToORM(ctx)` converters.
  - Services convert PB→ORM to query/write, then ORM→PB to return. See
    `server/host/host.go` for the canonical Read/Create pattern.
- **Struct tags drive interoperability.** Proto files use `// @gotags:` comments (applied by
  `protoc-go-inject-tag`) to attach `xml:"…"` (nmap), `display:"…"` (CLI columns),
  `readonly`, `strict` tags to generated fields. GORM relations (`belongs_to`, `many_to_many`,
  `primary_key`, `type:uuid`) are expressed via `(gorm.field)` proto options from
  `proto/options/gorm.proto`.
- **DB schema** = `db/schema.go` `Migrate(db)` — one big `AutoMigrate(...)` registering every
  `*ORM` type across all domains. IDs are UUID strings; relations cascade.
- **Native wrapper types.** Each domain root file does `type Host pb.Host` to hang
  Go-idiomatic helpers (display formatting, OS/CPU guessing, dedup) off the generated types
  without polluting the generated code.
- **Dedup on insert.** `internal/db` provides generic `FilterNew[T]` + per-domain
  `AreHostsIdentical` / `identical.go` comparators so re-importing the same scan doesn't
  duplicate rows. `Preload` builds association preload clauses from a filter map.

## Domains (the object catalog)

| Domain        | Dir           | Core objects | Model heritage |
|---------------|---------------|--------------|----------------|
| Host          | `host/`       | `Host`, `Hostname`, `Port`, `ExtraPort`, `OS`/`OSMatch`/`OSFingerprint`, `User`, `Group`, `Process`, `FileSystem`/`File`, `Status`, `Uptime` | nmap |
| Network       | `network/`    | `Address`, `Service`, `Trace`/`Hop`, `Distance`, `Times`, `TCPSequence`/`IPIDSequence`, packets | nmap |
| Credential    | `credential/` | `Core` (Private/Public/Realm/Origin), `Login`, passwords, hashes (NTLM/replayable/nonreplayable), keys (public/private), certificates | Metasploit |
| Scan          | `scan/`       | `Run`, `Info`, `Stats`, `Target`, `ScanTask`, `TaskProgress`; nmap-specific under `scan/nmap` (`Script`, `Table`, `Element`) | nmap et al. |
| C2            | `c2/`         | `Agent`, `Channel`, `Task` | Sliver-like |

Each domain follows the same layout: `pb/*.proto` (defs) + `pb/*.pb.gorm.go` (generated) +
`pb/rpc/*.proto` (gRPC services) + `<name>.go` (native helpers) at the domain root.

## Client / Server / CLI

Built on **`reeflective/team`** (a teamserver/teamclient framework extracted from Sliver) —
gives multi-user auth, transports, and RPC plumbing for free.

- `cmd/aims/` — the `aims` binary. Boots a teamserver, an in-process AIMS gRPC client,
  migrates the DB, and binds the cobra command tree (`cmd/aims/root.go`).
- `server/` — `server.New(grpcServer, WithDatabase(db))` registers a gRPC service per domain
  (`server/host`, `server/credential`, `server/network`, `server/scan`, `server/c2`). Each
  service is a straight PB↔ORM CRUD shim over GORM.
- `client/` — `Client` struct holds one typed gRPC client per service; connects via the
  teamclient. `client/transport` handles the dialer/middleware.
- `server/transport/` — mTLS and **Tailscale** listeners (`tailscale.com` dep) plus middleware.
- `cmd/<domain>/` — cobra subcommands (`hosts list/add`, `services`, `credentials`, `scan`,
  `c2 agents/channels`). `cmd/display/` is a shared table/detail/completion/color renderer
  driven by the `display:"…"` field tags and per-type `DisplayFields`/`DisplayHeaders` maps.
- `cmd/export/` — export objects out.

## Build / regenerate

- **Canonical module path is `github.com/d3c3ptive/aims`.** The local checkout currently sits
  under `.../maxlandon/aims`, but the repo is being migrated to the `d3c3ptive` GitHub org and
  the `maxlandon` path is going away — always use `d3c3ptive` import paths. (One dependency,
  `github.com/maxlandon/gondor` used for the Maltego integration, is still `maxlandon`-namespaced;
  it is a *separate* repo and would need its own migration/replacement decision.)
- **Codegen config lives at the repo ROOT** (not in `proto/`): `buf.yaml`, `buf.lock`,
  `buf.work.yaml`, `buf.gen-gorm.yaml`, `buf.gen-grpc.yaml`, `maltego-tags.sh`, plus the
  gotemplate under `proto/template/{{.File.Name|dir}}/{{.File.Name|base}}.gorm.go.tmpl`
  (URL-encoded on disk) that emits the `*.proto.gorm.go` DB-helper files.
- `Makefile`:
  - `make deps` — installs `protoc-gen-go` and `protoc-go-inject-tag`.
  - `make gen` — runs `buf generate --template buf.gen-gorm.yaml` (go + gorm + gotemplate
    plugins) then `buf generate --template buf.gen-grpc.yaml` (go-grpc), then
    `./maltego-tags.sh` which runs `protoc-go-inject-tag` over every `*.pb.go` to apply the
    `// @gotags:` comments (xml/display/etc.). `managed.go_package_prefix` is pinned to
    `github.com/d3c3ptive/aims`.
- Building: this working copy is inside a `go.work` context, so plain `go build ./...`
  errors with *"directory prefix … does not contain modules listed in go.work"*. Use
  **`GOWORK=off go build ./...`** (or `go vet`) to build against `go.mod` directly. First
  build pulls a large tree (tailscale, gvisor, gRPC) — expect a slow initial `go mod download`.
- Go 1.21. Deps resolve from the module cache (no `vendor/` present despite the README).

## Current state (investigated 2026-07-19)

Solo project (Maxime Landon), 92 commits over **three distinct work bursts** — it has been
paused for ~1 year:

| Period | Focus | Commits |
|--------|-------|--------:|
| **Nov 2021** | Foundation: all proto data models + generated code (host, network, credential à la Metasploit, scan/nmap), Makefile/buf codegen, Maltego tag script | 26 |
| **Jun–Aug 2023** | Client/server/gRPC layer, `reeflective/team` teamserver transport (mTLS + Tailscale), the generic `cmd/display` engine, cobra command tree | 34 |
| **Aug 2024** (last) | scan RPC, host/port dedup on insert, JSON/XML import-export, **c2 agents/channels**, display table/detail polish | 32 |

**Where it was left off (Aug 2024):** wiring the c2 Agent/Channel domain end-to-end and
polishing display fields. That is the newest and least-finished area.

**Maturity: the model + generated layer is solid; the service/CLI layer is a partial
vertical slice.** Read/Create paths work for the domains that were exercised; mutation
(Update/Delete/Upsert) is almost entirely stubbed. Per-service gRPC status:

| Service | Read/List | Create | Update/Delete/Upsert | Notes |
|---------|:---------:|:------:|:--------------------:|-------|
| host (Hosts) | ✅ | ✅ (with dedup) | ❌ stub | reference implementation |
| host Users | ❌ | ❌ | ❌ | all methods stubbed |
| network Services | ✅ | ❌ stub | ❌ stub | also has copy-pasted `ReadHost`/`ListHost`/`UpsertHost` stubs |
| credential Credentials | ✅ | ❌ stub | ❌ stub | |
| credential Logins | ❌ | ❌ | ❌ | all methods stubbed |
| scan Scans | ✅ | ✅ | ❌ stub | |
| c2 Agents/Channels | ✅ | ✅ | ❌ stub | see swap quirk below |

### Known rough edges / gotchas

- **c2 file↔content swap:** `server/c2/channel.go` actually implements the **Agent** server
  (`type server`, `CreateAgentRequest`); `server/c2/agent.go` implements the **Channel**
  server (`type channelServer`, `CreateChannelRequest`). The filenames are inverted vs. their
  contents — confusing but functional. Their `Unimplemented` messages are likewise mislabeled.
- **Empty CLI handlers:** several command `RunE`s are stubs returning `nil` (e.g. `hosts add`,
  `hosts rm`) — the command tree/completions exist but some actions don't do anything yet.
- **Debug leftovers in the display path:** `println(c.Type)` in `host/host.go` (`Purpose`),
  a `fmt.Println(val)` and empty `if head == "Purpose" {}` blocks in `cmd/display/details.go`.
- **`credential/core.go`** scope helpers (`WhereLoggedInHost`, `WhereOriginIs`, …) are empty
  signatures — the Metasploit-style credential querying API is designed but not implemented.
- **Maltego `AsEntity()`** is inconsistent: some real (`host/group.go` → `maltego.NewEntity`),
  some stubbed (`network/service.go` → `return maltego.Entity{}`).
- **`init()` bug in `cmd/display/defaults.go`:** the `stdoutTerm`/`stdinTerm`/`stderrTerm`
  assignments are crossed (stdout set to Stderr, stderr set to Stdin) — worth a look if
  terminal-size/output routing misbehaves.
- README mentions a `vendor/` dir and a `proto/gen/` layout that don't match reality (deps
  come from the module cache; generated code sits next to each `.proto`, `paths=source_relative`).

### Suggested re-entry points if resuming

1. Finish the **Update/Delete/Upsert** gRPC methods (host domain is the template to copy).
2. Wire the empty CLI `RunE`s (`hosts add/rm`, etc.) to the now-existing services.
3. Untangle the **c2 file/type naming** before building further on agents/channels.
4. Complete the **Users/Logins** services (both fully stubbed).
5. Decide the **`maxlandon/gondor`** dependency's fate as part of the org migration.

When extending: prefer changing the **`.proto`** and regenerating (`make gen`) over editing
generated `*.pb.go`/`*.pb.gorm.go` by hand; put Go-idiomatic behavior in the domain root
`<name>.go` files; wire new CRUD in `server/<domain>` + `client` + `cmd/<domain>` following
the host domain as the reference implementation.

## CLI, completion & display layer

The user-facing consumption tooling is the second big theme of the repo (alongside the data
model). It is built around **cobra** (commands) + **carapace** (rich, described completions)
+ **jedib0t/go-pretty** (tables), with one shared generic display package driving all of it.

### The single generic display engine (`cmd/display/`)

Everything renders through **one type-parameterized pattern**: a `map[string]func(T) string`
that maps a **column/field name → a value-generator** for an object of type `T`. The same map
feeds tables, detail views, and completions — you define an object's presentation once.

- `Table[T](values, fields, opts...)` (`table.go`) — builds a go-pretty table. Columns come
  from `opts` headers; each cell = `fields[column](value)`. Post-processing pipeline:
  `removeEmptyColumns` (drop columns empty on every row) → weight filtering → **terminal-size
  adaptation** (`term.GetSize`, `getMaximumWeight`, `adaptTableSize`) so wide tables shed
  low-priority columns on narrow terminals.
- `Details[T](value, fields, opts...)` (`details.go`) — vertical "key: value" detail view for
  a single object. Headers are **grouped by weight**, and groups are separated by blank lines,
  so weight doubles as a section/priority grouping mechanism.
- `Completions[T](values, fields, opts...)` (`complete.go`) — turns objects into
  carapace `value\ndescription` pairs. One column is the **candidate** (the value inserted,
  e.g. `ID` or `Hostnames`) via `WithCandidateValue(header, fallback)`; the rest become the
  aligned description. `WithSplitCandidate(sep)` explodes list-valued fields (e.g. multiple
  hostnames) into separate candidates with a shared description.

### Options & weighting

`settings.go` defines the functional-options `opts` struct. **Weight is the core layout
primitive** — `WithHeader(name, weight)` assigns each column a weight 1–4; lower = higher
priority / shown first / shown on narrower terminals (thresholds in `terminalWeightSizes`:
1→80 cols, 2→160, 3→240, 4→320). In tables weight controls responsive column dropping; in
details it controls section grouping. Other options: `WithStyle`, `WithAutoSmallID` /
`FormatSmallID` (truncate UUIDs to 8 chars), `WithCandidateValue`, `WithSplitCandidate`.

### Per-object presentation lives in the domain package

Each domain root file (e.g. `host/host.go`) owns its presentation contract:
- `DisplayFields` — the `map[string]func(*pb.Host) string` value-generators. This is where
  domain display logic lives: OS/CPU guessing from nmap matches, colored/up-state IDs,
  route/hop rendering, joining repeated fields with newlines.
- `DisplayHeaders()` / `DisplayDetails()` / `Completions()` — return the weighted `[]Options`
  header sets for table / detail / completion contexts respectively.

### Styles & color (`defaults.go`, `color.go`)

- **`AIMSDefault`** is the default table style: borderless, no row separators, header
  underlined with `=`, `FormatTitle` headers — a clean minimal look. `AIMSBordersDefault` is a
  bordered `+`/`-`/`|` alternative; several go-pretty styles are also registered by name.
- Raw ANSI SGR escape constants (`Bold`, `Dim`, `FgYellow`, 256-color `Fmt(Fg+"214")`, …) are
  defined directly rather than only via `fatih/color`. Detail field names get a
  gray-bg/orange-fg chip (`colorDetailFieldName`), values are bold.

### Command wiring pattern (`cmd/<domain>/*.go`)

Each domain exposes a `Commands(client) *cobra.Command` returning a subtree
(`list` / `add` / `rm` / `show` / `import` / `export`). Reference impl: `cmd/hosts/hosts.go`.
- `list` → `client.<Svc>.Read(...)` then `display.Table(res, host.DisplayFields, host.DisplayHeaders()...)`.
- `show` → filters by ID prefix, then `display.Details(...)`; a `--traceroute` flag appends a
  `Route` column at weight 4.
- **Completions** (`CompleteByID`, `CompleteByHostnameOrIP`) are carapace `ActionCallback`s
  that connect via `client.ConnectComplete()`, `Read` from the server, and feed the objects
  through `display.Completions(...)` — i.e. **completions are live DB queries**, and reuse the
  exact same `DisplayFields` map as the tables.
- Helper plumbing in `cmd/commands.go`: `BindGroup` (attach a domain's commands under a help
  group), `BindFlags`, `CompleteFlags`, `CheckError` (unwrap gRPC status → plain error).
- `cmd/export/` provides reusable `import`/`export` subcommands that marshal objects via
  JSON/XML using protobuf reflection, hooked into each domain command.

Top-level assembly: `cmd/aims/commands.go` `bindCommands` groups everything into two help
groups — **"database"** (hosts, credentials, services, scan) and **"command & control"**
(agents, channels). `bindRunners` walks the tree and attaches the client-connect pre-run to
leaf commands (so completions/commands lazily connect to the teamserver only when needed).

> CLI-layer state note: several command bodies are still stubs (`hosts add`/`rm` `RunE` return
> `nil`), and there are debug leftovers in the display path (empty `if head == "Purpose" {}`
> blocks and a `fmt.Println(val)` in `details.go`; a `println(c.Type)` in `host.go`). The
> *design/engine* is solid and reusable; the per-command handlers are partially wired.

## Conventions

- Every source file carries the GPLv3 header block.
- UUID string primary keys; `CreatedAt`/`UpdatedAt` timestamps on most objects.
- `display:` tags + `cmd/display` = the single source of truth for CLI rendering.
- `xml:` tags = nmap-XML ingestion contract; keep them accurate when touching host/network.
