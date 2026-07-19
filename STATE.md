# AIMS — Project State Overview

> Investigated 2026-07-19, after the repo had been paused ~1 year. Companion to
> [`CLAUDE.md`](./CLAUDE.md) (architecture) and [`ROADMAP.md`](./ROADMAP.md) (re-entry plan).
> This file answers: *where is the project right now, and what's broken.*

## TL;DR

The **data model + generated code layer is mature and compiles**. The **user-facing layer
(domain helpers + server + CLI) does not currently build** because the pinned
`github.com/maxlandon/gondor/maltego` dependency is itself broken. Read/Create gRPC paths
were implemented for the domains that got exercised; **mutations (Update/Delete/Upsert) are
almost all stubs.** It's a solid foundation with a partial, currently-non-compiling vertical
slice on top.

## History — three work bursts

Solo project (Maxime Landon), 92 commits, reconstructed from git:

| Period | What got built | Commits |
|--------|----------------|--------:|
| **Nov 2021** | Foundation: all proto data models + generated code (host, network, credentials à la Metasploit, scan/nmap), Makefile/buf codegen, Maltego tag script | 26 |
| **Jun–Aug 2023** | Client/server/gRPC layer, `reeflective/team` teamserver transport (mTLS + Tailscale), the generic `cmd/display` engine, cobra command tree | 34 |
| **Aug 2024** (last touch) | scan RPC, host/port dedup on insert, JSON/XML import-export, **c2 agents/channels**, display table/detail polish | 32 |

**Left off at:** wiring the c2 Agent/Channel domain end-to-end and polishing display fields —
the newest and least-finished area.

## Build status (updated 2026-07-19 — core now compiles)

The original gondor/maltego blocker (below) is resolved, along with a cascade of ~1-year
dependency drift it was masking. Current state of `GOWORK=off go build ./...`:

- ✅ **AIMS core compiles.** Every domain (`host`, `network`, `credential`, `scan/nmap`, `c2`),
  the generated `pb` layer, all per-domain gRPC servers (`server/<domain>`), the aggregate
  `server` package, the `client` (incl. `client/transport`), and every CLI package
  (`cmd/<domain>`, `cmd/display`, `cmd/export`) build clean.
- ❌ **`server/transport/` does not yet compile** — a `reeflective/team` **v0.3.2** API
  migration: `NamedLogger` now returns `*slog.Logger` (no `Infof/Errorf/Debugf`); the
  `grpc_logrus` middleware is gone; `server.Listener`/`WithListener` became
  `server.Handler`/`WithHandler`; and `GetConfig`/`AuditLogger`/`UsersTLSConfig`/
  `UserAuthenticate` signatures changed. `cmd/aims` (the binary) fails transitively.

### What was fixed to unblock the core

- **gondor/maltego isolated behind a `maltego` build tag.** All 20 `AsEntity()` methods moved
  into per-package `maltego.go` files guarded by `//go:build maltego`; the broken
  `github.com/maxlandon/gondor/maltego` import is dropped from default builds. Opt in with
  `-tags maltego` once gondor is repaired/replaced.
- **Tailscale transport isolated behind a `tailscale` build tag.** `server/transport/tailscale.go`
  is now `//go:build tailscale` with a `tailscale_stub.go` (`//go:build !tailscale`) returning
  a nil handler. This drops `tailscale.com/tsnet` → **gvisor** (which fails to compile under
  Go 1.26 at its 2023-pinned version) from the default build entirely. Opt in with `-tags tailscale`.
- **Follow-on drift fixes** (were masked behind the gondor failure): `credential.LanManagerHexCharacters`
  was undefined → replaced with a local `lanManagerMaxChars = 14` const; `client/transport/middleware.go`
  ported off `grpc_logrus` to slog; `client.New(...)` dropped its removed positional arg;
  `cmd/scan` carapace `.FilterArgs()` → `.Filter(c.Args)`.

### Toolchain note
Installed toolchain is **go1.26.3** (go.mod says `go 1.23.0`). The gvisor breakage is a
toolchain-vs-pinned-dep incompatibility (`//go:linkname` to runtime internals), which is why
build-tagging the Tailscale transport out was the pragmatic unblock rather than a dep bump.

---

### Original blocker (historical — now resolved via build tag)
Every domain root package imported `github.com/maxlandon/gondor/maltego` for its `AsEntity()`
methods, and that dependency did not build at its pinned version:
```
gondor/maltego/entity.go: undefined: base
gondor/maltego/entity.go: declared and not used: dir
gondor/maltego/entity.go: undefined: getDirectory
gondor/maltego/entity.go: undefined: configuration.Entity
gondor/maltego/entity.go: undefined: getNamePlural
```

## Implementation matrix (gRPC services)

| Service | Read/List | Create | Upd/Del/Upsert | Notes |
|---------|:--:|:--:|:--:|-------|
| host **Hosts** | ✅ | ✅ (with dedup) | ❌ stub | reference implementation |
| host **Users** | ❌ | ❌ | ❌ | all methods stubbed |
| network **Services** | ✅ | ❌ stub | ❌ stub | stray copy-pasted `ReadHost`/`ListHost`/`UpsertHost` stubs |
| credential **Credentials** | ✅ | ❌ stub | ❌ stub | |
| credential **Logins** | ❌ | ❌ | ❌ | all methods stubbed |
| scan **Scans** | ✅ | ✅ | ❌ stub | |
| c2 **Agents/Channels** | ✅ | ✅ | ❌ stub | file/type swap, see below |

## Known rough edges / gotchas

- **gondor Maltego dep is broken** — see Build status. Root blocker.
- **c2 file↔content swap:** `server/c2/channel.go` implements the **Agent** server
  (`type server`, `CreateAgentRequest`); `server/c2/agent.go` implements the **Channel**
  server (`type channelServer`, `CreateChannelRequest`). Filenames are inverted vs contents;
  their `Unimplemented` messages are mislabeled too.
- **Empty CLI handlers:** several command `RunE`s just `return nil` (e.g. `hosts add`,
  `hosts rm`) — command tree/completions exist but the actions are no-ops.
- **Debug leftovers in display path:** `println(c.Type)` in `host/host.go` (`Purpose`);
  `fmt.Println(val)` and empty `if head == "Purpose" {}` blocks in `cmd/display/details.go`.
- **`cmd/display/defaults.go` `init()` bug:** `stdoutTerm/stdinTerm/stderrTerm` assignments
  are crossed (stdout←os.Stderr, stderr←os.Stdin) — suspicious if output routing/size misbehaves.
- **`credential/core.go`** Metasploit-style scope helpers (`WhereLoggedInHost`, `WhereOriginIs`,
  …) are empty signatures — designed, not implemented.
- **Maltego `AsEntity()`** is half-done even where it's called: real in `host/group.go`
  (`maltego.NewEntity`), stubbed `return maltego.Entity{}` in `network/service.go`.
- **README drift:** mentions a `vendor/` dir and `proto/gen/` layout that don't match reality
  (deps come from the module cache; generated code sits next to each `.proto`).

## Codegen / infra facts (corrected)

- Codegen config lives at the **repo root**, not `proto/`: `buf.yaml`, `buf.lock`,
  `buf.work.yaml`, `buf.gen-gorm.yaml`, `buf.gen-grpc.yaml`, `maltego-tags.sh`, and the
  gotemplate under `proto/template/`. `make gen` runs `buf generate` (×2) + `maltego-tags.sh`.
- Canonical module path: **`github.com/d3c3ptive/aims`** (repo migrating to the `d3c3ptive`
  GitHub org; the `maxlandon` checkout path is going away). Note the `maxlandon/gondor` *dep*
  is a separate repo and part of the same namespace-migration question.
