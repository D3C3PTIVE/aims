# AIMS — Project State Overview

> Investigated 2026-07-19, after the repo had been paused ~1 year. Companion to
> [`CLAUDE.md`](./CLAUDE.md) (architecture), [`ROADMAP.md`](./ROADMAP.md) (re-entry plan) and
> [`SCAN.md`](./SCAN.md) (scan model & scanner-plug substrate).
> This file answers: *where is the project right now, and what's broken.*

## TL;DR

The **data model + generated code layer is mature**, and the **whole tree now builds and the
`aims` binary runs** (the gondor/maltego and Tailscale/gvisor blockers are gated behind build
tags). The user-facing layer is a **vertical slice filling out domain by domain**: host and
credential are full CRUD; Read/Create work broadly elsewhere; **Update/Delete/Upsert are still
stubbed on network, scan, and c2, and the Users/Logins services are entirely stubbed.** A solid
foundation with a real, compiling, partially-complete slice on top.

## History — three work bursts

Solo project (Maxime Landon), 92 commits, reconstructed from git:

| Period | What got built | Commits |
|--------|----------------|--------:|
| **Nov 2021** | Foundation: all proto data models + generated code (host, network, credentials à la Metasploit, scan/nmap), Makefile/buf codegen, Maltego tag script | 26 |
| **Jun–Aug 2023** | Client/server/gRPC layer, `reeflective/team` teamserver transport (mTLS + Tailscale), the generic `cmd/display` engine, cobra command tree | 34 |
| **Aug 2024** (last touch) | scan RPC, host/port dedup on insert, JSON/XML import-export, **c2 agents/channels**, display table/detail polish | 32 |

**Since resumed (2026-07):** build unblocked, then domain-by-domain depth — credential (full
CRUD), scan (host-fold ingest, live-state list/show), provenance/Source across domains, and a
CLI/display/completion polish pass. See CLAUDE.md for the live per-domain detail.

## Build status — the whole tree builds; the `aims` binary runs

The original gondor/maltego blocker is resolved (isolated behind a build tag), along with a
cascade of ~1-year dependency drift it was masking, and the `reeflective/team` v0.3.2 migration
is done. Current state of `GOWORK=off go build ./...`:

- ✅ **The whole tree builds — including `cmd/aims`.** Every domain (`host`, `network`,
  `credential`, `scan/nmap`, `c2`), the generated `pb` layer, all per-domain gRPC servers, the
  aggregate `server` package, `server/transport`, the `client`, every CLI package, and the
  **`aims` binary** build clean.
- ✅ **`server/transport/` compiles** — the `reeflective/team` **v0.3.2** API migration landed
  in `7749329` (slog loggers, `WithHandler`, changed `GetConfig`/auth signatures; Tailscale
  gated behind `-tags tailscale`). `cmd/aims` no longer fails transitively.
- ✅ **The binary runs.** `aims --help` shows the full command tree (database + C2 groups +
  `teamserver`); `aims scan run nmap …` executes and stores; its completions fire
  (`aims __complete scan run nmap --script ""` returns the NSE catalog). The nmap fork
  (`d3c3ptive/nmap`) is a real dependency via local `replace => ../nmap`.

> First build of `./...` (or `cmd/aims`) is slow — it compiles the large teamserver/gRPC tree;
> allow a few minutes. Subsequent builds are cached.

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

## Implementation matrix (gRPC services)

Verified 2026-07-20 against source. CLAUDE.md's table carries the same status with fuller notes.

| Service | Read/List | Create | Upsert | Delete | Notes |
|---------|:--:|:--:|:--:|:--:|-------|
| host **Hosts** | ✅ | ✅ (dedup) | ✅ | ❌ stub | reference impl.; DB-level fold + deep child enrichment (`saveMergedHost`/`saveMergedPorts`) done; Delete has scaffolding ending in Unimplemented (`server/host/host.go:480`) |
| host **Users** | ❌ | ❌ | ❌ | ❌ | all methods stubbed |
| network **Services** | ✅ | ❌ stub | ❌ stub | ❌ stub | Read/List + display/CLI slice done; mutations Unimplemented |
| credential **Credentials** | ✅ | ✅ | ✅ | ✅ | full CRUD; Delete resolves by identity when no ID given |
| credential **Logins** | ❌ | ❌ | ❌ | ❌ | all methods stubbed |
| scan **Scans** | ✅ | ✅ (host fold + `run_hosts` join) | ❌ stub | ❌ stub | Upsert/Delete/List `Unimplemented` (`server/scan/scan.go:289-297`); list/show CLI slice done |
| c2 **Agents/Channels** | ✅ | ✅ | ❌ stub | ❌ stub | type-name asymmetry, see below |

## Known rough edges / gotchas

- **c2 server type-name asymmetry (minor):** filenames match contents — `agent.go` is the
  **Agents** server (`type server`, `CreateAgentRequest`), `channel.go` the **Channels** server
  (`type channelServer`, `CreateChannelRequest`). Only wart: the Agents type is the generic
  `server` vs the specific `channelServer`; an optional `server`→`agentServer` rename squares it.
- **Empty CLI handlers:** several command `RunE`s just `return nil` (e.g. `hosts add`,
  `hosts rm`) — command tree/completions exist but the actions are no-ops.
- **`credential/core.go`** Metasploit-style scope helpers (`WhereLoggedInHost`, `WhereOriginIs`,
  …) are empty signatures — designed, not implemented.
- **Maltego `AsEntity()`** is half-done even where it's called: real in `host/group.go`
  (`maltego.NewEntity`), stubbed `return maltego.Entity{}` in `network/service.go`. Gated behind
  `-tags maltego`; gondor dep still broken at its pinned version (see Build status).
- **README drift:** mentions a `vendor/` dir and `proto/gen/` layout that don't match reality
  (deps come from the module cache; generated code sits next to each `.proto`).

> Fixed since the original survey (no longer issues): the display-path debug leftovers
> (`println`/`fmt.Println`/empty `if head == "Purpose"`); the crossed
> `stdoutTerm/stdinTerm/stderrTerm` `init()`; and the stray copy-pasted `ReadHost`/`ListHost`/
> `UpsertHost` stubs in `server/network/service.go`.

## Codegen / infra facts (corrected)

- Codegen config lives at the **repo root**, not `proto/`: `buf.yaml`, `buf.lock`,
  `buf.work.yaml`, `buf.gen-gorm.yaml`, `buf.gen-grpc.yaml`, `maltego-tags.sh`, and the
  gotemplate under `proto/template/`. `make gen` runs `buf generate` (×2) + `maltego-tags.sh`.
- Canonical module path: **`github.com/d3c3ptive/aims`** (repo migrating to the `d3c3ptive`
  GitHub org; the `maxlandon` checkout path is going away). Note the `maxlandon/gondor` *dep*
  is a separate repo and part of the same namespace-migration question.
