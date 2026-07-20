Transport
==========

Server-side glue between the AIMS gRPC services and the `reeflective/team` teamserver. This
package no longer contains a hand-forked gRPC/mTLS transport — that was factored out into the
shared, importable `reeflective/team/transports/grpc/{server,client}` package. What remains here
is the AIMS-specific *construction and boot wiring*.

## What's here

- `server.go`
  - `NewTeamserver() (*server.Server, *grpcserver.Handler, error)` — builds the team server and
    the default TCP+mTLS gRPC handler (`grpcserver.NewListener()`), enables the core Team service
    over the wire (`WithCoreServices()` → users/version), and registers the AIMS services via a
    **PostServe hook** (`registerServices`). It deliberately does **not** start a listener and
    does **not** prime the in-memory bufconn.
  - `InMemoryClientOptions(handler)` — primes the in-memory bufconn and returns dial options for
    an in-process teamclient. Call this **only** for the embedded local console. A network daemon
    must never prime a bufconn, or its `Listen()` would serve the in-memory pipe instead of
    binding the requested TCP address (this was a real, fixed bug).
  - `registerServices(handler)` — the PostServe hook run at serve time (for both the in-memory
    console and a network daemon, after the core teamserver DB is initialized). It migrates the
    AIMS schema (`db.Migrate`) and binds every AIMS gRPC service (`aims.New`). This is the single
    place the AIMS schema is migrated regardless of how the server starts.
- `tailscale.go` (`//go:build tailscale`) / `tailscale_stub.go` (`//go:build !tailscale`) — the
  opt-in Tailscale (tsnet) transport variant, which embeds the shared team handler and reuses its
  `ServeOn(ln)` seam. Off by default; enable with `-tags tailscale`.

## Boot mode

Whether the binary runs as an embedded server or a thin client is decided in `cmd/aims/root.go`
via `reeflective/team/boot`. The teamserver (and therefore the database) is constructed **only**
in the server callback — a thin client never calls `NewTeamserver()`. See the repository
[`NAVIGATION.md`](../../NAVIGATION.md#boot-mode-client-vs-server) for the full picture.
