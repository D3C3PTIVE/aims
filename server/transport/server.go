package transport

/*
   AIMS (Attacked Infrastructure Modular Specification)
   Copyright (C) 2021 Maxime Landon

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

import (
	"google.golang.org/grpc"

	"github.com/reeflective/team/server"
	grpcserver "github.com/reeflective/team/transports/grpc/server"

	"github.com/d3c3ptive/aims/db"
	aims "github.com/d3c3ptive/aims/server"
)

// NewTeamserver builds an AIMS teamserver and its transport stacks (TCP+mTLS
// gRPC by default, plus the opt-in Tailscale variant), WITHOUT starting any
// listener and WITHOUT priming an in-memory connection. It returns the
// teamserver and its default gRPC handler; all errors are critical.
//
// Crucially, this does NOT open the in-memory bufconn. Priming a bufconn on the
// default handler would make a network daemon's Listen() serve that in-memory
// pipe instead of binding the requested TCP address. The in-memory teamclient
// connection is set up separately, and only for the embedded local console, via
// InMemoryClientOptions.
func NewTeamserver() (team *server.Server, handler *grpcserver.Handler, err error) {
	// The default TCP+mTLS gRPC stack, from the shared team transport.
	tlsListener := grpcserver.NewListener()
	tlsListener.WithCoreServices() // Expose team users/version over the wire.
	tlsListener.PostServe(registerServices(tlsListener))

	// The opt-in Tailscale variant (nil when built without `-tags tailscale`).
	tailscaleListener := newTeamserverTailScale()

	serverOpts := []server.Options{
		server.WithDefaultPort(31448),
		server.WithHandler(tlsListener),       // Default TCP+mTLS gRPC stack.
		server.WithHandler(tailscaleListener), // Tailscale variant (nil = skipped).
	}

	teamserver, err := server.New("aims", serverOpts...)
	if err != nil {
		return nil, nil, err
	}

	return teamserver, tlsListener, nil
}

// InMemoryClientOptions primes an in-memory (bufconn) connection on the given
// gRPC handler and returns the dial options for an in-process teamclient of it.
//
// Call this ONLY for the embedded local console. A network daemon must never
// prime a bufconn: the handler decides in-memory-vs-TCP by whether a bufconn is
// primed, so a primed daemon would serve the in-memory pipe instead of binding
// its TCP address.
func InMemoryClientOptions(handler *grpcserver.Handler) []grpc.DialOption {
	return grpcserver.NewClientFrom(handler)
}

// registerServices returns a PostServe hook that (1) ensures the AIMS schema
// exists on the teamserver database and (2) binds all AIMS gRPC services onto
// the transport's gRPC server. It runs at serve time — for both the in-memory
// console and a network daemon — after the core teamserver database has been
// initialized, so it is the single place the AIMS schema is migrated regardless
// of how the server is started.
func registerServices(h *grpcserver.Handler) func(*grpc.Server) error {
	return func(grpcServer *grpc.Server) error {
		if err := db.Migrate(h.Database()); err != nil {
			return err
		}

		aims.New(grpcServer, aims.WithDatabase(h.Database()))

		return nil
	}
}
