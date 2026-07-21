package network

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
	"context"
	"path/filepath"
	"testing"

	_ "github.com/ncruces/go-sqlite3/embed" // loads the pure-Go SQLite (wazero) binary
	"github.com/ncruces/go-sqlite3/gormlite"
	"gorm.io/gorm"

	schema "github.com/d3c3ptive/aims/db"
	hostpb "github.com/d3c3ptive/aims/host/pb"
	hostrpc "github.com/d3c3ptive/aims/host/pb/rpc"
	"github.com/d3c3ptive/aims/network/pb"
	network "github.com/d3c3ptive/aims/network/pb/rpc"
	hostsrv "github.com/d3c3ptive/aims/server/host"
)

// newTestServer returns a service server backed by a fresh, migrated pure-Go sqlite DB, plus a host
// server on the SAME database: services are only ever created through host ingest (the service
// server's own Create is still a stub), so the host server is how these tests seed.
func newTestServer(t *testing.T) (*server, *gorm.DB, context.Context) {
	t.Helper()

	dsn := "file:" + filepath.Join(t.TempDir(), "aims.db")
	gdb, err := gorm.Open(gormlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := schema.Migrate(gdb); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return New(gdb), gdb, context.Background()
}

// hostWith builds a host at addr running one service per (port, name, product) triple.
func hostWith(addr string, svcs ...*pb.Service) *hostpb.Host {
	h := &hostpb.Host{Addresses: []*pb.Address{{Addr: addr}}}
	for i, svc := range svcs {
		h.Ports = append(h.Ports, &hostpb.Port{Number: uint32(1000 + i), Protocol: "tcp", Service: svc})
	}
	return h
}

func svc(name, product string) *pb.Service {
	return &pb.Service{Name: name, Product: product, Protocol: "tcp"}
}

// seed creates two hosts with distinct service sets and returns them read back (so their generated
// ids are available for the id-identity leg of the host scope).
func seed(t *testing.T, gdb *gorm.DB, ctx context.Context) []*hostpb.Host {
	t.Helper()

	hs := hostsrv.New(gdb)

	in := []*hostpb.Host{
		hostWith("10.0.0.1", svc("http", "nginx"), svc("ssh", "OpenSSH"), svc("https", "nginx")),
		hostWith("10.0.0.2", svc("smtp", "Postfix"), svc("http_alt", "lighttpd")),
	}
	if _, err := hs.Create(ctx, &hostrpc.CreateHostRequest{Hosts: in}); err != nil {
		t.Fatalf("seed create: %v", err)
	}

	res, err := hs.Read(ctx, &hostrpc.ReadHostRequest{
		Host:    &hostpb.Host{},
		Filters: &hostrpc.HostFilters{Ports: true},
	})
	if err != nil {
		t.Fatalf("seed read back: %v", err)
	}
	if len(res.GetHosts()) != 2 {
		t.Fatalf("seeded %d hosts, want 2", len(res.GetHosts()))
	}
	return res.GetHosts()
}

// hostByAddr picks a seeded host by its address.
func hostByAddr(t *testing.T, hosts []*hostpb.Host, addr string) *hostpb.Host {
	t.Helper()
	for _, h := range hosts {
		for _, a := range h.GetAddresses() {
			if a.GetAddr() == addr {
				return h
			}
		}
	}
	t.Fatalf("no seeded host at %s", addr)
	return nil
}

// TestListHostScopes locks the host/subnet scoping axis on services (ReadServiceRequest.Host): a set
// host restricts List to the services running on it, resolved either by the host's id or — with no
// id on the filter — by one of its addresses; a nil host is a no-op that returns every service.
func TestListHostScopes(t *testing.T) {
	s, gdb, ctx := newTestServer(t)
	hosts := seed(t, gdb, ctx)
	h1 := hostByAddr(t, hosts, "10.0.0.1")

	count := func(h *hostpb.Host) int {
		t.Helper()
		res, err := s.List(ctx, &network.ReadServiceRequest{Service: &pb.Service{}, Host: h})
		if err != nil {
			t.Fatalf("list (host=%v): %v", h, err)
		}
		return len(res.GetServices())
	}

	if n := count(nil); n != 5 {
		t.Errorf("nil host matched %d services, want all 5 (no-op)", n)
	}
	if n := count(&hostpb.Host{}); n != 5 {
		t.Errorf("empty host matched %d services, want all 5 (no-op)", n)
	}
	if n := count(&hostpb.Host{Id: h1.GetId()}); n != 3 {
		t.Errorf("host-by-id matched %d services, want 3", n)
	}
	// No id on the filter: the address identity leg must resolve to the same host.
	if n := count(&hostpb.Host{Addresses: []*pb.Address{{Addr: "10.0.0.2"}}}); n != 2 {
		t.Errorf("host-by-address matched %d services, want 2", n)
	}
	// A host that exists nowhere scopes to nothing rather than silently widening to everything.
	if n := count(&hostpb.Host{Addresses: []*pb.Address{{Addr: "203.0.113.9"}}}); n != 0 {
		t.Errorf("unknown host matched %d services, want 0", n)
	}
}

// TestListPrefixScopes locks the server-side service completion filter (ReadServiceRequest.Prefix):
// a set prefix restricts List to services whose name or product begins with it, an empty prefix is a
// no-op, and LIKE wildcards typed at the prompt match literally rather than as SQL wildcards.
func TestListPrefixScopes(t *testing.T) {
	s, gdb, ctx := newTestServer(t)
	seed(t, gdb, ctx)

	count := func(prefix string) int {
		t.Helper()
		res, err := s.List(ctx, &network.ReadServiceRequest{Service: &pb.Service{}, Prefix: prefix})
		if err != nil {
			t.Fatalf("list (prefix=%q): %v", prefix, err)
		}
		return len(res.GetServices())
	}

	if n := count(""); n != 5 {
		t.Errorf("empty prefix matched %d services, want all 5 (no-op)", n)
	}
	// "http" and "https" on 10.0.0.1, plus "http_alt" on 10.0.0.2 — the name leg.
	if n := count("http"); n != 3 {
		t.Errorf("prefix %q matched %d services, want 3 (name leg)", "http", n)
	}
	if n := count("ssh"); n != 1 {
		t.Errorf("prefix %q matched %d services, want 1", "ssh", n)
	}
	// The product leg: nginx backs both http and https on 10.0.0.1.
	if n := count("nginx"); n != 2 {
		t.Errorf("prefix %q matched %d services, want 2 (product leg)", "nginx", n)
	}
	if n := count("nfocontext"); n != 0 {
		t.Errorf("prefix %q matched %d services, want 0", "nfocontext", n)
	}
	// '_' is a SQL LIKE wildcard; escaped, "http_" must match the literal "http_alt" alone and not
	// "https", which an unescaped '_' would also match.
	if n := count("http_"); n != 1 {
		t.Errorf("prefix %q matched %d services, want 1 (underscore escaped, matched literally)", "http_", n)
	}
}

// TestListHostAndPrefixCompose locks the two axes composing: host scope AND prefix filter applied
// together narrow to their intersection, not to either one alone.
func TestListHostAndPrefixCompose(t *testing.T) {
	s, gdb, ctx := newTestServer(t)
	hosts := seed(t, gdb, ctx)
	h1 := hostByAddr(t, hosts, "10.0.0.1")

	res, err := s.List(ctx, &network.ReadServiceRequest{
		Service: &pb.Service{},
		Host:    &hostpb.Host{Id: h1.GetId()},
		Prefix:  "http",
	})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	// "http" and "https" live on 10.0.0.1; "http_alt" matches the prefix but is on the other host.
	if n := len(res.GetServices()); n != 2 {
		t.Fatalf("host+prefix matched %d services, want 2 (intersection)", n)
	}
	for _, s := range res.GetServices() {
		if s.GetName() == "http_alt" {
			t.Errorf("host scope leaked a service from the other host: %q", s.GetName())
		}
	}
}

// TestListHostReturnsHostContext locks the Read/List versus ReadHost/ListHost split the proto asks
// for: the plain variants return services alone, the *Host variants return the same services PLUS
// the distinct hosts they run on.
func TestListHostReturnsHostContext(t *testing.T) {
	s, gdb, ctx := newTestServer(t)
	hosts := seed(t, gdb, ctx)
	h1 := hostByAddr(t, hosts, "10.0.0.1")

	plain, err := s.List(ctx, &network.ReadServiceRequest{Service: &pb.Service{}, Host: &hostpb.Host{Id: h1.GetId()}})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if got := len(plain.GetHost()); got != 0 {
		t.Errorf("List returned %d hosts, want 0 (services alone)", got)
	}

	withHost, err := s.ListHost(ctx, &network.ReadServiceRequest{Service: &pb.Service{}, Host: &hostpb.Host{Id: h1.GetId()}})
	if err != nil {
		t.Fatalf("listhost: %v", err)
	}
	if got, want := len(withHost.GetServices()), len(plain.GetServices()); got != want {
		t.Errorf("ListHost returned %d services, want the same %d as List", got, want)
	}
	if got := len(withHost.GetHost()); got != 1 {
		t.Fatalf("ListHost returned %d hosts, want 1", got)
	}
	if got := withHost.GetHost()[0].GetId(); got != h1.GetId() {
		t.Errorf("ListHost returned host %s, want %s", got, h1.GetId())
	}
}
