package credential

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

	credpb "github.com/d3c3ptive/aims/credential/pb"
	credentials "github.com/d3c3ptive/aims/credential/pb/rpc"
	schema "github.com/d3c3ptive/aims/db"
	hostpb "github.com/d3c3ptive/aims/host/pb"
	hostrpc "github.com/d3c3ptive/aims/host/pb/rpc"
	netpb "github.com/d3c3ptive/aims/network/pb"
	provenance "github.com/d3c3ptive/aims/provenance/pb"
	hostsrv "github.com/d3c3ptive/aims/server/host"
)

// newHostScopedServer returns a credential server plus the gorm handle behind it, so the host
// domain can be seeded on the SAME database — credentials reach a host through their provenance
// (sources.service_id -> ports.host_id), so the host/port/service rows have to exist for the scope
// to resolve to anything.
func newHostScopedServer(t *testing.T) (*server, *gorm.DB, context.Context) {
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

// seedHostsWithServices creates two hosts, each running one service, and returns them read back so
// their generated host ids and service ids are available.
func seedHostsWithServices(t *testing.T, gdb *gorm.DB, ctx context.Context) []*hostpb.Host {
	t.Helper()

	hs := hostsrv.New(gdb)
	in := []*hostpb.Host{
		{
			Addresses: []*netpb.Address{{Addr: "10.0.0.1"}},
			Ports:     []*hostpb.Port{{Number: 22, Protocol: "tcp", Service: &netpb.Service{Name: "ssh"}}},
		},
		{
			Addresses: []*netpb.Address{{Addr: "10.0.0.2"}},
			Ports:     []*hostpb.Port{{Number: 3306, Protocol: "tcp", Service: &netpb.Service{Name: "mysql"}}},
		},
	}
	if _, err := hs.Create(ctx, &hostrpc.CreateHostRequest{Hosts: in}); err != nil {
		t.Fatalf("seed hosts: %v", err)
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

// serviceIDOn returns the id of the (single) service running on the seeded host at addr.
func serviceIDOn(t *testing.T, hosts []*hostpb.Host, addr string) (hostID, serviceID string) {
	t.Helper()
	for _, h := range hosts {
		for _, a := range h.GetAddresses() {
			if a.GetAddr() != addr {
				continue
			}
			for _, p := range h.GetPorts() {
				if svc := p.GetService(); svc.GetId() != "" {
					return h.GetId(), svc.GetId()
				}
			}
		}
	}
	t.Fatalf("no seeded service on host %s", addr)
	return "", ""
}

// credOn builds a username/password credential whose provenance says it was gathered from the given
// service — the link credential.WhereLoggedInHost walks back to a host.
func credOn(username, serviceID string) *credpb.Core {
	return &credpb.Core{
		Public:  &credpb.Public{Type: credpb.PublicType_Username, Username: username},
		Private: &credpb.Private{Type: credpb.PrivateType_Password, Data: "pw-" + username},
		Sources: []*provenance.Source{{
			Tool:      "hydra",
			Type:      provenance.SourceType_Service,
			ServiceId: serviceID,
		}},
	}
}

// TestListHostScopes locks the host/subnet scoping axis on credentials
// (ReadCredentialRequest.Host): a set host restricts List to the credentials gathered from a service
// running on it — resolved by the host's id, or by one of its addresses when the filter carries no
// id — while a nil host is a no-op returning every credential.
func TestListHostScopes(t *testing.T) {
	s, gdb, ctx := newHostScopedServer(t)
	hosts := seedHostsWithServices(t, gdb, ctx)

	sshHost, sshSvc := serviceIDOn(t, hosts, "10.0.0.1")
	_, sqlSvc := serviceIDOn(t, hosts, "10.0.0.2")

	seed := []*credpb.Core{
		credOn("root", sshSvc),
		credOn("deploy", sshSvc),
		credOn("dbadmin", sqlSvc),
		// A credential with no service provenance at all: it belongs to no host, so every host
		// scope must exclude it while the unscoped view still returns it.
		{
			Public:  &credpb.Public{Type: credpb.PublicType_Username, Username: "orphan"},
			Private: &credpb.Private{Type: credpb.PrivateType_Password, Data: "pw-orphan"},
		},
	}
	if _, err := s.Create(ctx, &credentials.CreateCredentialRequest{Credentials: seed}); err != nil {
		t.Fatalf("seed creds: %v", err)
	}

	count := func(h *hostpb.Host) int {
		t.Helper()
		res, err := s.List(ctx, &credentials.ReadCredentialRequest{Credential: &credpb.Core{}, Host: h})
		if err != nil {
			t.Fatalf("list (host=%v): %v", h, err)
		}
		return len(res.GetCredentials())
	}

	if n := count(nil); n != 4 {
		t.Errorf("nil host matched %d creds, want all 4 (no-op)", n)
	}
	if n := count(&hostpb.Host{}); n != 4 {
		t.Errorf("empty host matched %d creds, want all 4 (no-op)", n)
	}
	if n := count(&hostpb.Host{Id: sshHost}); n != 2 {
		t.Errorf("host-by-id matched %d creds, want 2 (root, deploy)", n)
	}
	// No id on the filter: the address identity leg must resolve to the same host.
	if n := count(&hostpb.Host{Addresses: []*netpb.Address{{Addr: "10.0.0.2"}}}); n != 1 {
		t.Errorf("host-by-address matched %d creds, want 1 (dbadmin)", n)
	}
	// A host that exists nowhere scopes to nothing rather than silently widening to everything.
	if n := count(&hostpb.Host{Addresses: []*netpb.Address{{Addr: "203.0.113.9"}}}); n != 0 {
		t.Errorf("unknown host matched %d creds, want 0", n)
	}
}

// TestListHostAndPrefixCompose locks the host axis composing with the completion prefix filter that
// was already there: both applied together narrow to their intersection, not to either alone.
func TestListHostAndPrefixCompose(t *testing.T) {
	s, gdb, ctx := newHostScopedServer(t)
	hosts := seedHostsWithServices(t, gdb, ctx)

	sshHost, sshSvc := serviceIDOn(t, hosts, "10.0.0.1")
	_, sqlSvc := serviceIDOn(t, hosts, "10.0.0.2")

	seed := []*credpb.Core{
		credOn("deploy", sshSvc),
		credOn("developer", sshSvc),
		credOn("root", sshSvc),
		// Same "de" prefix, but on the other host: the host scope must exclude it.
		credOn("debug", sqlSvc),
	}
	if _, err := s.Create(ctx, &credentials.CreateCredentialRequest{Credentials: seed}); err != nil {
		t.Fatalf("seed creds: %v", err)
	}

	res, err := s.List(ctx, &credentials.ReadCredentialRequest{
		Credential: &credpb.Core{},
		Host:       &hostpb.Host{Id: sshHost},
		Prefix:     "de",
	})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if n := len(res.GetCredentials()); n != 2 {
		t.Fatalf("host+prefix matched %d creds, want 2 (deploy, developer)", n)
	}
	for _, c := range res.GetCredentials() {
		if c.GetPublic().GetUsername() == "debug" {
			t.Error("host scope leaked a credential from the other host: debug")
		}
	}
}
