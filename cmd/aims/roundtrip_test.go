package main

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
	"testing"

	"github.com/d3c3ptive/aims/client"
	"github.com/d3c3ptive/aims/db"
	pb "github.com/d3c3ptive/aims/host/pb"
	hosts "github.com/d3c3ptive/aims/host/pb/rpc"
	network "github.com/d3c3ptive/aims/network/pb"
	scanpb "github.com/d3c3ptive/aims/scan/pb"
	scans "github.com/d3c3ptive/aims/scan/pb/rpc"
	"github.com/d3c3ptive/aims/server/transport"
)

// newInMemoryStack boots the exact production wiring from main(): an in-process reeflective/team
// teamserver serving every AIMS gRPC service over an in-memory bufconn, and an AIMS client whose
// per-domain stubs speak to it through the teamclient. It reuses team's builtin sqlite database
// and logging (sandboxed to a temp app dir via AIMS_ROOT_DIR), and returns a connected client.
//
// This is the only test that exercises the full CLI transport path — client → teamclient →
// bufconn → teamserver → AIMS services → GORM — rather than calling a server struct directly.
func newInMemoryStack(t testing.TB) *client.Client {
	t.Helper()

	// Sandbox team's on-disk db/config/logs to a throwaway dir (team reads <APP>_ROOT_DIR once,
	// at server.New time). t.Setenv also forbids t.Parallel, which we want: one teamserver "aims"
	// per test, isolated state.
	t.Setenv("AIMS_ROOT_DIR", t.TempDir())

	teamserver, opts, err := transport.NewTeamserver()
	if err != nil {
		t.Fatalf("NewTeamserver: %v", err)
	}

	con, err := client.New(opts...)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}

	// Mirror preRunServer + ConnectRun from cmd/aims: serve the in-memory teamclient (this also
	// connects it), migrate the AIMS schema onto team's builtin DB, then register the RPC stubs.
	if err := teamserver.Serve(con.Teamclient); err != nil {
		t.Fatalf("teamserver.Serve: %v", err)
	}
	if err := db.Migrate(teamserver.Database()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := con.Teamclient.Connect(); err != nil { // idempotent (sync.Once) after Serve.
		t.Fatalf("teamclient.Connect: %v", err)
	}
	if err := con.Init(); err != nil {
		t.Fatalf("client.Init: %v", err)
	}

	t.Cleanup(func() { _ = con.Disconnect() })

	return con
}

func webHost() *pb.Host {
	return &pb.Host{
		Addresses: []*network.Address{{Addr: "10.0.0.1"}},
		Hostnames: []*pb.Hostname{{Name: "web01"}},
		Ports: []*pb.Port{{
			Number:   80,
			Protocol: "tcp",
			State:    &pb.State{State: "open"},
			Service:  &network.Service{Name: "http", Product: "nginx"},
		}},
	}
}

// TestHostRoundTripOverTeamClient proves a command's Create/Read reach the database through the
// teamclient/teamserver stack: a host written with con.Hosts.Create comes back — with its ports
// preloaded — from con.Hosts.Read, over the in-memory gRPC transport.
func TestHostRoundTripOverTeamClient(t *testing.T) {
	con := newInMemoryStack(t)
	ctx := context.Background()

	created, err := con.Hosts.Create(ctx, &hosts.CreateHostRequest{Hosts: []*pb.Host{webHost()}})
	if err != nil {
		t.Fatalf("Hosts.Create over teamclient: %v", err)
	}
	if len(created.GetHosts()) != 1 {
		t.Fatalf("Create returned %d hosts, want 1", len(created.GetHosts()))
	}

	res, err := con.Hosts.Read(ctx, &hosts.ReadHostRequest{
		Host:    &pb.Host{},
		Filters: &hosts.HostFilters{Ports: true},
	})
	if err != nil {
		t.Fatalf("Hosts.Read over teamclient: %v", err)
	}

	got := res.GetHosts()
	if len(got) != 1 {
		t.Fatalf("Read returned %d hosts, want 1", len(got))
	}
	if n := len(got[0].GetPorts()); n != 1 {
		t.Errorf("read host has %d ports, want 1", n)
	}
	if names := got[0].GetHostnames(); len(names) != 1 || names[0].GetName() != "web01" {
		t.Errorf("read host hostnames = %v, want [web01]", names)
	}
}

// TestHostCreateIsIdempotentOverTeamClient proves the dedup-on-insert behaviour holds across the
// RPC boundary too: re-creating an identical host through the teamclient inserts nothing.
func TestHostCreateIsIdempotentOverTeamClient(t *testing.T) {
	con := newInMemoryStack(t)
	ctx := context.Background()

	if _, err := con.Hosts.Create(ctx, &hosts.CreateHostRequest{Hosts: []*pb.Host{webHost()}}); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	again, err := con.Hosts.Create(ctx, &hosts.CreateHostRequest{Hosts: []*pb.Host{webHost()}})
	if err != nil {
		t.Fatalf("second Create: %v", err)
	}
	if n := len(again.GetHosts()); n != 0 {
		t.Errorf("re-creating an identical host inserted %d hosts over RPC, want 0", n)
	}

	res, err := con.Hosts.Read(ctx, &hosts.ReadHostRequest{Host: &pb.Host{}})
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if n := len(res.GetHosts()); n != 1 {
		t.Errorf("db holds %d hosts after duplicate Create, want 1", n)
	}
}

// TestScanCreateOverTeamClient proves the `scan run` ingest path works over the transport: a
// scan Run submitted with con.Scans.Create (the exact call cmd/scan/run.go makes) is stored and
// its host surfaces through con.Hosts.Read.
func TestScanCreateOverTeamClient(t *testing.T) {
	con := newInMemoryStack(t)
	ctx := context.Background()

	run := &scanpb.Run{
		Scanner: "nmap",
		Hosts: []*pb.Host{{
			Addresses: []*network.Address{{Addr: "10.0.0.2"}},
			Ports:     []*pb.Port{{Number: 22, Protocol: "tcp", State: &pb.State{State: "open"}}},
		}},
	}

	res, err := con.Scans.Create(ctx, &scans.CreateScanRequest{Scans: []*scanpb.Run{run}})
	if err != nil {
		t.Fatalf("Scans.Create over teamclient: %v", err)
	}
	if len(res.GetScans()) != 1 {
		t.Fatalf("Scans.Create returned %d runs, want 1", len(res.GetScans()))
	}

	hostsRes, err := con.Hosts.Read(ctx, &hosts.ReadHostRequest{
		Host:    &pb.Host{},
		Filters: &hosts.HostFilters{Ports: true},
	})
	if err != nil {
		t.Fatalf("Hosts.Read after scan ingest: %v", err)
	}
	if n := len(hostsRes.GetHosts()); n != 1 {
		t.Fatalf("db holds %d hosts after scan ingest, want 1", n)
	}
}
