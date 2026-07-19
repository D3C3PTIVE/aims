package host

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
	pb "github.com/d3c3ptive/aims/host/pb"
	hosts "github.com/d3c3ptive/aims/host/pb/rpc"
	network "github.com/d3c3ptive/aims/network/pb"
)

// newTestServer returns a host server backed by a fresh, migrated sqlite database (pure-Go
// driver, one file per test) plus a context.
func newTestServer(t *testing.T) (*server, context.Context) {
	t.Helper()

	dsn := "file:" + filepath.Join(t.TempDir(), "aims.db")
	gdb, err := gorm.Open(gormlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := schema.Migrate(gdb); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return New(gdb), context.Background()
}

// readAll reads back every host with its ports (and their service/state) preloaded.
func readAll(t *testing.T, s *server, ctx context.Context) []*pb.Host {
	t.Helper()
	res, err := s.Read(ctx, &hosts.ReadHostRequest{
		Host:    &pb.Host{},
		Filters: &hosts.HostFilters{Ports: true},
	})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return res.GetHosts()
}

// webHost is 10.0.0.1 (web01) with a single open HTTP port — the seed host for the tests.
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

// TestCreateIsAdditiveAndIdempotent: Create inserts a new host, and re-creating the same host is
// a no-op (skipped by natural key) rather than a duplicate row.
func TestCreateIsAdditiveAndIdempotent(t *testing.T) {
	s, ctx := newTestServer(t)

	res, err := s.Create(ctx, &hosts.CreateHostRequest{Hosts: []*pb.Host{webHost()}})
	if err != nil {
		t.Fatalf("first create: %v", err)
	}
	if len(res.GetHosts()) != 1 {
		t.Fatalf("first create returned %d hosts, want 1", len(res.GetHosts()))
	}

	res2, err := s.Create(ctx, &hosts.CreateHostRequest{Hosts: []*pb.Host{webHost()}})
	if err != nil {
		t.Fatalf("second create: %v", err)
	}
	if len(res2.GetHosts()) != 0 {
		t.Errorf("re-creating an identical host inserted %d hosts, want 0 (skipped)", len(res2.GetHosts()))
	}

	all := readAll(t, s, ctx)
	if len(all) != 1 {
		t.Fatalf("db holds %d hosts after duplicate create, want 1", len(all))
	}
	if got := len(all[0].GetPorts()); got != 1 {
		t.Errorf("host has %d ports, want 1", got)
	}
}

// TestUpsertMergesAndIsIdempotent is the DEDUP.md prime directive end to end: re-importing the
// identical host writes nothing, and importing an enriched observation of the same host (new
// port, new hostname, same address) merges into the one record instead of duplicating or
// dropping — additive and idempotent.
func TestUpsertMergesAndIsIdempotent(t *testing.T) {
	s, ctx := newTestServer(t)

	if _, err := s.Create(ctx, &hosts.CreateHostRequest{Hosts: []*pb.Host{webHost()}}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Idempotent: upserting the identical host must not add rows.
	if _, err := s.Upsert(ctx, &hosts.UpsertHostRequest{Hosts: []*pb.Host{webHost()}}); err != nil {
		t.Fatalf("idempotent upsert: %v", err)
	}
	all := readAll(t, s, ctx)
	if len(all) != 1 || len(all[0].GetPorts()) != 1 {
		t.Fatalf("after idempotent upsert: %d hosts / %d ports, want 1 / 1", len(all), len(all[0].GetPorts()))
	}

	// Enriched: same machine (shared address), a new port and a new hostname.
	enriched := &pb.Host{
		Addresses: []*network.Address{{Addr: "10.0.0.1"}},
		Hostnames: []*pb.Hostname{{Name: "www"}},
		Ports: []*pb.Port{{
			Number:   443,
			Protocol: "tcp",
			State:    &pb.State{State: "open"},
			Service:  &network.Service{Name: "https", Product: "nginx"},
		}},
	}
	out, err := s.Upsert(ctx, &hosts.UpsertHostRequest{Hosts: []*pb.Host{enriched}})
	if err != nil {
		t.Fatalf("enriching upsert: %v", err)
	}
	if len(out.GetHosts()) != 1 {
		t.Fatalf("enriching upsert returned %d hosts, want 1", len(out.GetHosts()))
	}

	all = readAll(t, s, ctx)
	if len(all) != 1 {
		t.Fatalf("db holds %d hosts after enrichment, want 1 (merged, not duplicated)", len(all))
	}
	h := all[0]
	if got := len(h.GetPorts()); got != 2 {
		t.Errorf("merged host has %d ports, want 2 (80 + 443)", got)
	}
	if got := len(h.GetHostnames()); got != 2 {
		t.Errorf("merged host has %d hostnames, want 2 (web01 + www)", got)
	}
	if got := len(h.GetAddresses()); got != 1 {
		t.Errorf("merged host has %d addresses, want 1 (10.0.0.1 not duplicated)", got)
	}
}

// TestUpsertInsertsUnknownHost: an unmatched host is inserted, not dropped.
func TestUpsertInsertsUnknownHost(t *testing.T) {
	s, ctx := newTestServer(t)

	other := &pb.Host{
		Addresses: []*network.Address{{Addr: "10.0.0.2"}},
		Ports:     []*pb.Port{{Number: 22, Protocol: "tcp", State: &pb.State{State: "open"}}},
	}
	if _, err := s.Upsert(ctx, &hosts.UpsertHostRequest{Hosts: []*pb.Host{webHost(), other}}); err != nil {
		t.Fatalf("upsert two new hosts: %v", err)
	}

	if all := readAll(t, s, ctx); len(all) != 2 {
		t.Fatalf("db holds %d hosts, want 2", len(all))
	}
}
