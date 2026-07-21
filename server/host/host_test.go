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
	nmap "github.com/d3c3ptive/aims/scan/pb/nmap"
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

// TestUpsertEnrichesExistingPort is the deep in-place enrichment contract: a second observation of
// a port the host already has must have its new evidence — a filled Service.Product, a new NSE
// script, a new state reason — written back onto the *existing* port row, not dropped and not
// duplicated onto a second port.
func TestUpsertEnrichesExistingPort(t *testing.T) {
	s, ctx := newTestServer(t)

	// Seed: 10.0.0.1 with port 80 open, service named http but no product yet, no scripts.
	seed := &pb.Host{
		Addresses: []*network.Address{{Addr: "10.0.0.1"}},
		Ports: []*pb.Port{{
			Number:   80,
			Protocol: "tcp",
			State:    &pb.State{State: "open"},
			Service:  &network.Service{Name: "http"},
		}},
	}
	if _, err := s.Create(ctx, &hosts.CreateHostRequest{Hosts: []*pb.Host{seed}}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Enrich the SAME port 80: fill the service product, add an NSE script and a state reason.
	enriched := &pb.Host{
		Addresses: []*network.Address{{Addr: "10.0.0.1"}},
		Ports: []*pb.Port{{
			Number:   80,
			Protocol: "tcp",
			Service:  &network.Service{Name: "http", Product: "nginx", Version: "1.25"},
			Scripts:  []*nmap.Script{{Name: "http-title", Output: "Welcome"}},
			Reasons:  []*pb.Reason{{Reason: "syn-ack"}},
		}},
	}
	if _, err := s.Upsert(ctx, &hosts.UpsertHostRequest{Hosts: []*pb.Host{enriched}}); err != nil {
		t.Fatalf("enriching upsert: %v", err)
	}

	// Read back with the port subtree fully preloaded.
	res, err := s.Read(ctx, &hosts.ReadHostRequest{
		Host:    &pb.Host{},
		Filters: &hosts.HostFilters{Ports: true, Scripts: true},
	})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	all := res.GetHosts()
	if len(all) != 1 {
		t.Fatalf("db holds %d hosts, want 1", len(all))
	}
	if got := len(all[0].GetPorts()); got != 1 {
		t.Fatalf("host has %d ports, want 1 (enriched in place, not duplicated)", got)
	}

	p := all[0].GetPorts()[0]
	if got := p.GetService().GetProduct(); got != "nginx" {
		t.Errorf("Service.Product = %q, want %q (fill-merged onto the existing service)", got, "nginx")
	}
	if got := p.GetService().GetVersion(); got != "1.25" {
		t.Errorf("Service.Version = %q, want %q (fill-merged onto the existing service)", got, "1.25")
	}
	if got := len(p.GetScripts()); got != 1 || (len(p.GetScripts()) == 1 && p.GetScripts()[0].GetName() != "http-title") {
		t.Errorf("port scripts = %v, want one http-title script (appended to the existing port)", p.GetScripts())
	}
	if got := len(p.GetReasons()); got != 1 {
		t.Errorf("port has %d reasons, want 1 (syn-ack appended to the existing port)", got)
	}
	// The original state observation is preserved (fill-only, never clobbered).
	if got := p.GetState().GetState(); got != "open" {
		t.Errorf("port state = %q, want %q (first observation preserved)", got, "open")
	}

	// Idempotent: re-applying the identical enrichment must not duplicate the script or reason
	// (only ID-less rows are appended, and these now carry DB IDs).
	if _, err := s.Upsert(ctx, &hosts.UpsertHostRequest{Hosts: []*pb.Host{enriched}}); err != nil {
		t.Fatalf("re-enriching upsert: %v", err)
	}
	res, err = s.Read(ctx, &hosts.ReadHostRequest{
		Host:    &pb.Host{},
		Filters: &hosts.HostFilters{Ports: true, Scripts: true},
	})
	if err != nil {
		t.Fatalf("read after re-enrich: %v", err)
	}
	p = res.GetHosts()[0].GetPorts()[0]
	if got := len(p.GetScripts()); got != 1 {
		t.Errorf("after idempotent re-enrich: %d scripts, want 1 (not duplicated)", got)
	}
	if got := len(p.GetReasons()); got != 1 {
		t.Errorf("after idempotent re-enrich: %d reasons, want 1 (not duplicated)", got)
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

// TestReadMaxResultsCaps locks the P4 fix: MaxResults>1 must LIMIT the result set (before the
// fix any value other than 1 loaded the whole table), ==1 returns a single row, and <=0 (unset)
// loads everything.
func TestReadMaxResultsCaps(t *testing.T) {
	s, ctx := newTestServer(t)

	seed := []*pb.Host{
		{Addresses: []*network.Address{{Addr: "10.0.0.1"}}},
		{Addresses: []*network.Address{{Addr: "10.0.0.2"}}},
		{Addresses: []*network.Address{{Addr: "10.0.0.3"}}},
	}
	if _, err := s.Create(ctx, &hosts.CreateHostRequest{Hosts: seed}); err != nil {
		t.Fatalf("seed create: %v", err)
	}

	read := func(max int64) int {
		t.Helper()
		res, err := s.Read(ctx, &hosts.ReadHostRequest{
			Host:    &pb.Host{},
			Filters: &hosts.HostFilters{MaxResults: max},
		})
		if err != nil {
			t.Fatalf("read (MaxResults=%d): %v", max, err)
		}
		return len(res.GetHosts())
	}

	if n := read(2); n != 2 {
		t.Fatalf("MaxResults=2 returned %d hosts, want 2 (LIMIT not applied)", n)
	}
	if n := read(1); n != 1 {
		t.Fatalf("MaxResults=1 returned %d hosts, want 1", n)
	}
	if n := read(0); n != 3 {
		t.Fatalf("MaxResults=0 returned %d hosts, want all 3", n)
	}
}

// TestReadPrefixScopes locks the server-side completion filter (HostFilters.Prefix): a set prefix
// restricts the read to hosts whose address OR hostname begins with it, an empty prefix is a no-op,
// and LIKE wildcards typed at the prompt are matched literally rather than as SQL wildcards.
func TestReadPrefixScopes(t *testing.T) {
	s, ctx := newTestServer(t)

	seed := []*pb.Host{
		{Addresses: []*network.Address{{Addr: "10.0.0.1"}}, Hostnames: []*pb.Hostname{{Name: "web01"}}},
		{Addresses: []*network.Address{{Addr: "10.0.0.2"}}, Hostnames: []*pb.Hostname{{Name: "web02"}}},
		{Addresses: []*network.Address{{Addr: "192.168.1.5"}}, Hostnames: []*pb.Hostname{{Name: "db01"}}},
		{Addresses: []*network.Address{{Addr: "172.16.0.9"}}, Hostnames: []*pb.Hostname{{Name: "a_b"}}},
	}
	if _, err := s.Create(ctx, &hosts.CreateHostRequest{Hosts: seed}); err != nil {
		t.Fatalf("seed create: %v", err)
	}

	count := func(prefix string) int {
		t.Helper()
		res, err := s.Read(ctx, &hosts.ReadHostRequest{
			Host:    &pb.Host{},
			Filters: &hosts.HostFilters{Prefix: prefix},
		})
		if err != nil {
			t.Fatalf("read (prefix=%q): %v", prefix, err)
		}
		return len(res.GetHosts())
	}

	if n := count("10.0.0"); n != 2 {
		t.Errorf("prefix %q matched %d hosts, want 2 (address leg)", "10.0.0", n)
	}
	if n := count("web"); n != 2 {
		t.Errorf("prefix %q matched %d hosts, want 2 (hostname leg)", "web", n)
	}
	if n := count("192"); n != 1 {
		t.Errorf("prefix %q matched %d hosts, want 1", "192", n)
	}
	if n := count(""); n != 4 {
		t.Errorf("empty prefix matched %d hosts, want all 4 (no-op)", n)
	}
	if n := count("nfocontext"); n != 0 {
		t.Errorf("prefix %q matched %d hosts, want 0", "nfocontext", n)
	}
	// '_' is a SQL LIKE wildcard; escaped, "a_b" must match the literal "a_b" hostname only and
	// not, say, an "axb" — there is no "axb" seeded, so the literal match returns exactly one.
	if n := count("a_b"); n != 1 {
		t.Errorf("prefix %q matched %d hosts, want 1 (underscore escaped, matched literally)", "a_b", n)
	}
}
