package scan

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
	hostrpcpb "github.com/d3c3ptive/aims/host/pb/rpc"
	network "github.com/d3c3ptive/aims/network/pb"
	netrpcpb "github.com/d3c3ptive/aims/network/pb/rpc"
	scanpb "github.com/d3c3ptive/aims/scan/pb"
	scanrpcpb "github.com/d3c3ptive/aims/scan/pb/rpc"
	hostsrv "github.com/d3c3ptive/aims/server/host"
	netsrv "github.com/d3c3ptive/aims/server/network"
)

// newTestServer returns a scan server backed by a fresh, migrated sqlite database (pure-Go driver,
// one file per test) plus a context.
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

// runObserving builds a scan Run with a distinct RawXML (so it is not skipped as a duplicate) that
// observed one host at 10.0.0.1 with a single open port.
func runObserving(rawXML string, port uint32, service string) *scanpb.Run {
	return &scanpb.Run{
		Scanner: "nmap",
		RawXML:  rawXML,
		Hosts: []*hostpb.Host{{
			Addresses: []*network.Address{{Addr: "10.0.0.1"}},
			Hostnames: []*hostpb.Hostname{{Name: "web01"}},
			Ports: []*hostpb.Port{{
				Number:   port,
				Protocol: "tcp",
				State:    &hostpb.State{State: "open"},
				Service:  &network.Service{Name: service},
			}},
		}},
	}
}

// countRows returns the number of rows in a table.
func countRows(t *testing.T, gdb *gorm.DB, table string) int64 {
	t.Helper()
	var n int64
	if err := gdb.Table(table).Count(&n).Error; err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

// TestCreateStampsAndScopesProvenance is the end-to-end provenance contract: a scan ingest stamps
// a provenance.Source (Tool=Scanner) onto the hosts it produces, persists it through the host
// fold, and the per-tool query scope (HostFilters.Source / WhereContributedBy) returns only the
// hosts a given tool contributed.
func TestCreateStampsAndScopesProvenance(t *testing.T) {
	s, gdb, ctx := newTestServer(t)

	if _, err := s.Create(ctx, &scanrpcpb.CreateScanRequest{Scans: []*scanpb.Run{runObserving("<xml>P</xml>", 443, "https")}}); err != nil {
		t.Fatalf("create run: %v", err)
	}

	// Provenance persisted and DEDUPED: the whole run's co-produced objects (host + address +
	// port + service) reference ONE shared source row, not one per object. The host and the
	// service it produced must point at the same source_id.
	if n := countRows(t, gdb, "host_sources"); n == 0 {
		t.Fatal("host not linked to provenance (host_sources join empty)")
	}
	var hostSrc, svcSrc string
	if err := gdb.Table("host_sources").Select("source_id").Limit(1).Scan(&hostSrc).Error; err != nil {
		t.Fatalf("read host_sources: %v", err)
	}
	if err := gdb.Table("service_sources").Select("source_id").Limit(1).Scan(&svcSrc).Error; err != nil {
		t.Fatalf("read service_sources: %v", err)
	}
	if hostSrc == "" || hostSrc != svcSrc {
		t.Fatalf("co-produced host and service should share one source row: host=%q service=%q", hostSrc, svcSrc)
	}
	// That shared object row + the run's own producer row = 2 provenance rows for this scan,
	// not one per object.
	if n := countRows(t, gdb, "sources"); n != 2 {
		t.Fatalf("expected 2 source rows (1 shared object + 1 run producer), got %d", n)
	}
	var tool string
	if err := gdb.Table("sources").Select("tool").Limit(1).Scan(&tool).Error; err != nil {
		t.Fatalf("read source tool: %v", err)
	}
	if tool != "nmap" {
		t.Fatalf("stamped source tool = %q, want nmap", tool)
	}

	// Per-tool scoping: the contributing tool sees the host; another tool sees nothing.
	hsrv := hostsrv.New(gdb)
	mine, err := hsrv.Read(ctx, &hostrpcpb.ReadHostRequest{Host: &hostpb.Host{}, Filters: &hostrpcpb.HostFilters{Source: "nmap"}})
	if err != nil {
		t.Fatalf("read scoped to nmap: %v", err)
	}
	if len(mine.GetHosts()) != 1 {
		t.Fatalf("WhereContributedBy(nmap) returned %d hosts, want 1", len(mine.GetHosts()))
	}
	other, err := hsrv.Read(ctx, &hostrpcpb.ReadHostRequest{Host: &hostpb.Host{}, Filters: &hostrpcpb.HostFilters{Source: "metasploit"}})
	if err != nil {
		t.Fatalf("read scoped to metasploit: %v", err)
	}
	if len(other.GetHosts()) != 0 {
		t.Fatalf("WhereContributedBy(metasploit) returned %d hosts, want 0", len(other.GetHosts()))
	}

	// The same per-tool scope works for a second domain: the produced service is stamped and
	// filterable through the network server (service_sources join).
	if n := countRows(t, gdb, "service_sources"); n == 0 {
		t.Fatal("service not linked to provenance (service_sources empty)")
	}
	nsrv := netsrv.New(gdb)
	svc, err := nsrv.Read(ctx, &netrpcpb.ReadServiceRequest{Service: &network.Service{}, Source: "nmap"})
	if err != nil {
		t.Fatalf("read services scoped to nmap: %v", err)
	}
	if len(svc.GetServices()) != 1 {
		t.Fatalf("service WhereContributedBy(nmap) returned %d, want 1", len(svc.GetServices()))
	}
}

// TestCreateUnifiesHostAcrossRuns is the cross-run host-row unification contract: two *different*
// runs (distinct RawXML) that each observed the same physical host must share ONE host row — linked
// to both runs via run_hosts and enriched with the union of both runs' ports — not a private host
// copy per run.
func TestCreateUnifiesHostAcrossRuns(t *testing.T) {
	s, gdb, ctx := newTestServer(t)

	// Run A: 10.0.0.1 with port 22 open.
	resA, err := s.Create(ctx, &scanrpcpb.CreateScanRequest{Scans: []*scanpb.Run{runObserving("<xml>A</xml>", 22, "ssh")}})
	if err != nil {
		t.Fatalf("create run A: %v", err)
	}
	if len(resA.GetScans()) != 1 {
		t.Fatalf("run A created %d runs, want 1", len(resA.GetScans()))
	}

	// Run B: the same host, but port 80 open — a different scan of the same machine.
	resB, err := s.Create(ctx, &scanrpcpb.CreateScanRequest{Scans: []*scanpb.Run{runObserving("<xml>B</xml>", 80, "http")}})
	if err != nil {
		t.Fatalf("create run B: %v", err)
	}
	if len(resB.GetScans()) != 1 {
		t.Fatalf("run B created %d runs, want 1", len(resB.GetScans()))
	}

	// Two distinct runs were stored.
	if got := countRows(t, gdb, "runs"); got != 2 {
		t.Fatalf("db holds %d runs, want 2", got)
	}

	// But only ONE host row — the machine is unified across both runs.
	if got := countRows(t, gdb, "hosts"); got != 1 {
		t.Fatalf("db holds %d hosts, want 1 (unified across runs, not one per run)", got)
	}

	// The shared host carries the union of both runs' ports.
	if got := countRows(t, gdb, "ports"); got != 2 {
		t.Errorf("db holds %d ports, want 2 (22 from A + 80 from B on the one host)", got)
	}

	// The one host is joined to BOTH runs.
	if got := countRows(t, gdb, "run_hosts"); got != 2 {
		t.Errorf("run_hosts holds %d links, want 2 (the shared host linked to run A and run B)", got)
	}

	// Read run B back with its hosts, and confirm the shared host is reachable through it.
	read, err := s.Read(ctx, &scanrpcpb.ReadScanRequest{
		Scan:    &scanpb.Run{Id: resB.GetScans()[0].GetId()},
		Filters: &scanrpcpb.RunFilters{Hosts: true},
	})
	if err != nil {
		t.Fatalf("read run B: %v", err)
	}
	if len(read.GetScans()) != 1 {
		t.Fatalf("read run B returned %d runs, want 1", len(read.GetScans()))
	}
	if got := len(read.GetScans()[0].GetHosts()); got != 1 {
		t.Errorf("run B links %d hosts, want 1 (the shared host)", got)
	}
}

// TestCreateSkipsDuplicateRun: re-importing the exact same run (same RawXML) is an idempotent no-op
// — no new run row, no new host row, and an empty Scans response the CLI renders as "skipped".
func TestCreateSkipsDuplicateRun(t *testing.T) {
	s, gdb, ctx := newTestServer(t)

	if _, err := s.Create(ctx, &scanrpcpb.CreateScanRequest{Scans: []*scanpb.Run{runObserving("<xml>same</xml>", 22, "ssh")}}); err != nil {
		t.Fatalf("first create: %v", err)
	}

	res, err := s.Create(ctx, &scanrpcpb.CreateScanRequest{Scans: []*scanpb.Run{runObserving("<xml>same</xml>", 22, "ssh")}})
	if err != nil {
		t.Fatalf("duplicate create: %v", err)
	}
	if len(res.GetScans()) != 0 {
		t.Errorf("re-importing the identical run created %d runs, want 0 (skipped)", len(res.GetScans()))
	}

	if got := countRows(t, gdb, "runs"); got != 1 {
		t.Errorf("db holds %d runs after duplicate import, want 1", got)
	}
	if got := countRows(t, gdb, "hosts"); got != 1 {
		t.Errorf("db holds %d hosts after duplicate import, want 1", got)
	}
}
