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

// BenchmarkServerRead / BenchmarkServerList / BenchmarkServerUpsert measure the scan gRPC service
// straight against the gormlite DB (no teamserver, no gRPC framing) — the pure DB+ORM cost that
// MaxResults capping / indexing target (reviews/benchmark-review.md §B #1). Read/List share one
// query path (List == Read); the difference the benches exercise is the host-subtree preload
// (Filters.Hosts) versus the bare run-row list.
//
// BenchmarkScanIngest measures the per-run host-fold amplifier (§B #3): Create/persistRun re-loads
// the growing host tree on EVERY run, so K runs that all observe the same N hosts pay the cross-run
// O(K·N) reload — the case a run-to-run diff of a long series drives.
//
// Setup is excluded from the timed region. Reads do not mutate, so a seeded server is reused across
// a read benchmark's iterations; the ingest benchmark mutates, so each iteration gets a fresh DB.
import (
	"context"
	"fmt"
	"path/filepath"
	"testing"

	_ "github.com/ncruces/go-sqlite3/embed" // loads the pure-Go SQLite (wazero) binary
	"github.com/ncruces/go-sqlite3/gormlite"
	"gorm.io/gorm"

	schema "github.com/d3c3ptive/aims/db"
	hostpb "github.com/d3c3ptive/aims/host/pb"
	network "github.com/d3c3ptive/aims/network/pb"
	scanpb "github.com/d3c3ptive/aims/scan/pb"
	scanrpcpb "github.com/d3c3ptive/aims/scan/pb/rpc"
)

// scanReadBenchSizes is the runs-table population swept for the read benches. A run carries a full
// host subtree, so seeding is heavier than the flat host/credential tables — kept modest on
// purpose.
var scanReadBenchSizes = []int{100, 500, 1000}

// scanIngestRuns is the number of consecutive runs folded in the cross-run amplifier bench.
var scanIngestRuns = []int{5, 10, 20}

// scanIngestHosts is the host count each amplifier run observes (shared across all runs, so they
// unify to one growing host tree that every run reloads).
const scanIngestHosts = 50

// newBenchServer returns a scan server on a fresh, migrated pure-Go sqlite DB (one file per call),
// mirroring newTestServer (scan_test.go) but taking a *testing.B.
func newBenchServer(b *testing.B) (*server, *gorm.DB, context.Context) {
	b.Helper()
	dsn := "file:" + filepath.Join(b.TempDir(), "aims.db")
	gdb, err := gorm.Open(gormlite.Open(dsn), &gorm.Config{})
	if err != nil {
		b.Fatalf("open db: %v", err)
	}
	if err := schema.Migrate(gdb); err != nil {
		b.Fatalf("migrate: %v", err)
	}
	return New(gdb), gdb, context.Background()
}

// benchScanRun builds a run with a distinct RawXML (so it is not skipped as a duplicate) observing
// one host at addr with a single open port.
func benchScanRun(runIdx int, addr string) *scanpb.Run {
	return &scanpb.Run{
		Scanner: "nmap",
		RawXML:  fmt.Sprintf("<run>%d/%s</run>", runIdx, addr),
		Hosts: []*hostpb.Host{{
			Addresses: []*network.Address{{Addr: addr}},
			Hostnames: []*hostpb.Hostname{{Name: fmt.Sprintf("host%05d", runIdx)}},
			Ports: []*hostpb.Port{{
				Number:   22,
				Protocol: "tcp",
				State:    &hostpb.State{State: "open"},
				Service:  &network.Service{Name: "ssh"},
			}},
		}},
	}
}

// benchHostAddr returns a unique dotted-quad for index i.
func benchHostAddr(i int) string {
	return fmt.Sprintf("10.%d.%d.%d", (i>>16)&0xff, (i>>8)&0xff, i&0xff)
}

// seedRuns inserts runs directly through the ORM, bypassing the O(n^2) cross-run host fold that
// Create runs — pure setup, so a linear seed keeps large-N read benchmarks cheap to populate. Each
// run gets its own host (distinct addr) so the seeded host tree is representative.
func seedRuns(b *testing.B, s *server, ctx context.Context, n int) {
	b.Helper()
	for i := 0; i < n; i++ {
		run := benchScanRun(i, benchHostAddr(i))
		runORM, err := run.ToORM(ctx)
		if err != nil {
			b.Fatalf("to orm: %v", err)
		}
		if err := s.db.Create(&runORM).Error; err != nil {
			b.Fatalf("seed run: %v", err)
		}
	}
}

func BenchmarkServerRead(b *testing.B) {
	for _, n := range scanReadBenchSizes {
		n := n

		s, _, ctx := newBenchServer(b)
		seedRuns(b, s, ctx, n)

		// Read every run WITH its host subtree preloaded (the `scan show --hosts` / diff path).
		b.Run(fmt.Sprintf("N=%d/with-hosts", n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := s.Read(ctx, &scanrpcpb.ReadScanRequest{
					Scan:    &scanpb.Run{},
					Filters: &scanrpcpb.RunFilters{Hosts: true, Ports: true},
				}); err != nil {
					b.Fatalf("read: %v", err)
				}
			}
		})
	}
}

func BenchmarkServerList(b *testing.B) {
	for _, n := range scanReadBenchSizes {
		n := n

		s, _, ctx := newBenchServer(b)
		seedRuns(b, s, ctx, n)

		// List the run rows without their host subtrees (the `scan list` path).
		b.Run(fmt.Sprintf("N=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				res, err := s.List(ctx, &scanrpcpb.ReadScanRequest{
					Scan:    &scanpb.Run{},
					Filters: &scanrpcpb.RunFilters{},
				})
				if err != nil {
					b.Fatalf("list: %v", err)
				}
				if len(res.GetScans()) != n {
					b.Fatalf("list returned %d runs, want %d", len(res.GetScans()), n)
				}
			}
		})
	}
}

func BenchmarkServerUpsert(b *testing.B) {
	for _, n := range scanReadBenchSizes {
		n := n

		s, _, ctx := newBenchServer(b)
		seedRuns(b, s, ctx, n)
		// Upsert an already-stored run: the duplicate fast-path (whole-runs load + RawXML match),
		// echoed back with its canonical Id. Idempotent, so the table does not grow.
		dup := benchScanRun(0, benchHostAddr(0))

		b.Run(fmt.Sprintf("N=%d/dup", n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := s.Upsert(ctx, &scanrpcpb.UpsertScanRequest{Scans: []*scanpb.Run{dup}}); err != nil {
					b.Fatalf("dup upsert: %v", err)
				}
			}
		})
	}
}

// BenchmarkScanIngest folds K consecutive runs that all observed the SAME N hosts through the
// server Create path — the cross-run host-fold amplifier (persistRun re-loads the whole host tree
// on every run). Each iteration gets a fresh DB because Create mutates persistent state.
func BenchmarkScanIngest(b *testing.B) {
	for _, k := range scanIngestRuns {
		k := k

		b.Run(fmt.Sprintf("runs=%d/hosts=%d", k, scanIngestHosts), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				s, _, ctx := newBenchServer(b)
				// K runs, each a distinct scan (unique RawXML) observing the same N hosts, so the
				// hosts unify across runs and every run reloads the growing shared tree.
				runs := make([]*scanpb.Run, 0, k)
				for r := 0; r < k; r++ {
					run := &scanpb.Run{Scanner: "nmap", RawXML: fmt.Sprintf("<run>%d</run>", r)}
					for h := 0; h < scanIngestHosts; h++ {
						run.Hosts = append(run.Hosts, benchScanRun(h, benchHostAddr(h)).GetHosts()[0])
					}
					runs = append(runs, run)
				}
				b.StartTimer()

				for _, run := range runs {
					if _, err := s.Create(ctx, &scanrpcpb.CreateScanRequest{Scans: []*scanpb.Run{run}}); err != nil {
						b.Fatalf("ingest run: %v", err)
					}
				}
			}
		})
	}
}
