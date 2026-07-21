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

// BenchmarkIngestHosts measures the host ingest fold — the additive/idempotent merge that backs
// server.Upsert, IngestHosts, and (via those) scan import. It is the hot path .claude/ROADMAP.md flags as
// an O(n^2) shape: ingest() calls loadHostsPB(), which loads the WHOLE host table with its full
// child tree on EVERY call, then matches each incoming host against that set (indexSameHost is
// O(existing) per incoming host). Nothing here was measured before.
//
// Three modes make the cost visible:
//
//	fresh-batch      — one ingest of N brand-new hosts into an empty DB (all inserts). The
//	                   baseline: one whole-DB load (of nothing) + N inserts.
//	reingest-dup     — one ingest of N hosts into a DB that already holds them (all merge path):
//	                   one whole-DB load of N hosts + N SameHost matches + MergeHost (mostly no-op
//	                   writes since nothing changed).
//	incremental-1by1 — N separate single-host ingests against a growing DB. This is the felt
//	                   CLI/scan-import cost and the genuinely O(n^2) case: call k reloads the k-1
//	                   hosts already stored, so the whole run loads ~N^2/2 host trees.
//
// The DB is the pure-Go wasm sqlite (in a temp file), same stack as the server tests. Setup is
// excluded from the timed region via Stop/StartTimer; each timed iteration gets a fresh DB because
// ingest mutates persistent state.
import (
	"context"
	"fmt"
	"path/filepath"
	"testing"

	_ "github.com/ncruces/go-sqlite3/embed"
	"github.com/ncruces/go-sqlite3/gormlite"
	"gorm.io/gorm"

	schema "github.com/d3c3ptive/aims/db"
	pb "github.com/d3c3ptive/aims/host/pb"
	network "github.com/d3c3ptive/aims/network/pb"
)

// ingestSizes is the DB population swept. It stays modest on purpose: the incremental mode is
// O(n^2) in whole-tree DB loads, so a larger N there costs seconds of pure-Go sqlite work per op.
var ingestSizes = []int{50, 200, 500}

// newBenchServer returns a host server on a fresh, migrated pure-Go sqlite DB (one file per call).
func newBenchServer(b *testing.B) (*server, context.Context) {
	b.Helper()
	dsn := "file:" + filepath.Join(b.TempDir(), "aims.db")
	gdb, err := gorm.Open(gormlite.Open(dsn), &gorm.Config{})
	if err != nil {
		b.Fatalf("open db: %v", err)
	}
	if err := schema.Migrate(gdb); err != nil {
		b.Fatalf("migrate: %v", err)
	}
	return New(gdb), context.Background()
}

// benchHostN returns a host made unique by index i (distinct address + hostname, so SameHost keeps
// them separate and every one is stored), carrying a small port tree so the merge path has real
// children to compare and load.
func benchHostN(i int) *pb.Host {
	return &pb.Host{
		Addresses: []*network.Address{{Addr: fmt.Sprintf("10.%d.%d.%d", (i>>16)&0xff, (i>>8)&0xff, i&0xff)}},
		Hostnames: []*pb.Hostname{{Name: fmt.Sprintf("host%05d", i)}},
		Status:    &pb.Status{State: "up"},
		Ports: []*pb.Port{
			{Number: 22, Protocol: "tcp", State: &pb.State{State: "open"}, Service: &network.Service{Name: "ssh", Product: "openssh"}},
			{Number: 80, Protocol: "tcp", State: &pb.State{State: "open"}, Service: &network.Service{Name: "http", Product: "nginx"}},
		},
	}
}

// makeIngestBatch builds n unique hosts.
func makeIngestBatch(n int) []*pb.Host {
	batch := make([]*pb.Host, 0, n)
	for i := 0; i < n; i++ {
		batch = append(batch, benchHostN(i))
	}
	return batch
}

func BenchmarkIngestHosts(b *testing.B) {
	for _, n := range ingestSizes {
		n := n

		b.Run(fmt.Sprintf("N=%d/fresh-batch", n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				s, ctx := newBenchServer(b)
				batch := makeIngestBatch(n)
				b.StartTimer()

				if _, err := s.ingest(ctx, batch); err != nil {
					b.Fatalf("ingest: %v", err)
				}
			}
		})

		b.Run(fmt.Sprintf("N=%d/reingest-dup", n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				s, ctx := newBenchServer(b)
				if _, err := s.ingest(ctx, makeIngestBatch(n)); err != nil {
					b.Fatalf("seed ingest: %v", err)
				}
				again := makeIngestBatch(n)
				b.StartTimer()

				if _, err := s.ingest(ctx, again); err != nil {
					b.Fatalf("reingest: %v", err)
				}
			}
		})

		b.Run(fmt.Sprintf("N=%d/incremental-1by1", n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				s, ctx := newBenchServer(b)
				batch := makeIngestBatch(n)
				b.StartTimer()

				for _, h := range batch {
					if _, err := s.ingest(ctx, []*pb.Host{h}); err != nil {
						b.Fatalf("incremental ingest: %v", err)
					}
				}
			}
		})
	}
}
