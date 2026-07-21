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

// BenchmarkServerRead / BenchmarkServerUpsert / BenchmarkScopeBySource measure the host gRPC
// service straight against the gormlite DB — no teamserver, no gRPC framing — so the numbers are
// the pure DB+ORM cost that the MaxResults cap (server P4) and the provenance-join index (server
// P2) target (see reviews/benchmark-review.md §B #1, #2). They complement BenchmarkIngestHosts
// (the write/merge fold) by isolating the read side.
//
// The host server exposes no separate List RPC — Read IS the list path (a filter-less Read Finds
// every matching row), so BenchmarkServerRead covers both the single-row and whole-table shapes.
//
// Setup (DB open + seed) is excluded from the timed region: reads and idempotent (duplicate)
// upserts do not grow the table, so one seeded server is reused across a benchmark's iterations.
import (
	"context"
	"fmt"
	"testing"

	pb "github.com/d3c3ptive/aims/host/pb"
	hosts "github.com/d3c3ptive/aims/host/pb/rpc"
	provpb "github.com/d3c3ptive/aims/provenance/pb"
)

// serverBenchSizes is the table population swept for the read/scope benches. Seeding is linear
// (direct ORM inserts, below), so 10k is affordable here even though the write-fold benches cap
// lower.
var serverBenchSizes = []int{100, 1000, 10000}

// benchTools is the small set of contributing tools spread across the seeded hosts so the
// provenance scope (host_sources join) has more than one tool to discriminate between.
var benchTools = []string{"nmap", "masscan", "metasploit", "sliver", "manual"}

// seedHosts inserts hosts directly through the ORM, bypassing the O(n^2) SameHost fold that
// Create/Upsert run — this is pure setup (correctness of the fold is covered elsewhere), so a
// linear seed keeps large-N benchmarks from spending minutes populating the table. Associations
// (ports, sources) are persisted by GORM's default Create cascade.
func seedHosts(b *testing.B, s *server, ctx context.Context, list []*pb.Host) {
	b.Helper()
	for _, h := range list {
		horm, err := h.ToORM(ctx)
		if err != nil {
			b.Fatalf("to orm: %v", err)
		}
		if err := s.db.Create(&horm).Error; err != nil {
			b.Fatalf("seed host: %v", err)
		}
	}
}

// benchSourcedHost is benchHostN plus a single provenance Source stamping the contributing tool,
// so the host lands in that tool's host_sources bucket for the scope benchmark.
func benchSourcedHost(i int, tool string) *pb.Host {
	h := benchHostN(i)
	h.Sources = []*provpb.Source{{Tool: tool}}
	return h
}

func BenchmarkServerRead(b *testing.B) {
	for _, n := range serverBenchSizes {
		n := n

		s, ctx := newBenchServer(b)
		seedHosts(b, s, ctx, makeIngestBatch(n))

		// Whole-table Read (the `hosts list` path): Find every row with its port subtree.
		b.Run(fmt.Sprintf("N=%d/all", n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				res, err := s.Read(ctx, &hosts.ReadHostRequest{
					Host:    &pb.Host{},
					Filters: &hosts.HostFilters{Ports: true},
				})
				if err != nil {
					b.Fatalf("read all: %v", err)
				}
				if len(res.GetHosts()) != n {
					b.Fatalf("read all returned %d hosts, want %d", len(res.GetHosts()), n)
				}
			}
		})

		// Capped Read (the MaxResults P4 fix): a LIMIT keeps a large table from being fully
		// loaded. This should stay flat as N grows.
		b.Run(fmt.Sprintf("N=%d/capped-10", n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := s.Read(ctx, &hosts.ReadHostRequest{
					Host:    &pb.Host{},
					Filters: &hosts.HostFilters{Ports: true, MaxResults: 10},
				}); err != nil {
					b.Fatalf("capped read: %v", err)
				}
			}
		})
	}
}

func BenchmarkServerUpsert(b *testing.B) {
	for _, n := range serverBenchSizes {
		n := n

		s, ctx := newBenchServer(b)
		seedHosts(b, s, ctx, makeIngestBatch(n))
		// Upsert an already-present host: the merge path (whole-DB load + SameHost match + a
		// no-op MergeHost). Idempotent, so the table does not grow across iterations.
		dup := benchHostN(0)

		b.Run(fmt.Sprintf("N=%d/dup-merge", n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := s.Upsert(ctx, &hosts.UpsertHostRequest{Hosts: []*pb.Host{dup}}); err != nil {
					b.Fatalf("dup upsert: %v", err)
				}
			}
		})
	}
}

// BenchmarkScopeBySource measures the provenance-scoped Read — the "give me only my objects" query
// that joins host_sources + sources and filters on sources.tool. Run before/after the proposed
// index on sources.tool + the join FKs (server P2), this is the regression guard proving that win.
func BenchmarkScopeBySource(b *testing.B) {
	for _, n := range serverBenchSizes {
		n := n

		s, ctx := newBenchServer(b)
		batch := make([]*pb.Host, 0, n)
		for i := 0; i < n; i++ {
			batch = append(batch, benchSourcedHost(i, benchTools[i%len(benchTools)]))
		}
		seedHosts(b, s, ctx, batch)

		b.Run(fmt.Sprintf("N=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := s.Read(ctx, &hosts.ReadHostRequest{
					Host:    &pb.Host{},
					Filters: &hosts.HostFilters{Source: benchTools[0]},
				}); err != nil {
					b.Fatalf("scoped read: %v", err)
				}
			}
		})
	}
}
