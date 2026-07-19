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

// BenchmarkCompleteHosts measures the round-trip that backs every host-name Tab completion.
//
// A single Tab press on `hosts show <TAB>` runs the carapace ActionCallback in
// cmd/hosts/hosts.go:CompleteByID, which is a three-step live query:
//
//	client.ConnectComplete()   // pre-connect hooks + Teamclient.Connect() + Init()
//	client.Hosts.Read(...)     // gRPC Read: fetch the whole host set (+ preloads)
//	display.Completions(...)   // format every host into (candidate, description) pairs
//
// This benchmark reproduces that callback body verbatim over the in-memory bufconn stack
// (newInMemoryStack, in roundtrip_test.go) — the real client -> teamclient -> teamserver ->
// GORM path — at N in {100, 1_000, 10_000} hosts, in two modes:
//
//	warm — connect once (newInMemoryStack already connected), then time Read + format only.
//	       Models the persistent-connection console / a completion daemon.
//	cold — call ConnectComplete() INSIDE the timed loop before the query. Models the
//	       exec-once CLI, where every Tab is a fresh process that reconnects and re-runs Init.
//
// It does NOT drive carapace itself: it calls the underlying client Read + display.Completions
// so the numbers reflect the round-trip + format, not the shell framework.
//
// -----------------------------------------------------------------------------------------------
// FINDINGS  (measured on this machine; see BENCH_COMPLETIONS.md for the run and full discussion)
// -----------------------------------------------------------------------------------------------
// See the sibling file cmd/aims/BENCH_COMPLETIONS.md for the recorded numbers and their reading:
// the cold/warm delta, how each mode scales with N, whether connect or query dominates, and the
// explicit caveat that a bufconn cold number is a FLOOR (no OS process spawn, no real-TLS
// handshake, and Teamclient.Connect() is sync.Once-guarded so no fresh dial is re-paid here).

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/carapace-sh/carapace"
	"google.golang.org/protobuf/proto"

	"github.com/d3c3ptive/aims/client"
	"github.com/d3c3ptive/aims/cmd/display"
	cmdhosts "github.com/d3c3ptive/aims/cmd/hosts"
	"github.com/d3c3ptive/aims/host"
	pb "github.com/d3c3ptive/aims/host/pb"
	hosts "github.com/d3c3ptive/aims/host/pb/rpc"
	network "github.com/d3c3ptive/aims/network/pb"
)

// benchSizes is the DB population swept by the benchmark. It scales to 10k on purpose: the
// completion Read fetches the WHOLE host set with full preloads (no server-side prefix match, no
// result cap), so both latency and wire size are expected to grow with total DB size.
var benchSizes = []int{100, 1_000, 10_000}

// benchHost returns a webHost()-shaped host made unique by index i (distinct address + hostname,
// so the dedup-on-insert Create actually stores all N). Status is set so the read-back host has
// the fields display.Completions formats (host.DisplayFields["ID"] dereferences h.Status).
func benchHost(i int) *pb.Host {
	return &pb.Host{
		Addresses: []*network.Address{{Addr: fmt.Sprintf("10.%d.%d.%d", (i>>16)&0xff, (i>>8)&0xff, i&0xff)}},
		Hostnames: []*pb.Hostname{{Name: fmt.Sprintf("web%05d", i)}},
		Status:    &pb.Status{State: "up"},
		Ports: []*pb.Port{
			{Number: 80, Protocol: "tcp", State: &pb.State{State: "open"}, Service: &network.Service{Name: "http", Product: "nginx"}},
			{Number: 443, Protocol: "tcp", State: &pb.State{State: "open"}, Service: &network.Service{Name: "https", Product: "nginx"}},
			{Number: 22, Protocol: "tcp", State: &pb.State{State: "open"}, Service: &network.Service{Name: "ssh", Product: "openssh"}},
		},
	}
}

// seedHosts bulk-inserts n unique hosts through the real Create RPC. Called once per sub-benchmark,
// before b.ResetTimer, so seeding is never in the timed region.
//
// It issues ONE Create per stack: Create dedups by loading the whole existing host tree
// (server/host.loadHostsPB) on every call, so chunking would re-load an ever-larger full tree per
// chunk and exhaust the wasm-sqlite linear memory well before 10k. A single call loads that tree
// once, against the empty DB, then dedups the batch in memory.
func seedHosts(tb testing.TB, con *client.Client, n int) {
	tb.Helper()

	batch := make([]*pb.Host, 0, n)
	for i := 0; i < n; i++ {
		batch = append(batch, benchHost(i))
	}
	if _, err := con.Hosts.Create(context.Background(), &hosts.CreateHostRequest{Hosts: batch}); err != nil {
		tb.Fatalf("seed Create: %v", err)
	}
}

// completionReadRequest mirrors the completion callbacks' Read: the whole host set with the full
// child tree preloaded. CompleteByID passes nil Filters, but with nil Filters the server preloads
// nothing (server/host.WithPreloads returns nil), so the read-back hosts would carry no hostnames,
// OS, or ports and display.Completions would emit empty candidates. We therefore request the full
// preloads the completion is meant to display — this is also what makes the whole-DB-fetch cost
// (latency + wire bytes climbing with N) visible, which is the point of the benchmark.
func completionReadRequest() *hosts.ReadHostRequest {
	return &hosts.ReadHostRequest{
		Host:    &pb.Host{},
		Filters: &hosts.HostFilters{Ports: true, Trace: true, Scripts: true},
	}
}

// formatCompletions reproduces CompleteByID's format step and returns the produced candidates.
func formatCompletions(res *hosts.ReadHostResponse) []string {
	options := host.Completions()
	options = append(options, display.WithCandidateValue("ID", ""))
	return display.Completions(res.Hosts, host.DisplayFields, options...)
}

// runCompletion performs one Read + format, returning the number of candidates and the approximate
// wire size (proto Size of the gRPC response payload).
func runCompletion(tb testing.TB, con *client.Client) (candidates, wireBytes int) {
	res, err := con.Hosts.Read(context.Background(), completionReadRequest())
	if err != nil {
		tb.Fatalf("Hosts.Read: %v", err)
	}
	results := formatCompletions(res)
	// display.Completions returns flat (candidate, description) pairs.
	return len(results) / 2, proto.Size(res)
}

// setXDGCacheHome points XDG_CACHE_HOME at dir for the benchmark, restoring it after.
// It uses os.Setenv rather than b.Setenv because the testing framework forbids
// b.Setenv inside a benchmark (it may run the function several times to size b.N).
func setXDGCacheHome(b *testing.B, dir string) {
	b.Helper()
	prev, had := os.LookupEnv("XDG_CACHE_HOME")
	if err := os.Setenv("XDG_CACHE_HOME", dir); err != nil {
		b.Fatalf("set XDG_CACHE_HOME: %v", err)
	}
	b.Cleanup(func() {
		if had {
			os.Setenv("XDG_CACHE_HOME", prev)
		} else {
			os.Unsetenv("XDG_CACHE_HOME")
		}
	})
}

// dirBytes sums the size of every file under dir — used to report the on-disk size of
// the cached completion payload served on a hit.
func dirBytes(dir string) (total int64) {
	_ = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if info, err := d.Info(); err == nil {
			total += info.Size()
		}
		return nil
	})
	return total
}

func BenchmarkCompleteHosts(b *testing.B) {
	for _, n := range benchSizes {
		n := n

		// warm: persistent connection. Connect + seed happen before ResetTimer; the timed loop is
		// Read + format only.
		b.Run(fmt.Sprintf("N=%d/warm", n), func(b *testing.B) {
			con := newInMemoryStack(b)
			seedHosts(b, con, n)

			b.ReportAllocs()
			b.ResetTimer()

			var cands, wire int
			for i := 0; i < b.N; i++ {
				cands, wire = runCompletion(b, con)
			}

			b.StopTimer()
			b.ReportMetric(float64(cands), "candidates/op")
			b.ReportMetric(float64(wire), "wirebytes/op")
		})

		// cold: exec-once CLI. ConnectComplete() is paid INSIDE the timed loop, before each query.
		b.Run(fmt.Sprintf("N=%d/cold", n), func(b *testing.B) {
			con := newInMemoryStack(b)
			seedHosts(b, con, n)

			b.ReportAllocs()
			b.ResetTimer()

			var cands, wire int
			for i := 0; i < b.N; i++ {
				if msg, err := con.ConnectComplete(); err != nil {
					b.Fatalf("ConnectComplete: %v (%v)", err, msg)
				}
				cands, wire = runCompletion(b, con)
			}

			b.StopTimer()
			b.ReportMetric(float64(cands), "candidates/op")
			b.ReportMetric(float64(wire), "wirebytes/op")
		})
	}
}

// BenchmarkCompleteHostsCacheHit measures the third mode: a warm on-disk cache hit.
//
// It drives the REAL wired completion — cmdhosts.CompleteByHostnameOrIP, wrapped in
// cmd.CacheCompletion — through carapace's Invoke, so the cache path is exercised end
// to end. The cache is warmed once (a miss: connect + whole-DB Read + format, then a
// disk write), then the timed loop invokes only cache hits: no ConnectComplete, no
// gRPC, no format — just load + deserialize the cached candidate set from disk. This
// is what every Tab after the first (within CompletionCacheTTL) actually costs, and
// the number to compare against the warm/cold query costs in BENCH_COMPLETIONS.md.
//
// XDG_CACHE_HOME is redirected to a temp dir (carapace reads it lazily, so this
// isolates the cache) — otherwise a stale hit from a previous run could serve the
// wrong N. b.N * benchtime stays well under the 10s TTL, so every timed iteration is
// a genuine hit.
func BenchmarkCompleteHostsCacheHit(b *testing.B) {
	for _, n := range benchSizes {
		n := n

		b.Run(fmt.Sprintf("N=%d/hit", n), func(b *testing.B) {
			cacheHome := b.TempDir()
			setXDGCacheHome(b, cacheHome) // isolate carapace's on-disk cache

			con := newInMemoryStack(b)
			seedHosts(b, con, n)

			// Candidate count for reporting (same Read+format the completion caches).
			cands, _ := runCompletion(b, con)

			action := cmdhosts.CompleteByHostnameOrIP(con)
			ctx := carapace.Context{}
			action.Invoke(ctx) // warm: miss -> query + write cache

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				action.Invoke(ctx) // hit: served from disk, no query
			}

			b.StopTimer()
			b.ReportMetric(float64(cands), "candidates/op")
			b.ReportMetric(float64(dirBytes(cacheHome)), "cachebytes/op")
		})
	}
}
