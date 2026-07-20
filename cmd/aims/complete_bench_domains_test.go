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

// BenchmarkCompleteServices / BenchmarkCompleteCredentials generalise the host completion
// benchmark (complete_bench_test.go) to the other cache-wrapped domains, driving the REAL wired
// completers (cmd/services.CompleteByID, cmd/credentials.CompleteByID) through carapace's Invoke.
//
// Each has two modes:
//
//	miss — a fresh on-disk cache dir per iteration, so every Invoke is a cache MISS: connect +
//	       whole-DB List + format + cache write. This is a cold Tab (first press, or after the TTL).
//	hit  — warm the cache once, then time only hits: load + deserialize from disk, no query. This
//	       is every subsequent Tab within CompletionCacheTTL.
//
// Together with BenchmarkCompleteHosts this confirms cache parity across domains — the point of
// wrapping the scan/c2 completers in CacheCompletion (they previously ran uncached). It reuses the
// host benchmark's stack/seed/cache helpers (same package): newInMemoryStack, seedHosts,
// setXDGCacheHome, dirBytes, benchSizes.
import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/carapace-sh/carapace"

	"github.com/d3c3ptive/aims/client"
	cmdcredentials "github.com/d3c3ptive/aims/cmd/credentials"
	cmdservices "github.com/d3c3ptive/aims/cmd/services"
	credpb "github.com/d3c3ptive/aims/credential/pb"
	credrpc "github.com/d3c3ptive/aims/credential/pb/rpc"
	provpb "github.com/d3c3ptive/aims/provenance/pb"
)

// seedCreds bulk-inserts n unique credentials through the real Create RPC (distinct usernames +
// passwords so the identity dedup stores all n). Called before ResetTimer.
func seedCreds(tb testing.TB, con *client.Client, n int) {
	tb.Helper()
	batch := make([]*credpb.Core, 0, n)
	for i := 0; i < n; i++ {
		batch = append(batch, &credpb.Core{
			Public:  &credpb.Public{Username: fmt.Sprintf("user%05d", i)},
			Private: &credpb.Private{Type: credpb.PrivateType_Password, Data: fmt.Sprintf("pass%05d", i)},
			Sources: []*provpb.Source{{Tool: "bench"}},
		})
	}
	if _, err := con.Creds.Create(context.Background(), &credrpc.CreateCredentialRequest{Credentials: batch}); err != nil {
		tb.Fatalf("seed Create creds: %v", err)
	}
}

// benchCompleterHit warms the cache once, then times only cache hits for the wired completer.
func benchCompleterHit(b *testing.B, n int, seed func(testing.TB, *client.Client, int), makeAction func(*client.Client) carapace.Action) {
	cacheHome := b.TempDir()
	setXDGCacheHome(b, cacheHome) // isolate carapace's on-disk cache

	con := newInMemoryStack(b)
	seed(b, con, n)

	action := makeAction(con)
	ctx := carapace.Context{}
	action.Invoke(ctx) // warm: miss -> query + write cache

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		action.Invoke(ctx) // hit: served from disk
	}
	b.StopTimer()
	b.ReportMetric(float64(n), "objects/op")
	b.ReportMetric(float64(dirBytes(cacheHome)), "cachebytes/op")
}

// benchCompleterMiss times a genuine cache MISS every iteration by pointing XDG_CACHE_HOME at a
// fresh dir before each Invoke (carapace reads it lazily, so a new dir has no cached entry).
func benchCompleterMiss(b *testing.B, n int, seed func(testing.TB, *client.Client, int), makeAction func(*client.Client) carapace.Action) {
	con := newInMemoryStack(b)
	seed(b, con, n)

	action := makeAction(con)
	ctx := carapace.Context{}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		if err := os.Setenv("XDG_CACHE_HOME", b.TempDir()); err != nil {
			b.Fatalf("set XDG_CACHE_HOME: %v", err)
		}
		b.StartTimer()
		action.Invoke(ctx)
	}
	b.StopTimer()
	os.Unsetenv("XDG_CACHE_HOME")
	b.ReportMetric(float64(n), "objects/op")
}

func BenchmarkCompleteServices(b *testing.B) {
	for _, n := range benchSizes {
		n := n
		b.Run(fmt.Sprintf("N=%d/miss", n), func(b *testing.B) {
			benchCompleterMiss(b, n, seedHosts, cmdservices.CompleteByID)
		})
		b.Run(fmt.Sprintf("N=%d/hit", n), func(b *testing.B) {
			benchCompleterHit(b, n, seedHosts, cmdservices.CompleteByID)
		})
	}
}

func BenchmarkCompleteCredentials(b *testing.B) {
	for _, n := range benchSizes {
		n := n
		b.Run(fmt.Sprintf("N=%d/miss", n), func(b *testing.B) {
			benchCompleterMiss(b, n, seedCreds, cmdcredentials.CompleteByID)
		})
		b.Run(fmt.Sprintf("N=%d/hit", n), func(b *testing.B) {
			benchCompleterHit(b, n, seedCreds, cmdcredentials.CompleteByID)
		})
	}
}
