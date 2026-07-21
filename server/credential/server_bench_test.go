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

// BenchmarkServerRead / BenchmarkServerList / BenchmarkServerUpsert measure the credential gRPC
// service straight against the gormlite DB (no teamserver, no gRPC framing) — the pure DB+ORM
// cost that MaxResults capping / indexing target (reviews/benchmark-review.md §B #1). Read returns
// the first match, List loads every credential with its sub-credentials preloaded, and Upsert runs
// the identity-match + field-class merge fold against the whole table.
//
// Setup (DB open + seed) is excluded from the timed region: reads and idempotent (duplicate)
// upserts do not grow the table, so one seeded server is reused across a benchmark's iterations.
import (
	"context"
	"fmt"
	"path/filepath"
	"testing"

	_ "github.com/ncruces/go-sqlite3/embed" // loads the pure-Go SQLite (wazero) binary
	"github.com/ncruces/go-sqlite3/gormlite"
	"gorm.io/gorm"

	credpb "github.com/d3c3ptive/aims/credential/pb"
	credentials "github.com/d3c3ptive/aims/credential/pb/rpc"
	schema "github.com/d3c3ptive/aims/db"
)

// credServerBenchSizes is the table population swept. Seeding is linear (direct ORM inserts), so
// 10k is affordable here.
var credServerBenchSizes = []int{100, 1000, 10000}

// newBenchServer returns a credential server on a fresh, migrated pure-Go sqlite DB (one file per
// call), mirroring the host/scan test harnesses.
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

// benchCore is a credential made unique by index i (distinct username + password) so the identity
// key keeps them separate and every one is stored.
func benchCore(i int) *credpb.Core {
	return &credpb.Core{
		Public:  &credpb.Public{Type: credpb.PublicType_Username, Username: fmt.Sprintf("user%05d", i)},
		Private: &credpb.Private{Type: credpb.PrivateType_Password, Data: fmt.Sprintf("pass%05d", i)},
	}
}

// makeCredBatch builds n unique credentials.
func makeCredBatch(n int) []*credpb.Core {
	batch := make([]*credpb.Core, 0, n)
	for i := 0; i < n; i++ {
		batch = append(batch, benchCore(i))
	}
	return batch
}

// seedCreds inserts credentials directly through the ORM, bypassing the O(n^2) identity fold that
// Create/Upsert run — pure setup, so a linear seed keeps large-N benchmarks cheap to populate.
func seedCreds(b *testing.B, s *server, ctx context.Context, list []*credpb.Core) {
	b.Helper()
	for _, c := range list {
		corm, err := c.ToORM(ctx)
		if err != nil {
			b.Fatalf("to orm: %v", err)
		}
		if err := s.db.Create(&corm).Error; err != nil {
			b.Fatalf("seed credential: %v", err)
		}
	}
}

func BenchmarkServerRead(b *testing.B) {
	for _, n := range credServerBenchSizes {
		n := n

		s, ctx := newBenchServer(b)
		seedCreds(b, s, ctx, makeCredBatch(n))

		b.Run(fmt.Sprintf("N=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := s.Read(ctx, &credentials.ReadCredentialRequest{Credential: &credpb.Core{}}); err != nil {
					b.Fatalf("read: %v", err)
				}
			}
		})
	}
}

func BenchmarkServerList(b *testing.B) {
	for _, n := range credServerBenchSizes {
		n := n

		s, ctx := newBenchServer(b)
		seedCreds(b, s, ctx, makeCredBatch(n))

		b.Run(fmt.Sprintf("N=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				res, err := s.List(ctx, &credentials.ReadCredentialRequest{Credential: &credpb.Core{}})
				if err != nil {
					b.Fatalf("list: %v", err)
				}
				if len(res.GetCredentials()) != n {
					b.Fatalf("list returned %d credentials, want %d", len(res.GetCredentials()), n)
				}
			}
		})
	}
}

func BenchmarkServerUpsert(b *testing.B) {
	for _, n := range credServerBenchSizes {
		n := n

		s, ctx := newBenchServer(b)
		seedCreds(b, s, ctx, makeCredBatch(n))
		// Upsert an already-present credential: the merge path (whole-DB load + identity match +
		// a no-op MergeCore). Idempotent, so the table does not grow across iterations.
		dup := benchCore(0)

		b.Run(fmt.Sprintf("N=%d/dup-merge", n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := s.Upsert(ctx, &credentials.UpsertCredentialRequest{Credentials: []*credpb.Core{dup}}); err != nil {
					b.Fatalf("dup upsert: %v", err)
				}
			}
		})
	}
}
