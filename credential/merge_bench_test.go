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

// BenchmarkMergeCore measures the credential merge fold — the field-class merge + provenance union
// MergeCore runs on every Upsert of an already-known credential (reviews/benchmark-review.md §B #3,
// the credential sibling of the host ingest fold). Two shapes are covered: the idempotent no-op
// re-import (the common Tab-and-reimport case) and a merge that actually fills a field and unions a
// second tool's Source. MergeCore mutates dst, so the merging case rebuilds a fresh dst per
// iteration outside the timed region (Stop/StartTimer), matching the host ingest bench convention.
import (
	"testing"

	credential "github.com/d3c3ptive/aims/credential/pb"
	provpb "github.com/d3c3ptive/aims/provenance/pb"
)

// benchMergeDst builds an NTLM credential with an empty JTRFormat and one discovery Source — the
// destination the merge enriches.
func benchMergeDst() *credential.CoreORM {
	dst := core(user("admin"), &credential.PrivateORM{Type: int32(credential.PrivateType_NTLMHash), Data: "abc"}, nil)
	dst.Sources = []*provpb.SourceORM{{Type: int32(provpb.SourceType_Cracked), Cracker: "john"}}
	return dst
}

// benchMergeSrc is a second observation of the same credential: it fills JTRFormat and carries a
// different Source, so the merge does real work (fill + union).
func benchMergeSrc() *credential.CoreORM {
	src := core(user("admin"), &credential.PrivateORM{Type: int32(credential.PrivateType_NTLMHash), Data: "abc", JTRFormat: "nt"}, nil)
	src.Sources = []*provpb.SourceORM{{Type: int32(provpb.SourceType_Import), Filename: "later.txt"}}
	return src
}

func BenchmarkMergeCore(b *testing.B) {
	// Idempotent: dst == src, MergeCore is a no-op. dst is unchanged, so it is reused across
	// iterations without a per-iteration rebuild.
	b.Run("idempotent", func(b *testing.B) {
		dst := benchMergeSrc() // identical to src below
		src := benchMergeSrc()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = MergeCore(dst, src)
		}
	})

	// Enriching: MergeCore fills the empty JTRFormat and unions the new Source (returns true). dst
	// is mutated, so it is rebuilt fresh each iteration outside the timed region.
	b.Run("enriching", func(b *testing.B) {
		src := benchMergeSrc()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			b.StopTimer()
			dst := benchMergeDst()
			b.StartTimer()
			_ = MergeCore(dst, src)
		}
	})
}
