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

import (
	"testing"

	credential "github.com/d3c3ptive/aims/credential/pb"
	provpb "github.com/d3c3ptive/aims/provenance/pb"
)

// Re-importing the identical credential changes nothing (idempotent merge).
func TestMergeCore_Idempotent(t *testing.T) {
	dst := core(user("admin"), pass("hunter2"), nil)
	src := core(user("admin"), pass("hunter2"), nil)
	if MergeCore(dst, src) {
		t.Fatalf("merging identical credentials should be a no-op")
	}
}

// Fill-only: an empty enrichment field is filled from src, a known one is never clobbered.
func TestMergeCore_FillOnly(t *testing.T) {
	dst := core(user("admin"), &credential.PrivateORM{Type: int32(credential.PrivateType_NTLMHash), Data: "abc"}, nil)
	src := core(user("admin"), &credential.PrivateORM{Type: int32(credential.PrivateType_NTLMHash), Data: "abc", JTRFormat: "nt"}, nil)

	if !MergeCore(dst, src) {
		t.Fatalf("expected merge to fill the empty JTRFormat")
	}
	if dst.Private.JTRFormat != "nt" {
		t.Fatalf("JTRFormat not filled: got %q", dst.Private.JTRFormat)
	}

	// A second merge with a different format must NOT overwrite the known one.
	src2 := core(user("admin"), &credential.PrivateORM{Type: int32(credential.PrivateType_NTLMHash), Data: "abc", JTRFormat: "netntlmv2"}, nil)
	if MergeCore(dst, src2) {
		t.Fatalf("a known JTRFormat must not be clobbered")
	}
	if dst.Private.JTRFormat != "nt" {
		t.Fatalf("JTRFormat was clobbered: got %q", dst.Private.JTRFormat)
	}
}

// Provenance is union: a second tool's contribution is accumulated, and the original
// discovery Source is preserved (kept first), never overwritten.
func TestMergeCore_SourcesUnion(t *testing.T) {
	dst := core(user("admin"), pass("hunter2"), nil)
	dst.Sources = []*provpb.SourceORM{{Type: int32(provpb.SourceType_Cracked), Cracker: "john"}}

	src := core(user("admin"), pass("hunter2"), nil)
	src.Sources = []*provpb.SourceORM{{Type: int32(provpb.SourceType_Import), Filename: "later.txt"}}

	if !MergeCore(dst, src) {
		t.Fatal("merging a new Source should report a change")
	}
	if len(dst.Sources) != 2 {
		t.Fatalf("Sources were not unioned: want 2, got %d (%+v)", len(dst.Sources), dst.Sources)
	}
	if provpb.SourceType(dst.Sources[0].Type) != provpb.SourceType_Cracked || dst.Sources[0].Cracker != "john" {
		t.Fatalf("discovery Source was not preserved first: %+v", dst.Sources[0])
	}

	// Union is idempotent: folding the same Source again adds nothing.
	if MergeCore(dst, src) || len(dst.Sources) != 2 {
		t.Fatalf("re-merging an identical Source changed dst: %+v", dst.Sources)
	}
}
