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

// Provenance is first-wins: the original discovery Origin is preserved across merges.
func TestMergeCore_OriginFirstWins(t *testing.T) {
	dst := core(user("admin"), pass("hunter2"), nil)
	dst.Origin = &credential.OriginORM{Type: int32(credential.OriginType_CrackedPassword), Cracker: "john"}

	src := core(user("admin"), pass("hunter2"), nil)
	src.Origin = &credential.OriginORM{Type: int32(credential.OriginType_Import), Filename: "later.txt"}

	MergeCore(dst, src)
	if credential.OriginType(dst.Origin.Type) != credential.OriginType_CrackedPassword || dst.Origin.Cracker != "john" {
		t.Fatalf("discovery origin was overwritten: %+v", dst.Origin)
	}
}
