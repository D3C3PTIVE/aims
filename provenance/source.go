package provenance

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
	"strconv"
	"strings"

	pb "github.com/d3c3ptive/aims/provenance/pb"
)

// Source is a native wrapper around the generated provenance.Source, so Go-idiomatic
// helpers can hang off the type without polluting the generated code.
type Source pb.Source

// MergeSourceORMs unions `src` into `dst`: every contribution in src whose identity is not
// already present in dst is appended. It returns the merged slice and whether dst grew.
//
// This is the provenance-survives-as-union primitive that underpins the whole feature:
// when the ingest/merge fold folds two records that denote the same object (the same host,
// the same credential), their contributing tools must ACCUMULATE — a second tool enriching
// an existing object must never silently drop the first tool's provenance. Every domain
// merge (credential.MergeCore, host merge, …) routes its Sources through here so the union
// semantics stay identical across domains.
func MergeSourceORMs(dst, src []*pb.SourceORM) ([]*pb.SourceORM, bool) {
	seen := make(map[string]bool, len(dst))
	for _, s := range dst {
		seen[sourceKey(s)] = true
	}

	changed := false
	for _, s := range src {
		if s == nil {
			continue
		}
		k := sourceKey(s)
		if seen[k] {
			continue
		}
		seen[k] = true
		dst = append(dst, s)
		changed = true
	}

	return dst, changed
}

// sourceKey is the identity of a contribution for union/dedup: the who/what/where tuple that
// distinguishes one tool's contribution from another's. Two Sources with the same key are
// treated as the same contribution event, so re-importing the same scan does not pile up
// duplicate provenance rows.
func sourceKey(s *pb.SourceORM) string {
	if s == nil {
		return ""
	}
	return strings.Join([]string{
		s.Tool,
		strconv.Itoa(int(s.Type)),
		s.SessionId,
		s.Filename,
		s.Cracker,
		s.ServiceId,
	}, "\x00")
}
