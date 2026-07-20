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

	"gorm.io/gorm"

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

// Tools returns the distinct, comma-joined contributing tool names of a set of Sources, for
// compact display ("nmap, metasploit"). An empty Tool renders as "manual". Shared by every
// domain's detail view so provenance is presented identically everywhere.
func Tools(sources []*pb.Source) string {
	seen := make(map[string]bool, len(sources))
	var tools []string
	for _, s := range sources {
		if s == nil {
			continue
		}
		t := s.GetTool()
		if t == "" {
			t = "manual"
		}
		if seen[t] {
			continue
		}
		seen[t] = true
		tools = append(tools, t)
	}
	return strings.Join(tools, ", ")
}

// WhereContributedBy is the code-API "give me only my objects" scope: it restricts a query to
// the objects contributed by the named tool, joining through that object's provenance m2m table
// to the shared sources table. joinTable is the m2m join (e.g. "host_sources", "core_sources")
// and objectFK its column referencing the queried object's id (e.g. "host_id", "core_id"). An
// empty tool is a no-op (the default cross-tool shared view), so callers can pass a filter value
// through unconditionally. Any tool consuming AIMS as a library can therefore scope to just the
// data it produced with `db.Scopes(provenance.WhereContributedBy("host_sources","host_id",tool))`.
func WhereContributedBy(joinTable, objectFK, tool string) func(*gorm.DB) *gorm.DB {
	return func(d *gorm.DB) *gorm.DB {
		if tool == "" {
			return d
		}
		// Qualify the selected FK with the join table: sources itself carries a service_id
		// column (the soft Source.ServiceId ref), so a bare "service_id" would be ambiguous
		// once sources is joined in.
		sub := d.Session(&gorm.Session{NewDB: true}).
			Table(joinTable).
			Select(joinTable + "." + objectFK).
			Joins("JOIN sources ON sources.id = " + joinTable + ".source_id").
			Where("sources.tool = ?", tool)
		return d.Where("id IN (?)", sub)
	}
}

// MergeSources is the PB-level counterpart to MergeSourceORMs, with identical union
// semantics: the in-memory host merge (host/merge.go) folds user-facing *pb.Source values,
// whereas credential's ORM-level MergeCore folds *pb.SourceORM. Both route through the same
// identity so provenance dedups the same way regardless of which representation is in hand.
func MergeSources(dst, src []*pb.Source) ([]*pb.Source, bool) {
	seen := make(map[string]bool, len(dst))
	for _, s := range dst {
		seen[sourceKeyPB(s)] = true
	}

	changed := false
	for _, s := range src {
		if s == nil {
			continue
		}
		k := sourceKeyPB(s)
		if seen[k] {
			continue
		}
		seen[k] = true
		dst = append(dst, s)
		changed = true
	}

	return dst, changed
}

// sourceKey / sourceKeyPB are the identity of a contribution for union/dedup: the who/what/
// where tuple that distinguishes one tool's contribution from another's. Two Sources with the
// same key are treated as the same contribution event, so re-importing the same scan does not
// pile up duplicate provenance rows. The two forms differ only in receiver (ORM vs PB) and
// share keyTuple so their notion of identity can never drift apart.
func sourceKey(s *pb.SourceORM) string {
	if s == nil {
		return ""
	}
	return keyTuple(s.Tool, s.Type, s.SessionId, s.Filename, s.Cracker, s.ServiceId)
}

func sourceKeyPB(s *pb.Source) string {
	if s == nil {
		return ""
	}
	return keyTuple(s.Tool, int32(s.Type), s.SessionId, s.Filename, s.Cracker, s.ServiceId)
}

func keyTuple(tool string, typ int32, session, filename, cracker, serviceID string) string {
	return strings.Join([]string{
		tool,
		strconv.Itoa(int(typ)),
		session,
		filename,
		cracker,
		serviceID,
	}, "\x00")
}
