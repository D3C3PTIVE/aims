package db

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
	"context"
	"errors"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/d3c3ptive/aims/provenance"
)

// ScopeBySource restricts a query to the objects contributed by the named tool, via that
// object's provenance m2m join (e.g. "host_sources"/"host_id"). An empty tool is a no-op, so
// callers can thread a request's Source filter through unconditionally. It is the one-liner
// wrapper the per-domain servers share instead of each repeating the same Scopes(...) block.
func ScopeBySource(query *gorm.DB, joinTable, objectFK, tool string) *gorm.DB {
	if tool == "" {
		return query
	}
	return query.Scopes(provenance.WhereContributedBy(joinTable, objectFK, tool))
}

// FindMatch returns the first element of in for which pred is true, and whether one was found.
// It is the generic form of the per-domain "find the matching row in this slice" helpers
// (identity/absorbable/same-host lookups) so they need not each re-spell the loop.
func FindMatch[T any](in []T, pred func(T) bool) (T, bool) {
	for _, v := range in {
		if pred(v) {
			return v, true
		}
	}
	var zero T
	return zero, false
}

// Preload loads a database with the base clause.Associations preload plus every association named
// with a true value in filts (a false entry is skipped, so callers can gate a preload on a request
// flag). It is the map-driven form used when the set of associations is conditional; PreloadAll is
// the plainer variadic form for the unconditional case.
func Preload(database *gorm.DB, filts map[string]bool) *gorm.DB {
	names := make([]string, 0, len(filts))
	for name, load := range filts {
		if load {
			names = append(names, name)
		}
	}
	return PreloadAll(database, names...)
}

// PreloadAll loads a database with the base clause.Associations preload plus each named
// association, unconditionally. It is the single place association preloading is expressed, so the
// per-domain servers do not each re-implement the clause.Associations + range loop.
func PreloadAll(database *gorm.DB, names ...string) *gorm.DB {
	preloaded := database.Preload(clause.Associations)
	for _, name := range names {
		preloaded = preloaded.Preload(name)
	}
	return preloaded
}

// pbConvertible is anything the ORM layer can turn into its protobuf twin: every *ORM type emitted
// by protoc-gen-gorm carries a ToPB(ctx) (PB, error). P is the protobuf value type.
type pbConvertible[P any] interface {
	ToPB(context.Context) (P, error)
}

// ToPBs converts a slice of ORM rows to pointers to their protobuf twins, returning the first
// conversion error rather than swallowing it. It replaces the identical ORM→PB range loop the
// domain servers each hand-rolled (and which discarded the ToPB error with `pb, _ :=`).
func ToPBs[O pbConvertible[P], P any](ctx context.Context, in []O) ([]*P, error) {
	out := make([]*P, 0, len(in))
	for _, o := range in {
		p, err := o.ToPB(ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, &p)
	}
	return out, nil
}

// QueryToPBs runs a built query and returns the matching rows as their protobuf twins. It captures
// the tail every domain server's Read/List repeats verbatim: run First (single==true) or Find
// (single==false), treat gorm.ErrRecordNotFound as an empty result rather than an error (an
// unmatched filter is a valid "nothing here" answer the caller's len==0 branch renders, not a
// failure), then convert the ORM rows via ToPBs. The caller still owns everything type-specific —
// building/scoping/preloading the query and marshalling the typed request/response — so only the
// identical middle is shared. O is the ORM row type (e.g. *host.HostORM), P its protobuf twin.
func QueryToPBs[O pbConvertible[P], P any](ctx context.Context, query *gorm.DB, single bool) ([]*P, error) {
	rows := []O{}

	var err error
	if single {
		err = query.First(&rows).Error
	} else {
		err = query.Find(&rows).Error
	}
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	return ToPBs[O, P](ctx, rows)
}
