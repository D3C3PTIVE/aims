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
	credential "github.com/d3c3ptive/aims/credential/pb"
	"github.com/d3c3ptive/aims/provenance"
)

// MergeCore folds `src` into `dst` in place using the four field-classes (see CREDENTIALS.md §3):
//
//   - Identity fields (Public.Type/Username, Private.Type/Data, Realm.Key/Value) are left
//     untouched — by definition they are equal when two Cores match, and changing them would
//     mean a different credential.
//   - Enrichment fields (Public.Claims/Data, Private.JTRFormat) are fill-only: a known value is
//     never clobbered by an empty one, but an empty value is filled from src.
//   - Provenance (Sources) is UNION, not first-wins: every contributing tool a matched Core has
//     been seen from is accumulated, so a second tool enriching a known credential adds its
//     Source rather than being dropped (the former single Origin was first-wins).
//   - LoginsCount is derived from the Logins table and never taken from the wire.
//
// It returns true if dst was actually changed, so callers can skip a no-op write.
func MergeCore(dst, src *credential.CoreORM) (changed bool) {
	if dst == nil || src == nil {
		return false
	}

	// Public: fill-only Claims/Data.
	if dst.Public != nil && src.Public != nil {
		changed = fill(&dst.Public.Claims, src.Public.Claims) || changed
		changed = fill(&dst.Public.Data, src.Public.Data) || changed
	}

	// Private: fill-only JTRFormat (a cracker may identify the format after the fact).
	if dst.Private != nil && src.Private != nil {
		changed = fill(&dst.Private.JTRFormat, src.Private.JTRFormat) || changed
	}

	// Sources: union — accumulate src's contributions that dst does not already carry, so
	// provenance from multiple tools survives the merge instead of the first/last winning.
	if merged, grew := provenance.MergeSourceORMs(dst.Sources, src.Sources); grew {
		dst.Sources = merged
		changed = true
	}

	return changed
}

// fill writes src into *dst only if *dst is empty and src is not (the fill-only rule).
func fill(dst *string, src string) bool {
	if *dst == "" && src != "" {
		*dst = src
		return true
	}
	return false
}
