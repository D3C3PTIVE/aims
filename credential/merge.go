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
)

// MergeCore folds `src` into `dst` in place using the four field-classes (see CREDENTIALS.md §3):
//
//   - Identity fields (Public.Type/Username, Private.Type/Data, Realm.Key/Value) are left
//     untouched — by definition they are equal when two Cores match, and changing them would
//     mean a different credential.
//   - Enrichment fields (Public.Claims/Data, Private.JTRFormat) are fill-only: a known value is
//     never clobbered by an empty one, but an empty value is filled from src.
//   - Provenance (Origin) is first-wins: the original discovery origin is preserved.
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

	// Origin: first-wins — only adopt src's Origin if dst somehow has none.
	if dst.Origin == nil && src.Origin != nil {
		dst.Origin = src.Origin
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
