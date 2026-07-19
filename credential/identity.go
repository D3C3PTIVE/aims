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
	"strings"

	credential "github.com/d3c3ptive/aims/credential/pb"
)

// The credential identity model (see CREDENTIALS.md §2).
//
// A Core credential is identified by the *value* triple (Public, Private, Realm). Any component
// may be absent, and we match on whatever is present — never requiring what is unknown — so a
// credential discovered piecemeal at the start of an engagement (a bare username, then a
// password, then where it works) does not fan out into duplicate rows.

// publicKey returns a stable value-identity for a Public sub-credential, or "" if it carries no
// identifying value yet. Usernames are lower-cased so "Admin"/"admin" don't split into two rows.
func publicKey(p *credential.PublicORM) string {
	if p == nil {
		return ""
	}

	switch credential.PublicType(p.Type) {
	case credential.PublicType_PublicKey, credential.PublicType_Certificate:
		if p.Data == "" {
			return ""
		}
		return "k:" + p.Data
	case credential.PublicType_BlankUsername:
		return "u:"
	default:
		if p.Username == "" {
			return ""
		}
		return "u:" + strings.ToLower(p.Username)
	}
}

// privateKey returns a stable value-identity for a Private sub-credential (the secret/hash
// itself), or "" when the secret is still unknown.
func privateKey(p *credential.PrivateORM) string {
	if p == nil {
		return ""
	}

	if credential.PrivateType(p.Type) == credential.PrivateType_BlankPassword {
		return "p:blank"
	}

	if p.Data == "" {
		return ""
	}

	return "p:" + p.Data
}

// realmKey returns a stable value-identity for a Realm, or "" if empty.
func realmKey(r *credential.RealmORM) string {
	if r == nil || (r.Key == "" && r.Value == "") {
		return ""
	}
	return "r:" + r.Key + "=" + r.Value
}

// CoreIdentity is the value-based identity of a Core: the (public, private, realm) triple. Any
// component may be empty. Two Cores with the same non-empty identity are the same credential, so
// re-importing the exact same combination enriches the existing row rather than duplicating it.
func CoreIdentity(c *credential.CoreORM) string {
	if c == nil {
		return ""
	}
	return publicKey(c.Public) + "|" + privateKey(c.Private) + "|" + realmKey(c.Realm)
}

// AreCredentialsIdentical reports whether two Cores denote the same credential (same triple). A
// Core with no identity-bearing component at all ("||") is malformed (the model requires at least
// one of public/private/realm) and is never considered identical to anything.
func AreCredentialsIdentical(a, b *credential.CoreORM) bool {
	if a == nil || b == nil {
		return false
	}

	ida, idb := CoreIdentity(a), CoreIdentity(b)
	if ida == "||" || idb == "||" {
		return false
	}

	return ida == idb
}

// isPartial reports whether a Core is a "partial observation": a Public with neither a Private
// nor a Realm (e.g. a username enumerated before any secret is known).
func isPartial(c *credential.CoreORM) bool {
	if c == nil {
		return false
	}
	return publicKey(c.Public) != "" && privateKey(c.Private) == "" && realmKey(c.Realm) == ""
}

// AbsorbsPartial reports whether inserting `full` should collapse the existing `partial`
// Public-only Core: same Public, `full` adds a Private or Realm, and the partial carries no
// Logins of its own worth preserving (LoginsCount == 0). This keeps the username list clean
// (no "admin" bare + "admin" with-password pair) without ever silently dropping provenance.
func AbsorbsPartial(full, partial *credential.CoreORM) bool {
	if full == nil || partial == nil {
		return false
	}
	if isPartial(full) || !isPartial(partial) {
		return false
	}
	if partial.LoginsCount != 0 {
		return false
	}
	return publicKey(full.Public) != "" && publicKey(full.Public) == publicKey(partial.Public)
}
