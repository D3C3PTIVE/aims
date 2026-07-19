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

// helpers ----------------------------------------------------------------

func user(name string) *credential.PublicORM {
	return &credential.PublicORM{Type: int32(credential.PublicType_Username), Username: name}
}

func pass(data string) *credential.PrivateORM {
	return &credential.PrivateORM{Type: int32(credential.PrivateType_Password), Data: data}
}

func realm(key, val string) *credential.RealmORM {
	return &credential.RealmORM{Key: key, Value: val}
}

func core(p *credential.PublicORM, s *credential.PrivateORM, r *credential.RealmORM) *credential.CoreORM {
	return &credential.CoreORM{Public: p, Private: s, Realm: r}
}

// tests ------------------------------------------------------------------

// The core dedup contract: importing the exact same combination twice is the same credential
// (so Upsert enriches instead of duplicating).
func TestAreCredentialsIdentical_SameTriple(t *testing.T) {
	a := core(user("admin"), pass("hunter2"), realm("domain", "CORP"))
	b := core(user("admin"), pass("hunter2"), realm("domain", "CORP"))
	if !AreCredentialsIdentical(a, b) {
		t.Fatalf("identical credentials not recognised as the same")
	}
}

// Usernames must not split on case, or enumeration + later loot would duplicate.
func TestAreCredentialsIdentical_UsernameCaseInsensitive(t *testing.T) {
	if !AreCredentialsIdentical(core(user("Admin"), nil, nil), core(user("admin"), nil, nil)) {
		t.Fatalf("Admin/admin should be the same public identity")
	}
}

// Same user, different secret ⇒ different credentials (Metasploit-style: the Core is the combination).
func TestAreCredentialsIdentical_ConflictingSecret(t *testing.T) {
	if AreCredentialsIdentical(core(user("admin"), pass("hunter2"), nil), core(user("admin"), pass("swordfish"), nil)) {
		t.Fatalf("different secrets must not be treated as the same credential")
	}
}

// A partial (username only) and a full credential sharing that username are NOT identical...
func TestPartial_NotIdenticalToFull(t *testing.T) {
	if AreCredentialsIdentical(core(user("admin"), nil, nil), core(user("admin"), pass("hunter2"), nil)) {
		t.Fatalf("partial and full should be distinct identities")
	}
}

// ...but the full credential should ABSORB the partial (§2.3): same public, adds a secret, and the
// partial carries no logins.
func TestAbsorbsPartial(t *testing.T) {
	full := core(user("admin"), pass("hunter2"), nil)
	partial := core(user("admin"), nil, nil)

	if !AbsorbsPartial(full, partial) {
		t.Fatalf("full credential should absorb the bare-username partial")
	}
	// A partial with its own logins must be preserved, not absorbed.
	partial.LoginsCount = 1
	if AbsorbsPartial(full, partial) {
		t.Fatalf("a partial carrying logins must not be absorbed")
	}
	// A partial for a different user is untouched.
	if AbsorbsPartial(full, core(user("guest"), nil, nil)) {
		t.Fatalf("partial for a different user must not be absorbed")
	}
}

// A malformed credential with no identity-bearing component is never identical to anything.
func TestAreCredentialsIdentical_EmptyIsNeverIdentical(t *testing.T) {
	if AreCredentialsIdentical(core(nil, nil, nil), core(nil, nil, nil)) {
		t.Fatalf("credentials with no identity component must not match")
	}
}

func TestIsPartial(t *testing.T) {
	if !isPartial(core(user("admin"), nil, nil)) {
		t.Fatalf("username-only credential should be partial")
	}
	if isPartial(core(user("admin"), pass("x"), nil)) {
		t.Fatalf("credential with a secret is not partial")
	}
}
