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
	"context"
	"path/filepath"
	"testing"

	_ "github.com/ncruces/go-sqlite3/embed" // loads the pure-Go SQLite (wazero) binary
	"github.com/ncruces/go-sqlite3/gormlite"
	"gorm.io/gorm"

	credpb "github.com/d3c3ptive/aims/credential/pb"
	credentials "github.com/d3c3ptive/aims/credential/pb/rpc"
	schema "github.com/d3c3ptive/aims/db"
)

// newTestServer returns a credential server backed by a fresh, migrated pure-Go sqlite DB.
func newTestServer(t *testing.T) (*server, context.Context) {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "aims.db")
	gdb, err := gorm.Open(gormlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := schema.Migrate(gdb); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return New(gdb), context.Background()
}

// userCore is a username/password credential; keyCore is a public-key credential with no username
// (rendered by the completer through its id fallback), used to exercise the id leg of the filter.
func userCore(username string) *credpb.Core {
	return &credpb.Core{
		Public:  &credpb.Public{Type: credpb.PublicType_Username, Username: username},
		Private: &credpb.Private{Type: credpb.PrivateType_Password, Data: "pw-" + username},
	}
}

// TestListPrefixScopes locks the server-side credential completion filter
// (ReadCredentialRequest.Prefix): a set prefix restricts List to credentials whose public username
// begins with it, an empty prefix is a no-op, and LIKE wildcards typed at the prompt match
// literally rather than as SQL wildcards.
func TestListPrefixScopes(t *testing.T) {
	s, ctx := newTestServer(t)

	seed := []*credpb.Core{
		userCore("admin"),
		userCore("administrator"),
		userCore("alice"),
		userCore("bob"),
		userCore("a_b"),
	}
	if _, err := s.Create(ctx, &credentials.CreateCredentialRequest{Credentials: seed}); err != nil {
		t.Fatalf("seed create: %v", err)
	}

	count := func(prefix string) int {
		t.Helper()
		res, err := s.List(ctx, &credentials.ReadCredentialRequest{
			Credential: &credpb.Core{},
			Prefix:     prefix,
		})
		if err != nil {
			t.Fatalf("list (prefix=%q): %v", prefix, err)
		}
		return len(res.GetCredentials())
	}

	if n := count("admin"); n != 2 {
		t.Errorf("prefix %q matched %d creds, want 2 (admin, administrator)", "admin", n)
	}
	if n := count("al"); n != 1 {
		t.Errorf("prefix %q matched %d creds, want 1 (alice)", "al", n)
	}
	if n := count(""); n != 5 {
		t.Errorf("empty prefix matched %d creds, want all 5 (no-op)", n)
	}
	if n := count("nfocontext"); n != 0 {
		t.Errorf("prefix %q matched %d creds, want 0", "nfocontext", n)
	}
	// '_' is a SQL LIKE wildcard; escaped, "a_b" must match the literal "a_b" username only — not
	// "alice"/"admin"/… — so exactly the one seeded literal matches.
	if n := count("a_b"); n != 1 {
		t.Errorf("prefix %q matched %d creds, want 1 (underscore escaped, literal match)", "a_b", n)
	}
}
