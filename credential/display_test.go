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
	"os"
	"path/filepath"
	"testing"

	"github.com/fatih/color"

	"github.com/d3c3ptive/aims/cmd/display"
	credential "github.com/d3c3ptive/aims/credential/pb"
)

// sampleCredentials returns a target NTLM credential (replayable, used in logins, imported) plus
// a second credential sharing the same hash — enough to exercise the banner badges, all three
// panes, and the replayable + secret-reuse + login insights.
func sampleCredentials() (target *credential.Core, all []*credential.Core) {
	const ntlm = "aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c"

	target = &credential.Core{
		Id:          "11112222-0000-0000-0000-000000000000",
		Public:      &credential.Public{Username: "administrator", Type: credential.PublicType_Username},
		Private:     &credential.Private{Type: credential.PrivateType_NTLMHash, Data: ntlm},
		Realm:       &credential.Realm{Value: "CORP"},
		Origin:      &credential.Origin{Type: credential.OriginType_Import, Filename: "secretsdump.txt"},
		LoginsCount: 2,
	}
	other := &credential.Core{
		Id:      "33334444-0000-0000-0000-000000000000",
		Public:  &credential.Public{Username: "helpdesk", Type: credential.PublicType_Username},
		Private: &credential.Private{Type: credential.PrivateType_NTLMHash, Data: ntlm},
	}
	return target, []*credential.Core{target, other}
}

// TestCredentialDetailGolden snapshots the plain-text (ANSI-stripped) detail view for a
// credential — the info view always reveals secrets, so Reveal is on. Regenerate with
// UPDATE_GOLDEN=1 and eyeball the diff before committing.
func TestCredentialDetailGolden(t *testing.T) {
	color.NoColor = true // disable fatih/color; raw Bold/Dim/Reset are stripped below
	Reveal = true        // info view reveals secrets
	defer func() { Reveal = false }()

	target, all := sampleCredentials()
	out := display.StripANSI(Detail(target, all).Render(120))
	compareGolden(t, "testdata/credential_detail.golden", out)
}

// compareGolden asserts got matches the golden file, or writes it when UPDATE_GOLDEN is set.
func compareGolden(t *testing.T, path, got string) {
	t.Helper()

	if os.Getenv("UPDATE_GOLDEN") != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote golden %s", path)
		return
	}

	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden (run with UPDATE_GOLDEN=1 to create): %v", err)
	}
	if got != string(want) {
		t.Errorf("detail view diverged from golden %s\n--- got ---\n%s\n--- want ---\n%s", path, got, want)
	}
}
