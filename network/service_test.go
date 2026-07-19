package network

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
	host "github.com/d3c3ptive/aims/host/pb"
	network "github.com/d3c3ptive/aims/network/pb"
	nmap "github.com/d3c3ptive/aims/scan/pb/nmap"
)

// sampleService returns a representative open HTTP port with a service, state, and one NSE
// script — enough to exercise every part of the detail view (all three panes, the cleartext
// insight, and the Scripts section).
func sampleService() *host.Port {
	return &host.Port{
		Id:       "aabbccdd-0000-0000-0000-000000000000",
		Number:   80,
		Protocol: "tcp",
		Service: &network.Service{
			Protocol:  "http",
			Name:      "http",
			Product:   "nginx",
			Version:   "1.18.0",
			ExtraInfo: "Ubuntu",
			Method:    "probed",
		},
		State: &host.State{State: "open", Reason: "syn-ack"},
		Scripts: []*nmap.Script{
			{Name: "http-title", Output: "Welcome to nginx!"},
		},
	}
}

// TestServiceDetailGolden snapshots the plain-text (ANSI-stripped) detail view for a service, so
// any change to the field layout, panes, insights, or scripts section is caught. Regenerate with
// UPDATE_GOLDEN=1 and eyeball the diff before committing.
func TestServiceDetailGolden(t *testing.T) {
	color.NoColor = true // disable fatih/color; raw Bold/Dim/Reset are stripped below

	out := display.StripANSI(Detail(sampleService(), "web01").Render(120))
	compareGolden(t, "testdata/service_detail.golden", out)
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
