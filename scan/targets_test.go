package scan

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
	"reflect"
	"testing"

	host "github.com/d3c3ptive/aims/host/pb"
	network "github.com/d3c3ptive/aims/network/pb"
	scan "github.com/d3c3ptive/aims/scan/pb"
)

func TestTargetsFromHosts(t *testing.T) {
	hosts := []*host.Host{
		{
			// Duplicate address collapses to one target; hostname ignored because addressed.
			Addresses: []*network.Address{{Addr: "10.0.0.1"}, {Addr: "10.0.0.1"}},
			Hostnames: []*host.Hostname{{Name: "ignored.example"}},
		},
		{
			// No address → fall back to hostname as a Domain target.
			Hostnames: []*host.Hostname{{Name: "b.example"}},
		},
		{
			// Same address as the first host → deduplicated across hosts.
			Addresses: []*network.Address{{Addr: "10.0.0.1"}},
		},
		{Addresses: []*network.Address{{Addr: "10.0.0.2"}}},
		nil,
	}

	specs := TargetSpecs(TargetsFromHosts(hosts...))
	want := []string{"10.0.0.1", "b.example", "10.0.0.2"}
	if !reflect.DeepEqual(specs, want) {
		t.Errorf("specs = %v, want %v", specs, want)
	}
}

func TestTargetMatchesHost(t *testing.T) {
	addrHost := &host.Host{Addresses: []*network.Address{{Addr: "10.0.0.1"}}}
	nameHost := &host.Host{Hostnames: []*host.Hostname{{Name: "b.example"}}}

	tests := []struct {
		name   string
		target *scan.Target
		host   *host.Host
		want   bool
	}{
		{"address match", &scan.Target{Address: "10.0.0.1"}, addrHost, true},
		{"address mismatch", &scan.Target{Address: "10.0.0.9"}, addrHost, false},
		{"domain match", &scan.Target{Domain: "b.example"}, nameHost, true},
		{"domain mismatch", &scan.Target{Domain: "other.example"}, nameHost, false},
		{"address target vs name-only host", &scan.Target{Address: "10.0.0.1"}, nameHost, false},
		{"nil target", nil, addrHost, false},
		{"nil host", &scan.Target{Address: "10.0.0.1"}, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := TargetMatchesHost(tt.target, tt.host); got != tt.want {
				t.Errorf("TargetMatchesHost() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestMarkAndRemainingTargets covers the resume core: a streamed result marks its target done, an
// already-done target is not re-counted, an unreached target stays remaining, and RemainingTargets
// returns exactly the untouched work a resume would re-scan.
func TestMarkAndRemainingTargets(t *testing.T) {
	targets := []*scan.Target{
		{Address: "10.0.0.1"},
		{Address: "10.0.0.2"},
		{Domain: "b.example"},
	}

	// A result for 10.0.0.1 arrives.
	if n := MarkTargetsDone(targets, &host.Host{Addresses: []*network.Address{{Addr: "10.0.0.1"}}}); n != 1 {
		t.Fatalf("first mark newly-marked = %d, want 1", n)
	}
	// The same host again marks nothing new (idempotent completion).
	if n := MarkTargetsDone(targets, &host.Host{Addresses: []*network.Address{{Addr: "10.0.0.1"}}}); n != 0 {
		t.Fatalf("re-mark newly-marked = %d, want 0", n)
	}
	// A down host still counts as done — it was scanned.
	if n := MarkTargetsDone(targets, &host.Host{
		Addresses: []*network.Address{{Addr: "10.0.0.2"}},
		Status:    &host.Status{State: "down"},
	}); n != 1 {
		t.Fatalf("down-host mark newly-marked = %d, want 1", n)
	}

	// b.example was never reached → it is the only remaining work.
	remaining := RemainingTargets(targets)
	if got := TargetSpecs(remaining); !reflect.DeepEqual(got, []string{"b.example"}) {
		t.Errorf("remaining specs = %v, want [b.example]", got)
	}
}

func TestTargetSpecsPrefersAddress(t *testing.T) {
	targets := []*scan.Target{
		{Address: "1.2.3.4", Domain: "host.example"}, // Address wins
		{Domain: "only-domain.example"},
		{}, // empty → dropped
		nil,
	}
	specs := TargetSpecs(targets)
	want := []string{"1.2.3.4", "only-domain.example"}
	if !reflect.DeepEqual(specs, want) {
		t.Errorf("specs = %v, want %v", specs, want)
	}
}
