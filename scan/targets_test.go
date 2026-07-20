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
