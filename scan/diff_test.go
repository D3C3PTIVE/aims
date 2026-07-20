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
	"testing"

	host "github.com/d3c3ptive/aims/host/pb"
	network "github.com/d3c3ptive/aims/network/pb"
	scan "github.com/d3c3ptive/aims/scan/pb"
)

func diffPort(num uint32, name, product, version, state string) *host.Port {
	return &host.Port{
		Number:   num,
		Protocol: "tcp",
		State:    &host.State{State: state},
		Service:  &network.Service{Name: name, Product: product, Version: version},
	}
}

func diffHostAt(addr string, ports ...*host.Port) *host.Host {
	return &host.Host{
		Addresses: []*network.Address{{Addr: addr}},
		Ports:     ports,
	}
}

func TestDiffRuns(t *testing.T) {
	a := &scan.Run{Hosts: []*host.Host{
		diffHostAt("10.0.0.1",
			diffPort(22, "ssh", "OpenSSH", "8.9", "open"),
			diffPort(80, "http", "nginx", "1.20", "open"),
		),
		diffHostAt("10.0.0.2", diffPort(443, "https", "", "", "open")), // disappears in b
	}}

	b := &scan.Run{Hosts: []*host.Host{
		diffHostAt("10.0.0.1",
			diffPort(22, "ssh", "OpenSSH", "9.6", "open"), // version 8.9 -> 9.6 (changed)
			diffPort(80, "http", "nginx", "1.20", "open"), // unchanged
			diffPort(8080, "http-proxy", "", "", "open"),  // newly open
		),
		diffHostAt("10.0.0.3", diffPort(22, "ssh", "", "", "open")), // new host
	}}

	d := DiffRuns(a, b)

	if len(d.NewHosts) != 1 || d.NewHosts[0].Addresses[0].Addr != "10.0.0.3" {
		t.Errorf("NewHosts = %+v, want [10.0.0.3]", addrs(d.NewHosts))
	}
	if len(d.GoneHosts) != 1 || d.GoneHosts[0].Addresses[0].Addr != "10.0.0.2" {
		t.Errorf("GoneHosts = %+v, want [10.0.0.2]", addrs(d.GoneHosts))
	}
	if len(d.Changed) != 1 {
		t.Fatalf("Changed = %d host deltas, want 1", len(d.Changed))
	}

	hd := d.Changed[0]
	if hd.After.Addresses[0].Addr != "10.0.0.1" {
		t.Errorf("changed host = %s, want 10.0.0.1", hd.After.Addresses[0].Addr)
	}
	if len(hd.NewPorts) != 1 || hd.NewPorts[0].Number != 8080 {
		t.Errorf("NewPorts = %+v, want [8080]", hd.NewPorts)
	}
	if len(hd.GonePorts) != 0 {
		t.Errorf("GonePorts = %+v, want none", hd.GonePorts)
	}
	if len(hd.Changed) != 1 || hd.Changed[0].After.Number != 22 {
		t.Fatalf("port Changed = %+v, want [22]", hd.Changed)
	}
	if hd.Changed[0].Before.Service.Version != "8.9" || hd.Changed[0].After.Service.Version != "9.6" {
		t.Errorf("port 22 version delta = %s->%s, want 8.9->9.6",
			hd.Changed[0].Before.Service.Version, hd.Changed[0].After.Service.Version)
	}
}

func TestDiffRunsEmpty(t *testing.T) {
	a := &scan.Run{Hosts: []*host.Host{
		diffHostAt("10.0.0.1", diffPort(22, "ssh", "OpenSSH", "9.6", "open")),
	}}
	if !DiffRuns(a, a).Empty() {
		t.Error("a run diffed against itself should be Empty")
	}
	if !DiffRuns(nil, nil).Empty() {
		t.Error("nil vs nil should be Empty")
	}
}

func addrs(hosts []*host.Host) []string {
	var out []string
	for _, h := range hosts {
		if len(h.Addresses) > 0 {
			out = append(out, h.Addresses[0].Addr)
		}
	}
	return out
}
