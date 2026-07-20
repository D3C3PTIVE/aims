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

	hostpb "github.com/d3c3ptive/aims/host/pb"
	network "github.com/d3c3ptive/aims/network/pb"
	scanpb "github.com/d3c3ptive/aims/scan/pb"
	scanrpcpb "github.com/d3c3ptive/aims/scan/pb/rpc"
)

func runAt(addr, rawXML string, port uint32) *scanpb.Run {
	return &scanpb.Run{
		Scanner: "nmap",
		RawXML:  rawXML,
		Hosts: []*hostpb.Host{{
			Addresses: []*network.Address{{Addr: addr}},
			Ports: []*hostpb.Port{{
				Number:   port,
				Protocol: "tcp",
				State:    &hostpb.State{State: "open"},
				Service:  &network.Service{Name: "http"},
			}},
		}},
	}
}

// TestReadScopesHostsPerRun guards the fix for the unscoped host-loading bug: Read must return each
// run linked ONLY to its own hosts (via the run_hosts join), not every host in the DB. Two runs
// observing disjoint hosts must each come back with exactly their one host — and that host's ports
// preloaded (the nested preload the old, buggy per-run Find was there to provide).
func TestReadScopesHostsPerRun(t *testing.T) {
	s, _, ctx := newTestServer(t)

	if _, err := s.Create(ctx, &scanrpcpb.CreateScanRequest{
		Scans: []*scanpb.Run{runAt("10.0.0.1", "<runA/>", 80)},
	}); err != nil {
		t.Fatalf("create run A: %v", err)
	}
	if _, err := s.Create(ctx, &scanrpcpb.CreateScanRequest{
		Scans: []*scanpb.Run{runAt("10.0.0.2", "<runB/>", 443)},
	}); err != nil {
		t.Fatalf("create run B: %v", err)
	}

	res, err := s.Read(ctx, &scanrpcpb.ReadScanRequest{
		Scan:    &scanpb.Run{},
		Filters: &scanrpcpb.RunFilters{Hosts: true, Ports: true},
	})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(res.GetScans()) != 2 {
		t.Fatalf("runs = %d, want 2", len(res.GetScans()))
	}

	seen := map[string]bool{}
	for _, run := range res.GetScans() {
		hosts := run.GetHosts()
		if len(hosts) != 1 {
			t.Fatalf("run carries %d hosts, want exactly 1 (its own) — unscoped-load regression", len(hosts))
		}
		addr := hosts[0].GetAddresses()[0].GetAddr()
		seen[addr] = true
		if len(hosts[0].GetPorts()) != 1 {
			t.Errorf("host %s has %d ports, want 1 (nested preload)", addr, len(hosts[0].GetPorts()))
		}
	}
	if !seen["10.0.0.1"] || !seen["10.0.0.2"] {
		t.Errorf("each run should map to its own address; saw %v", seen)
	}
}
