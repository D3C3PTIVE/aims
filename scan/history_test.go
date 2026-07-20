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

func openPort(num uint32, svc string) *host.Port {
	return &host.Port{
		Number:   num,
		Protocol: "tcp",
		State:    &host.State{State: "open"},
		Service:  &network.Service{Name: svc},
	}
}

func runAt(finished int64, addr string, ports ...*host.Port) *scan.Run {
	return &scan.Run{
		Scanner: "nmap",
		Args:    "-sT 127.0.0.1",
		Stats:   &scan.Stats{Finished: &scan.Finished{Time: finished, Exit: "success"}},
		Hosts:   []*host.Host{{Addresses: []*network.Address{{Addr: addr}}, Ports: ports}},
	}
}

// TestBuildHistorySurface asserts the stability classification across a series: a port open in every
// run is stable, one that appears and stays is emerging, one present then gone is receding, and an
// intermittent one is flapping — each with the right presence sparkline (oldest -> newest).
func TestBuildHistorySurface(t *testing.T) {
	// Presence over runs r1,r2,r3 (oldest->newest):
	//   22   : T T T  stable
	//   443  : F T T  emerging (appeared, still open)
	//   8080 : T F T  flapping (intermittent)
	//   23   : T T F  receding (open from start, now gone)
	runs := []*scan.Run{
		runAt(300, "127.0.0.1", openPort(22, "ssh"), openPort(443, "https"), openPort(8080, "http")), // newest, out of order on purpose
		runAt(100, "127.0.0.1", openPort(22, "ssh"), openPort(8080, "http"), openPort(23, "telnet")),
		runAt(200, "127.0.0.1", openPort(22, "ssh"), openPort(443, "https"), openPort(23, "telnet")),
	}

	h := BuildHistory(runs)

	byPort := map[uint32]PortStability{}
	for _, ps := range h.Surface {
		byPort[ps.Port] = ps
	}
	cases := map[uint32]struct {
		class Stability
		spark string
	}{
		22:   {Stable, "███"},
		443:  {Emerging, "░██"},
		8080: {Flapping, "█░█"},
		23:   {Receding, "██░"},
	}
	for port, want := range cases {
		got, ok := byPort[port]
		if !ok {
			t.Errorf("port %d missing from surface", port)
			continue
		}
		if got.Class != want.class {
			t.Errorf("port %d class = %s, want %s", port, got.Class, want.class)
		}
		if got.Sparkline() != want.spark {
			t.Errorf("port %d sparkline = %q, want %q", port, got.Sparkline(), want.spark)
		}
	}

	if h.Span != 200 { // 300 - 100
		t.Errorf("span = %d, want 200", h.Span)
	}
	if h.Cadence != 100 { // 200 / 2 gaps
		t.Errorf("cadence = %d, want 100", h.Cadence)
	}
}

// TestBuildHistoryTimeline asserts the drift timeline is newest-first, the baseline has no delta,
// each change is summarized, and a run that changed nothing is collapsed into an "unchanged" marker.
func TestBuildHistoryTimeline(t *testing.T) {
	runs := []*scan.Run{
		runAt(100, "127.0.0.1", openPort(22, "ssh")),                         // baseline
		runAt(200, "127.0.0.1", openPort(22, "ssh"), openPort(443, "https")), // + 443
		runAt(300, "127.0.0.1", openPort(22, "ssh"), openPort(443, "https")), // unchanged
	}

	h := BuildHistory(runs)

	// Newest-first: [unchanged(300), run(200, +443), baseline(100)].
	if len(h.Timeline) != 3 {
		t.Fatalf("timeline entries = %d, want 3", len(h.Timeline))
	}
	if h.Timeline[0].Unchanged != 1 {
		t.Errorf("newest entry should be an unchanged marker, got Unchanged=%d", h.Timeline[0].Unchanged)
	}
	if h.Timeline[2].Delta != nil {
		t.Errorf("oldest entry is the baseline and must have no delta")
	}
	// The middle entry opened 443.
	found := false
	for _, line := range h.Timeline[1].Summary {
		if line == "+ 443/tcp https" {
			found = true
		}
	}
	if !found {
		t.Errorf("middle entry summary should note + 443/tcp https, got %v", h.Timeline[1].Summary)
	}
}
