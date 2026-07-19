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
	nmappb "github.com/d3c3ptive/aims/scan/pb/nmap"
)

// buildHost returns a fresh host (new objects every call, so folding two of them
// exercises the real re-import path rather than aliasing one pointer).
func buildHost(addr string, ports ...uint32) *host.Host {
	h := &host.Host{Addresses: []*network.Address{{Addr: addr, Type: "ipv4"}}}
	for _, p := range ports {
		h.Ports = append(h.Ports, &host.Port{Number: p, Protocol: "tcp"})
	}
	return h
}

func portOf(h *host.Host, number uint32) *host.Port {
	for _, p := range h.Ports {
		if p.Number == number {
			return p
		}
	}
	return nil
}

// The single most important property: re-importing the same scan is a no-op —
// no new host, no new port, and the second fold reports no change (DEDUP.md §9).
func TestFoldIdempotent(t *testing.T) {
	r := &Run{}
	r.AddHosts(buildHost("10.0.0.1", 80))

	changed := r.foldHost(buildHost("10.0.0.1", 80))
	if changed {
		t.Error("re-folding an identical host should be a no-op, got changed=true")
	}
	if len(r.Hosts) != 1 {
		t.Fatalf("want 1 host after re-import, got %d", len(r.Hosts))
	}
	if got := len(r.Hosts[0].Ports); got != 1 {
		t.Fatalf("want 1 port after re-import, got %d", got)
	}
}

// Two partial observations of the same host must union, never intersect and never
// drop: ports from both, plus enrichment (OS) that only one carried (DEDUP.md §0).
func TestFoldUnionEnrichment(t *testing.T) {
	r := &Run{}
	r.AddHosts(buildHost("10.0.0.1", 80))

	enrich := buildHost("10.0.0.1", 443)
	enrich.OSName = "Linux"
	r.AddHosts(enrich)

	if len(r.Hosts) != 1 {
		t.Fatalf("want 1 merged host, got %d", len(r.Hosts))
	}
	h := r.Hosts[0]
	if portOf(h, 80) == nil || portOf(h, 443) == nil {
		t.Errorf("want union of ports 80 and 443, got %d ports", len(h.Ports))
	}
	if h.OSName != "Linux" {
		t.Errorf("want OSName enriched to Linux, got %q", h.OSName)
	}
}

// Two genuinely distinct hosts (different address, no MAC) must stay separate: a
// coincidental overlap must not collapse them (the no-false-merge asymmetry).
func TestFoldNoFalseMerge(t *testing.T) {
	r := &Run{}
	r.AddHosts(buildHost("10.0.0.1", 80), buildHost("10.0.0.2", 80))

	if len(r.Hosts) != 2 {
		t.Fatalf("want 2 distinct hosts, got %d", len(r.Hosts))
	}
}

// Service fields are fill-only: a blank field is filled from a later scan, but a
// known value is never clobbered back to empty (DEDUP.md §4).
func TestServiceFillOnly(t *testing.T) {
	r := &Run{}

	bare := buildHost("10.0.0.1", 80)
	bare.Ports[0].Service = &network.Service{Name: "http"}
	r.AddHosts(bare)

	versioned := buildHost("10.0.0.1", 80)
	versioned.Ports[0].Service = &network.Service{Name: "http", Product: "nginx"}
	r.AddHosts(versioned)

	svc := portOf(r.Hosts[0], 80).Service
	if svc.Product != "nginx" {
		t.Errorf("want Product filled to nginx, got %q", svc.Product)
	}

	// A later scan that lost the product must not wipe the known one.
	regressed := buildHost("10.0.0.1", 80)
	regressed.Ports[0].Service = &network.Service{Name: "http"}
	r.AddHosts(regressed)

	if svc.Product != "nginx" {
		t.Errorf("known Product must not be clobbered by empty, got %q", svc.Product)
	}
}

// A contradicting port-state observation must not silently overwrite the first one.
// (Full state history needs the per-observation-timestamp proto change, gap C1;
// until then the non-destructive choice is to preserve the existing observation.)
func TestPortStateNoClobber(t *testing.T) {
	r := &Run{}

	open := buildHost("10.0.0.1", 80)
	open.Ports[0].State = &host.State{State: "open", Reason: "syn-ack"}
	r.AddHosts(open)

	filtered := buildHost("10.0.0.1", 80)
	filtered.Ports[0].State = &host.State{State: "filtered", Reason: "no-response"}
	r.AddHosts(filtered)

	if got := portOf(r.Hosts[0], 80).State.State; got != "open" {
		t.Errorf("existing port state must not be clobbered, got %q", got)
	}
}

// Scripts union by content identity: identical output dedups, differing output is
// kept as a second observation — opaque content is never fuzzy-merged (DEDUP.md §6.2).
func TestScriptUnionByContent(t *testing.T) {
	r := &Run{}

	withScript := func(output string) *host.Host {
		h := buildHost("10.0.0.1", 80)
		h.Ports[0].Scripts = []*nmappb.Script{{Name: "http-title", Output: output}}
		return h
	}

	r.AddHosts(withScript("Welcome"))
	r.AddHosts(withScript("Welcome")) // identical → dedup
	if got := len(portOf(r.Hosts[0], 80).Scripts); got != 1 {
		t.Fatalf("identical script output should dedup to 1, got %d", got)
	}

	r.AddHosts(withScript("Changed")) // different output → distinct observation
	if got := len(portOf(r.Hosts[0], 80).Scripts); got != 2 {
		t.Errorf("differing script output should be kept as a 2nd observation, got %d", got)
	}
}

// AddResult folds the universal feeder tuple into the host tree, and doing so twice
// with the same observation is idempotent.
func TestAddResultFeeder(t *testing.T) {
	r := &Run{}

	result := func() *Result {
		return &Result{
			Host:    &host.Host{Addresses: []*network.Address{{Addr: "10.0.0.1", Type: "ipv4"}}},
			Port:    &host.Port{Number: 80, Protocol: "tcp"},
			Service: &network.Service{Name: "http", Product: "nginx"},
		}
	}

	if err := r.AddResult(result()); err != nil {
		t.Fatalf("AddResult: %v", err)
	}
	if len(r.Hosts) != 1 || len(r.Hosts[0].Ports) != 1 {
		t.Fatalf("want 1 host / 1 port, got %d / %d", len(r.Hosts), len(r.Hosts[0].Ports))
	}
	if svc := portOf(r.Hosts[0], 80).Service; svc == nil || svc.Name != "http" {
		t.Fatalf("want service http attached to port 80, got %+v", svc)
	}

	if err := r.AddResult(result()); err != nil {
		t.Fatalf("AddResult (2nd): %v", err)
	}
	if len(r.Hosts) != 1 || len(r.Hosts[0].Ports) != 1 {
		t.Errorf("re-adding the same result must be idempotent, got %d hosts / %d ports",
			len(r.Hosts), len(r.Hosts[0].Ports))
	}

	if err := r.AddResult(nil); err == nil {
		t.Error("AddResult(nil) should error")
	}
}
