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
	hostmerge "github.com/d3c3ptive/aims/host"
	host "github.com/d3c3ptive/aims/host/pb"
	network "github.com/d3c3ptive/aims/network/pb"
	scan "github.com/d3c3ptive/aims/scan/pb"
)

// This file is run-to-run diff (SCAN.md Part C, capability 2: attack-surface drift). Because
// Runs are timestamped and hosts share one identity primitive, an ndiff across ANY scanners at
// once is nearly free: reuse host.SameHost / host.SamePort so the diff agrees with the ingest
// fold on what "the same host/port" means, then classify each host and port as new, gone, or
// changed between an earlier Run (a) and a later Run (b).

// RunDiff is the delta from Run a (earlier) to Run b (later).
type RunDiff struct {
	NewHosts  []*host.Host // present in b, absent in a
	GoneHosts []*host.Host // present in a, absent in b
	Changed   []HostDelta  // present in both, but ports/services differ
}

// HostDelta captures how one host's surface changed between the two runs.
type HostDelta struct {
	Before    *host.Host
	After     *host.Host
	NewPorts  []*host.Port // in b, not in a
	GonePorts []*host.Port // in a, not in b
	Changed   []PortDelta  // same (proto, number), but service or state differs
}

// PortDelta is a port whose service identity or state changed between runs.
type PortDelta struct {
	Before *host.Port
	After  *host.Port
}

// Empty reports whether the two runs are identical at the host/port/service level.
func (d *RunDiff) Empty() bool {
	return d == nil || (len(d.NewHosts) == 0 && len(d.GoneHosts) == 0 && len(d.Changed) == 0)
}

// DiffRuns computes the drift from a (earlier) to b (later). Either may be nil (treated as an
// empty host set). The result is deterministic in b's then a's host order.
func DiffRuns(a, b *scan.Run) *RunDiff {
	diff := &RunDiff{}

	var aHosts, bHosts []*host.Host
	if a != nil {
		aHosts = a.Hosts
	}
	if b != nil {
		bHosts = b.Hosts
	}

	// New hosts + changed hosts: walk b, match against a.
	for _, bh := range bHosts {
		ah := findHost(aHosts, bh)
		if ah == nil {
			diff.NewHosts = append(diff.NewHosts, bh)
			continue
		}
		if hd, changed := diffHost(ah, bh); changed {
			diff.Changed = append(diff.Changed, hd)
		}
	}

	// Gone hosts: walk a, anything not in b disappeared.
	for _, ah := range aHosts {
		if findHost(bHosts, ah) == nil {
			diff.GoneHosts = append(diff.GoneHosts, ah)
		}
	}

	return diff
}

func findHost(hosts []*host.Host, target *host.Host) *host.Host {
	for _, h := range hosts {
		if hostmerge.SameHost(h, target) {
			return h
		}
	}
	return nil
}

func findPort(ports []*host.Port, target *host.Port) *host.Port {
	for _, p := range ports {
		if hostmerge.SamePort(p, target) {
			return p
		}
	}
	return nil
}

func diffHost(a, b *host.Host) (HostDelta, bool) {
	hd := HostDelta{Before: a, After: b}
	changed := false

	for _, bp := range b.Ports {
		ap := findPort(a.Ports, bp)
		if ap == nil {
			hd.NewPorts = append(hd.NewPorts, bp)
			changed = true
			continue
		}
		if portChanged(ap, bp) {
			hd.Changed = append(hd.Changed, PortDelta{Before: ap, After: bp})
			changed = true
		}
	}
	for _, ap := range a.Ports {
		if findPort(b.Ports, ap) == nil {
			hd.GonePorts = append(hd.GonePorts, ap)
			changed = true
		}
	}

	return hd, changed
}

// portChanged reports whether a same-keyed port's state or service identity moved between runs.
// It compares open/closed state and the service's name/product/version — the fields an operator
// watches for drift (a service that changed version, or a port that opened/closed).
func portChanged(a, b *host.Port) bool {
	if portState(a) != portState(b) {
		return true
	}
	as, bs := a.Service, b.Service
	return serviceName(as) != serviceName(bs) ||
		serviceProduct(as) != serviceProduct(bs) ||
		serviceVersion(as) != serviceVersion(bs)
}

func portState(p *host.Port) string {
	if p == nil || p.State == nil {
		return ""
	}
	return p.State.State
}

func serviceName(s *network.Service) string {
	if s == nil {
		return ""
	}
	return s.Name
}

func serviceProduct(s *network.Service) string {
	if s == nil {
		return ""
	}
	return s.Product
}

func serviceVersion(s *network.Service) string {
	if s == nil {
		return ""
	}
	return s.Version
}
