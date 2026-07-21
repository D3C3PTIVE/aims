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
	"strings"

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

	// Index each side once, then match by O(1) lookup instead of re-scanning a slice per host
	// (findHost was O(n·m)). The indexes only answer "which host matches"; the b-then-a output
	// order DiffRuns documents is preserved because we still walk the original slices in order.
	aIndex := newHostIndex(aHosts)
	bIndex := newHostIndex(bHosts)

	// The two port indexes are allocated once here and reset (not reallocated) for each matched
	// host pair, so port matching costs one allocation for the whole diff rather than one per host.
	aPorts := portIndex{}
	bPorts := portIndex{}

	// New hosts + changed hosts: walk b, match against a.
	for _, bh := range bHosts {
		ah := aIndex.find(bh)
		if ah == nil {
			diff.NewHosts = append(diff.NewHosts, bh)
			continue
		}
		if hd, changed := diffHost(ah, bh, aPorts, bPorts); changed {
			diff.Changed = append(diff.Changed, hd)
		}
	}

	// Gone hosts: walk a, anything not in b disappeared.
	for _, ah := range aHosts {
		if bIndex.find(ah) == nil {
			diff.GoneHosts = append(diff.GoneHosts, ah)
		}
	}

	return diff
}

// hostIndex resolves a host to its match within one Run's host slice in O(1). It mirrors
// hostmerge.SameHost's keyed-first identity — MAC is definitive when both sides carry one,
// otherwise any shared address decides — so the diff agrees with the ingest fold on what "the
// same host" is. Entries are first-wins (never overwritten), so a duplicate key resolves to the
// same host the old linear findHost returned.
type hostIndex struct {
	byMAC  map[string]*host.Host // lower-cased MAC → first host carrying it
	byAddr map[string]*host.Host // address → first host carrying it
}

func newHostIndex(hosts []*host.Host) *hostIndex {
	idx := &hostIndex{
		byAddr: make(map[string]*host.Host, len(hosts)),
	}
	for _, h := range hosts {
		if h == nil {
			continue
		}
		// byMAC is allocated lazily: most scans have no MAC on hosts, so we avoid a wasted map.
		if h.MAC != "" {
			key := strings.ToLower(h.MAC)
			if idx.byMAC == nil {
				idx.byMAC = make(map[string]*host.Host)
			}
			if idx.byMAC[key] == nil {
				idx.byMAC[key] = h
			}
		}
		for _, a := range h.Addresses {
			if a == nil || a.Addr == "" {
				continue
			}
			if idx.byAddr[a.Addr] == nil {
				idx.byAddr[a.Addr] = h
			}
		}
	}
	return idx
}

// find returns the indexed host matching target under SameHost, or nil. MAC takes precedence
// over address, matching SameHost's rule that a shared MAC is definitive when both hosts carry
// one; an address hit is re-checked with SameHost so a both-have-MAC-but-differ pair (which
// SameHost never merges on a shared address) is rejected rather than falsely matched.
func (idx *hostIndex) find(target *host.Host) *host.Host {
	if target == nil {
		return nil
	}
	if target.MAC != "" {
		if h := idx.byMAC[strings.ToLower(target.MAC)]; h != nil {
			return h
		}
	}
	for _, a := range target.Addresses {
		if a == nil || a.Addr == "" {
			continue
		}
		if h := idx.byAddr[a.Addr]; h != nil && hostmerge.SameHost(h, target) {
			return h
		}
	}
	return nil
}

// diffHost matches b's ports against a's by lookup. aPorts/bPorts are caller-owned indexes reused
// across host pairs; diffHost resets them to the two port slices before probing.
func diffHost(a, b *host.Host, aPorts, bPorts portIndex) (HostDelta, bool) {
	hd := HostDelta{Before: a, After: b}
	changed := false

	aPorts.reset(a.Ports)
	bPorts.reset(b.Ports)

	for _, bp := range b.Ports {
		ap := aPorts.find(bp)
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
		if bPorts.find(ap) == nil {
			hd.GonePorts = append(hd.GonePorts, ap)
			changed = true
		}
	}

	return hd, changed
}

// portKey is a port's natural key within a host: (number, lower-cased protocol), mirroring
// hostmerge.SamePort's case-insensitive-protocol comparison.
type portKey struct {
	number   uint32
	protocol string
}

// portIndex resolves a port to its match within one host's port slice in O(1). First-wins (never
// overwritten), so a duplicate (number, protocol) resolves to the same port the old findPort did.
type portIndex map[portKey]*host.Port

// reset clears the index and repopulates it from ports, reusing the backing map so a diff over
// many host pairs indexes ports without reallocating for each one.
func (idx portIndex) reset(ports []*host.Port) {
	clear(idx)
	for _, p := range ports {
		if p == nil {
			continue
		}
		key := portKey{p.Number, strings.ToLower(p.Protocol)}
		if idx[key] == nil {
			idx[key] = p
		}
	}
}

func (idx portIndex) find(target *host.Port) *host.Port {
	if target == nil {
		return nil
	}
	return idx[portKey{target.Number, strings.ToLower(target.Protocol)}]
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
