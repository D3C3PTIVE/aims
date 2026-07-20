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
	host "github.com/d3c3ptive/aims/host/pb"
	scan "github.com/d3c3ptive/aims/scan/pb"
)

// This file is the hosts-as-targets bridge (SCAN.md Part C, plug point B): it turns stored
// Host objects into scan Targets so AIMS can drive a scanner against what it already knows,
// then fold the results back onto the same objects. Target is the input side of scan.Target
// (Address/Domain/Tag/Port); the scan/drive package consumes TargetSpecs to build a scanner's
// command line.

// TargetsFromHosts derives scan Targets from stored hosts. Each host contributes one Target per
// address (its identity anchor); a host with no address falls back to its hostnames as Domain
// targets. Duplicate endpoints (same address, or same domain) are collapsed so overlapping
// hosts never re-target the same thing. The result is deterministic in host/address order.
func TargetsFromHosts(hosts ...*host.Host) []*scan.Target {
	var targets []*scan.Target
	seen := make(map[string]bool)

	add := func(key string, t *scan.Target) {
		if key == "" || seen[key] {
			return
		}
		seen[key] = true
		targets = append(targets, t)
	}

	for _, h := range hosts {
		if h == nil {
			continue
		}
		hadAddress := false
		for _, a := range h.Addresses {
			if a == nil || a.Addr == "" {
				continue
			}
			hadAddress = true
			add("a:"+a.Addr, &scan.Target{Address: a.Addr})
		}
		if hadAddress {
			continue
		}
		// Address-less host (e.g. discovered only by name): target by hostname instead.
		for _, hn := range h.Hostnames {
			if hn == nil || hn.Name == "" {
				continue
			}
			add("d:"+hn.Name, &scan.Target{Domain: hn.Name})
		}
	}

	return targets
}

// TargetSpecs renders targets as the address/host tokens a scanner takes on its command line —
// Address preferred, else Domain — preserving order and dropping blanks, so the result can be
// appended straight onto a scanner's arguments.
func TargetSpecs(targets []*scan.Target) []string {
	specs := make([]string, 0, len(targets))
	for _, t := range targets {
		if t == nil {
			continue
		}
		switch {
		case t.Address != "":
			specs = append(specs, t.Address)
		case t.Domain != "":
			specs = append(specs, t.Domain)
		}
	}
	return specs
}
