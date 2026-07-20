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
	"fmt"
	"sort"
	"strings"

	host "github.com/d3c3ptive/aims/host/pb"
	scan "github.com/d3c3ptive/aims/scan/pb"
)

// This file turns a scan *series* (the runs a `scan cleanup`/auto-supersede collapsed — one head
// plus its superseded siblings, all the same definition over time) into an evolution report rather
// than a flat list. It answers "how has this target's attack surface changed?" two ways:
//   - a drift TIMELINE: each run annotated with what changed since the previous one (reusing
//     DiffRuns), with runs that changed nothing collapsed into a single "×N unchanged" marker; and
//   - a stability SURFACE: every port classified across the whole series as stable / emerging /
//     flapping / receding, with a per-run presence sparkline.
// It is pure analysis over loaded runs (hosts+ports preloaded); rendering lives in cmd/scan.

// Stability classifies a port's presence pattern across a series.
type Stability int

const (
	Stable   Stability = iota // open in every run — the persistent attack surface
	Emerging                  // opened partway through and still open — newly exposed
	Receding                  // was open early, now closed — surface that went away
	Flapping                  // intermittent (on/off) — noise, filtering, or a load-balanced pool
)

func (s Stability) String() string {
	switch s {
	case Stable:
		return "stable"
	case Emerging:
		return "emerging"
	case Receding:
		return "receding"
	default:
		return "flapping"
	}
}

// SeriesHistory is the analysed evolution of one scan series.
type SeriesHistory struct {
	Runs     []*scan.Run     // the series ordered oldest -> newest
	Timeline []TimelineEntry // ordered newest -> oldest, unchanged runs collapsed
	Surface  []PortStability // one row per (addr, proto, port) ever seen open, sorted
	Span     int64           // seconds from first to last run
	Cadence  int64           // mean seconds between consecutive runs (0 if <2 runs)
}

// TimelineEntry is one row of the drift timeline: either a run (with its delta vs the previous run)
// or a collapsed marker standing in for a stretch of runs that changed nothing.
type TimelineEntry struct {
	Run       *scan.Run // the run this row represents (the newest of a collapsed stretch)
	Delta     *RunDiff  // change vs the previous (older) run; nil for the baseline (oldest run)
	Unchanged int       // >1 means this row collapses that many consecutive no-change runs
	Summary   []string  // short per-change lines ("+ 443/tcp https", "~ 22/tcp ssh 8.9 → 9.0")
}

// PortStability is one port's presence across the series.
type PortStability struct {
	Addr     string
	Proto    string
	Port     uint32
	Service  string
	Presence []bool // per run, oldest -> newest: was this port open in that run
	Class    Stability
}

// BuildHistory analyses a series (any order) into its drift timeline and stability surface.
func BuildHistory(runs []*scan.Run) SeriesHistory {
	ordered := append([]*scan.Run(nil), runs...)
	sort.SliceStable(ordered, func(i, j int) bool {
		return activityTime(ordered[i]) < activityTime(ordered[j]) // oldest first
	})

	h := SeriesHistory{Runs: ordered}
	h.Timeline = buildTimeline(ordered)
	h.Surface = buildSurface(ordered)
	if n := len(ordered); n >= 2 {
		h.Span = activityTime(ordered[n-1]) - activityTime(ordered[0])
		h.Cadence = h.Span / int64(n-1)
	}
	return h
}

// buildTimeline walks the series oldest->newest computing each run's delta vs the previous, then
// emits entries newest-first, collapsing maximal runs of no-change runs into one marker.
func buildTimeline(ordered []*scan.Run) []TimelineEntry {
	var entries []TimelineEntry
	for i := len(ordered) - 1; i >= 0; i-- {
		var delta *RunDiff
		if i > 0 {
			delta = DiffRuns(ordered[i-1], ordered[i])
		}

		// Collapse a run that changed nothing (and is not the baseline) into the previous marker.
		if delta != nil && delta.Empty() {
			if n := len(entries); n > 0 && entries[n-1].Unchanged > 0 {
				entries[n-1].Unchanged++
			} else {
				entries = append(entries, TimelineEntry{Run: ordered[i], Unchanged: 1})
			}
			continue
		}
		entries = append(entries, TimelineEntry{Run: ordered[i], Delta: delta, Summary: summarizeDelta(delta)})
	}
	return entries
}

// summarizeDelta renders a diff as short, sorted change lines: new/gone hosts, and new/gone/changed
// ports across the changed hosts. Nil or empty diff yields nil.
func summarizeDelta(d *RunDiff) []string {
	if d.Empty() {
		return nil
	}
	var lines []string
	// A whole new/gone host is one compact token (its port-state digest, not a line per port).
	for _, nh := range d.NewHosts {
		lines = append(lines, fmt.Sprintf("+ %s (%s)", hostAddr(nh), portSummary(nh)))
	}
	for _, gh := range d.GoneHosts {
		lines = append(lines, "- "+hostAddr(gh))
	}
	for _, hd := range d.Changed {
		for _, p := range hd.NewPorts {
			if portState(p) == "open" {
				lines = append(lines, "+ "+portLabel(p))
			}
		}
		for _, p := range hd.GonePorts {
			lines = append(lines, "- "+portLabel(p))
		}
		for _, pd := range hd.Changed {
			lines = append(lines, "~ "+portDeltaLabel(pd))
		}
	}
	sort.Strings(lines)
	return lines
}

// portSummary digests a host's ports for the drift timeline: open / filtered / closed counts, folding
// nmap's summarised ExtraPorts (e.g. a single "996 closed" record) into the totals — so a new host
// reads "1 open, 300 closed", not a bare open count. Empty when the host has no port information.
func portSummary(h *host.Host) string {
	counts := map[string]int{}
	for _, p := range h.GetPorts() {
		if st := portState(p); st != "" {
			counts[st]++
		}
	}
	for _, ep := range h.GetExtraPorts() {
		if ep.GetState() != "" {
			counts[ep.GetState()] += int(ep.GetCount())
		}
	}
	var parts []string
	for _, st := range []string{"open", "filtered", "closed"} {
		if n := counts[st]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, st))
		}
	}
	if len(parts) == 0 {
		return "no ports"
	}
	return strings.Join(parts, ", ")
}

// buildSurface classifies every (addr, proto, port) ever seen open across the series.
func buildSurface(ordered []*scan.Run) []PortStability {
	type key struct {
		addr, proto string
		num         uint32
	}
	n := len(ordered)
	presence := map[key][]bool{}
	service := map[key]string{}

	for i, run := range ordered {
		for _, hst := range run.GetHosts() {
			addr := hostAddr(hst)
			for _, p := range hst.GetPorts() {
				if portState(p) != "open" {
					continue
				}
				k := key{addr: addr, proto: p.GetProtocol(), num: p.GetNumber()}
				if presence[k] == nil {
					presence[k] = make([]bool, n)
				}
				presence[k][i] = true
				if s := serviceName(p.GetService()); s != "" {
					service[k] = s
				}
			}
		}
	}

	var surface []PortStability
	for k, pres := range presence {
		surface = append(surface, PortStability{
			Addr:     k.addr,
			Proto:    k.proto,
			Port:     k.num,
			Service:  service[k],
			Presence: pres,
			Class:    classify(pres),
		})
	}
	// Sort: stable first (persistent surface), then by address/port for stability.
	sort.SliceStable(surface, func(i, j int) bool {
		if surface[i].Class != surface[j].Class {
			return surface[i].Class < surface[j].Class
		}
		if surface[i].Addr != surface[j].Addr {
			return surface[i].Addr < surface[j].Addr
		}
		return surface[i].Port < surface[j].Port
	})
	return surface
}

// classify maps a presence vector (oldest->newest) to a Stability. All-present is stable; a
// contiguous block ending at the last run is emerging; a contiguous block starting at the first run
// (and now gone) is receding; anything else (intermittent) is flapping.
func classify(pres []bool) Stability {
	n := len(pres)
	first, last, count := -1, -1, 0
	for i, ok := range pres {
		if ok {
			if first < 0 {
				first = i
			}
			last = i
			count++
		}
	}
	if count == 0 {
		return Flapping
	}
	if count == n {
		return Stable
	}
	contiguous := count == last-first+1
	if !contiguous {
		return Flapping
	}
	if last == n-1 { // still open at the newest run
		return Emerging
	}
	if first == 0 { // open from the start, now gone
		return Receding
	}
	return Flapping
}

// Sparkline renders a presence vector as full/empty blocks, oldest -> newest.
func (p PortStability) Sparkline() string {
	var b strings.Builder
	for _, ok := range p.Presence {
		if ok {
			b.WriteRune('█')
		} else {
			b.WriteRune('░')
		}
	}
	return b.String()
}

// Ratio is the "present / total" fraction shown next to the sparkline.
func (p PortStability) Ratio() string {
	c := 0
	for _, ok := range p.Presence {
		if ok {
			c++
		}
	}
	return fmt.Sprintf("%d/%d", c, len(p.Presence))
}

//
// [ small helpers ] ------------------------------------------------------
//

func hostAddr(h *host.Host) string {
	for _, a := range h.GetAddresses() {
		if a.GetAddr() != "" {
			return a.GetAddr()
		}
	}
	for _, hn := range h.GetHostnames() {
		if hn.GetName() != "" {
			return hn.GetName()
		}
	}
	return "?"
}

func portLabel(p *host.Port) string {
	label := fmt.Sprintf("%d/%s", p.GetNumber(), p.GetProtocol())
	if s := serviceName(p.GetService()); s != "" {
		label += " " + s
	}
	return label
}

func portDeltaLabel(pd PortDelta) string {
	base := fmt.Sprintf("%d/%s", pd.After.GetNumber(), pd.After.GetProtocol())
	// State change takes priority; else a service/version move.
	if portState(pd.Before) != portState(pd.After) {
		return fmt.Sprintf("%s %s → %s", base, portState(pd.Before), portState(pd.After))
	}
	bv := strings.TrimSpace(serviceName(pd.Before.GetService()) + " " + serviceVersion(pd.Before.GetService()))
	av := strings.TrimSpace(serviceName(pd.After.GetService()) + " " + serviceVersion(pd.After.GetService()))
	if bv != av {
		return fmt.Sprintf("%s %s → %s", base, bv, av)
	}
	return base
}
