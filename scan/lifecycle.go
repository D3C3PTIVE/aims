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
	"sort"
	"strings"

	scan "github.com/d3c3ptive/aims/scan/pb"
)

//
// [ Run lifecycle — cleanup / tombstone / history ] ----------------------
//
// A repeated scan definition (cron-scanning the same targets) accumulates near-duplicate Runs.
// Collapsing them must NOT delete the older runs: those are exactly what `scan diff` reads to show
// attack-surface drift. So the primary mechanism is a *tombstone* — the older siblings of a series
// stay in the DB (rows + run_hosts links intact) but are marked SupersededBy the surviving head, so
// the default `scan list` shows one row per series while `scan history` and `scan diff` still reach
// them. Hard deletion is reserved for the strict subset whose *output* is byte-identical (a
// re-imported scan), where the dropped rows carry no unique information.
//
// This file is the pure-Go core (no DB, no RPC): it groups runs into series, picks each series'
// head, and produces a CleanupPlan of field mutations the caller persists via the existing Upsert /
// Delete RPCs. Identity here is deliberately coarse (the scan *definition*), distinct from
// AreScansIdentical's fine *output* identity — the two answer different questions (§ the SCAN.md
// Phase-5 table).

// IsSuperseded reports whether a run has been tombstoned under a surviving head.
func IsSuperseded(r *scan.Run) bool { return r.GetSupersededBy() != "" }

// VisibleRuns drops tombstoned runs — the default view for `scan list` and completions. Callers that
// need the full set (history, diff, cleanup) use the unfiltered slice.
func VisibleRuns(runs []*scan.Run) []*scan.Run {
	out := runs[:0:0]
	for _, r := range runs {
		if !IsSuperseded(r) {
			out = append(out, r)
		}
	}
	return out
}

// seriesKey identifies the scan *definition* a run is an instance of: same scanner, same
// (order-normalized) arguments, same target set collapse into one series. A named profile, when
// present, stands in for the arguments — it is the stable definition identity and sidesteps
// arg-string cosmetics entirely.
func seriesKey(r *scan.Run) string {
	var b strings.Builder
	b.WriteString(r.GetScanner())
	b.WriteByte(0)
	if p := r.GetProfileName(); p != "" {
		b.WriteString("profile:")
		b.WriteString(p)
	} else {
		b.WriteString(normalizeArgs(r.GetArgs()))
	}
	b.WriteByte(0)
	b.WriteString(sortedTargets(r))
	return b.String()
}

// normalizeArgs canonicalizes an argument string so cosmetic reordering/whitespace does not split a
// series: whitespace-split, sort, single-space-join. Deterministic — two equal arg strings always
// map to the same key regardless of token order.
func normalizeArgs(args string) string {
	fields := strings.Fields(args)
	sort.Strings(fields)
	return strings.Join(fields, " ")
}

// sortedTargets is the run's target specifications, de-duplicated and sorted, joined — the scope
// half of a series identity. Empty when a run carries no explicit targets (then scanner+args alone
// key the series).
func sortedTargets(r *scan.Run) string {
	seen := map[string]bool{}
	var specs []string
	for _, t := range r.GetTargets() {
		spec := t.GetSpecification()
		if spec == "" {
			spec = t.GetAddress()
		}
		if spec == "" || seen[spec] {
			continue
		}
		seen[spec] = true
		specs = append(specs, spec)
	}
	sort.Strings(specs)
	return strings.Join(specs, ",")
}

// pickHead selects the surviving run of a series. Quality ranks before recency: a clean `done` run
// is never demoted under a later `failed`/`interrupted` one. Among equally-ranked runs, the most
// recent wins.
func pickHead(runs []*scan.Run) *scan.Run {
	var head *scan.Run
	for _, r := range runs {
		if head == nil || headWorse(head, r) {
			head = r
		}
	}
	return head
}

// headWorse reports whether a is a worse head than b (so b should win). A finished-clean run beats a
// non-clean one; otherwise the newer run beats the older, breaking a same-second tie by creation time.
func headWorse(a, b *scan.Run) bool {
	aClean, bClean := stateOf(a) == stateDone, stateOf(b) == stateDone
	if aClean != bClean {
		return !aClean
	}
	ta, tb := activityTime(a), activityTime(b)
	if ta != tb {
		return ta < tb
	}
	// Same activity second (two runs that finished within the same second — e.g. back-to-back failing
	// scans): break the tie by creation time (sub-second) so the genuinely-latest run heads the group
	// deterministically, not whichever the DB happened to return first.
	return createdBefore(a, b)
}

// createdBefore reports whether a was persisted before b, by CreatedAt (sub-second). A run with no
// creation timestamp sorts earliest, so a persisted run wins the head over one not yet stored.
func createdBefore(a, b *scan.Run) bool {
	at, bt := a.GetCreatedAt(), b.GetCreatedAt()
	if at == nil || bt == nil {
		return bt != nil // a (missing) is "earliest"; if b has a timestamp, a precedes b
	}
	return at.AsTime().Before(bt.AsTime())
}

// coalesceClass returns the coalescing class of a run, or "" if the run must never be collapsed.
// Runs collapse only against others of the SAME class within a series, so a series keeps at most one
// head PER class — a successful head and the latest failed head coexist as separate visible rows.
// That is deliberate: it surfaces a "was working, now failing" regression instead of burying the
// fresh failure under a stale success (or vice-versa). The classes:
//
//   - "done": a clean completion. Repeats collapse to the newest done (the existing behaviour).
//   - "failed-empty": a terminal failure that produced NO host — pure noise (a misconfigured cron, a
//     privilege error, an unresolved target set) whose repeats collapse to the LATEST failure, whose
//     FormerRuns count then reads as "failed N times". The count IS the diagnostic; the runs stay in
//     `scan history`/`scan diff`.
//
// Everything else is non-coalescible ("" — kept as its own visible row): a failure that DID find
// hosts (partial surface is unique data, worth seeing at a glance), an interrupted run (each is
// individually resumable), and a running/queued run (still in flight).
func coalesceClass(r *scan.Run) string {
	switch stateOf(r) {
	case stateDone:
		return "done"
	case stateFailed:
		if runFoundHosts(r) {
			return "" // a partial failure carries unique surface — never fold it away
		}
		return "failed-empty"
	default:
		return "" // interrupted, running, created — never coalesced
	}
}

// runFoundHosts reports whether a run produced any host observation. It prefers the loaded host
// subtree but falls back to the persisted host stats, because the cleanup/auto-supersede path loads
// runs WITHOUT their hosts (loadRuns preloads Stats, not Hosts) — so the streamed-run host count that
// consume stamps into Stats.Hosts is the authoritative "did this failure find anything" signal there.
func runFoundHosts(r *scan.Run) bool {
	if len(r.GetHosts()) > 0 {
		return true
	}
	return r.GetStats().GetHosts().GetTotal() > 0
}

// CleanupPlan is the set of field mutations a cleanup pass computes over the whole run set. The runs
// it references are mutated in place (SupersededBy / FormerRuns set) and ready to persist: Heads and
// Tombstoned via Upsert, Prunable via Delete. It carries no DB or RPC dependency.
type CleanupPlan struct {
	Heads      []*scan.Run // survivors whose FormerRuns was (re)computed
	Tombstoned []*scan.Run // runs newly pointed at their head via SupersededBy
	Prunable   []*scan.Run // tombstoned runs whose output is byte-identical to the head (hard-deletable)
}

// Empty reports whether the plan collapses nothing.
func (p CleanupPlan) Empty() bool { return len(p.Tombstoned) == 0 && len(p.Prunable) == 0 }

// ComputeCleanup groups every run into its series-and-outcome-class and collapses each multi-run
// group onto a single head, mutating the affected runs in place and returning the plan. It is
// idempotent: a group already collapsed to one visible head yields no new tombstones, so re-running
// is a no-op.
//
// Only currently-visible, coalescible runs are candidates to become or absorb a head (see
// coalesceClass): a live scan, an interrupted run, and a failure that found hosts are left untouched
// as their own rows; already-tombstoned runs are re-homed only if their head is itself absorbed
// (chains are flattened to one level). FormerRuns on each head is recomputed from the full set so it
// always equals the number of runs it supersedes.
func ComputeCleanup(all []*scan.Run) CleanupPlan {
	var plan CleanupPlan

	// Group the visible, coalescible runs by series definition AND outcome class, so a series
	// collapses to one head per class (a success head and the latest failure head coexist) rather than
	// one head overall. Non-coalescible runs (running, interrupted, a partial failure) get class "" and
	// are skipped entirely — never grouped, never tombstoned.
	groups := map[string][]*scan.Run{}
	var order []string
	for _, r := range all {
		if IsSuperseded(r) {
			continue
		}
		class := coalesceClass(r)
		if class == "" {
			continue
		}
		k := seriesKey(r) + "\x00" + class
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], r)
	}

	// Tombstone every non-head run of each multi-run series onto its head.
	heads := map[string]*scan.Run{} // head Id -> head, for FormerRuns recount and chain flattening
	for _, k := range order {
		group := groups[k]
		if len(group) < 2 {
			continue
		}
		head := pickHead(group)
		heads[head.GetId()] = head
		for _, r := range group {
			if r == head {
				continue
			}
			r.SupersededBy = head.GetId()
			plan.Tombstoned = append(plan.Tombstoned, r)
		}
	}

	// Flatten chains: any previously-tombstoned run whose head is now itself tombstoned re-points to
	// the ultimate surviving head.
	for _, r := range all {
		if !IsSuperseded(r) {
			continue
		}
		if final := resolveHead(r, all); final != "" && final != r.GetSupersededBy() {
			r.SupersededBy = final
			plan.Tombstoned = append(plan.Tombstoned, r)
		}
	}

	// Recompute FormerRuns on each surviving head as the count of runs it now supersedes.
	counts := map[string]int32{}
	for _, r := range all {
		if IsSuperseded(r) {
			counts[r.GetSupersededBy()]++
		}
	}
	for id, head := range heads {
		// Never lower the count: a hard --prune deletes the tombstoned rows it absorbed, so a later
		// recount over surviving rows would otherwise drop that trace. Keeping FormerRuns monotonic
		// preserves "former runs: N" as the durable record of everything the head ever absorbed.
		n := counts[id]
		if prior := head.GetFormerRuns(); prior > n {
			n = prior
		}
		if head.GetFormerRuns() != n {
			head.FormerRuns = n
		}
		plan.Heads = append(plan.Heads, head)
	}

	// The hard-prunable subset: a tombstoned run whose output is byte-identical to its head carries
	// no unique information and may be deleted rather than kept.
	byID := map[string]*scan.Run{}
	for _, r := range all {
		byID[r.GetId()] = r
	}
	for _, r := range plan.Tombstoned {
		head := byID[r.GetSupersededBy()]
		if head != nil && r.GetRawXML() != "" && r.GetRawXML() == head.GetRawXML() {
			plan.Prunable = append(plan.Prunable, r)
		}
	}

	return plan
}

// resolveHead follows a tombstoned run's SupersededBy chain to the ultimate non-superseded head Id,
// guarding against cycles. Returns "" if the chain cannot be resolved within the set.
func resolveHead(r *scan.Run, all []*scan.Run) string {
	byID := map[string]*scan.Run{}
	for _, x := range all {
		byID[x.GetId()] = x
	}
	seen := map[string]bool{}
	cur := r
	for cur != nil && IsSuperseded(cur) {
		next := cur.GetSupersededBy()
		if seen[next] {
			return "" // cycle
		}
		seen[next] = true
		cur = byID[next]
	}
	if cur == nil {
		return ""
	}
	return cur.GetId()
}

// SupersedeFor computes a cleanup plan limited to the series containing runID — the auto-collapse a
// server runs when a new scan of the same definition finishes, so `scan list` self-collapses without
// a manual `scan cleanup`. It restricts the run set to that one series and reuses ComputeCleanup, so
// the collapse stays within outcome classes: a finished clean run heads the success line, a resultless
// failure coalesces with earlier resultless failures of the same definition (latest wins, with a
// count), and the two heads coexist. A still-running or interrupted sibling, and a failure that found
// hosts, are left alone. Returns an empty plan when the run is unknown or its series has nothing to
// collapse.
func SupersedeFor(all []*scan.Run, runID string) CleanupPlan {
	var target *scan.Run
	for _, r := range all {
		if r.GetId() == runID {
			target = r
			break
		}
	}
	if target == nil {
		return CleanupPlan{}
	}
	key := seriesKey(target)
	var series []*scan.Run
	for _, r := range all {
		if seriesKey(r) == key {
			series = append(series, r)
		}
	}
	return ComputeCleanup(series)
}

// SeriesOf returns a head run together with every run tombstoned under it (directly), ordered
// head-first then by recency — the browse set behind `scan history`.
func SeriesOf(all []*scan.Run, head *scan.Run) []*scan.Run {
	series := []*scan.Run{head}
	for _, r := range all {
		if r.GetSupersededBy() == head.GetId() {
			series = append(series, r)
		}
	}
	SortRuns(series)
	return series
}

// HeadOf resolves the surviving head for any run: the run itself if visible, else the run its
// SupersededBy points to (following one level). Returns the input when nothing better is found.
func HeadOf(all []*scan.Run, r *scan.Run) *scan.Run {
	if !IsSuperseded(r) {
		return r
	}
	for _, x := range all {
		if x.GetId() == r.GetSupersededBy() {
			return x
		}
	}
	return r
}
