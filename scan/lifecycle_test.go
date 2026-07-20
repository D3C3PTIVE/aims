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

	scan "github.com/d3c3ptive/aims/scan/pb"
)

// doneRun builds a finished-clean run at a given completion time (for recency/quality ranking).
func mkDone(id, scanner, args string, finished int64) *scan.Run {
	return &scan.Run{
		Id:      id,
		Scanner: scanner,
		Args:    args,
		Stats:   &scan.Stats{Finished: &scan.Finished{Time: finished, Exit: "success"}},
	}
}

// failedRun builds a finished-with-error run.
func mkFailed(id, scanner, args string, finished int64) *scan.Run {
	return &scan.Run{
		Id:      id,
		Scanner: scanner,
		Args:    args,
		Stats:   &scan.Stats{Finished: &scan.Finished{Time: finished, Exit: "error", ErrorMsg: "boom"}},
	}
}

// TestSeriesKeyIgnoresArgOrder asserts cosmetically-reordered arguments collapse into one series,
// while a different scanner or a different flag set does not.
func TestSeriesKeyIgnoresArgOrder(t *testing.T) {
	a := &scan.Run{Scanner: "nmap", Args: "-sT -p1-1000"}
	b := &scan.Run{Scanner: "nmap", Args: "-p1-1000 -sT"}
	if seriesKey(a) != seriesKey(b) {
		t.Errorf("reordered args should share a series key:\n a=%q\n b=%q", seriesKey(a), seriesKey(b))
	}

	other := &scan.Run{Scanner: "nmap", Args: "-sT -p1-2000"}
	if seriesKey(a) == seriesKey(other) {
		t.Error("a different port range must not share the series key")
	}
	masscan := &scan.Run{Scanner: "masscan", Args: "-sT -p1-1000"}
	if seriesKey(a) == seriesKey(masscan) {
		t.Error("a different scanner must not share the series key")
	}
}

// TestSeriesKeyPrefersProfile asserts a named profile stands in for the argument string.
func TestSeriesKeyPrefersProfile(t *testing.T) {
	a := &scan.Run{Scanner: "nmap", ProfileName: "quick", Args: "-sT -F"}
	b := &scan.Run{Scanner: "nmap", ProfileName: "quick", Args: "-F -sT --reason"} // different args, same profile
	if seriesKey(a) != seriesKey(b) {
		t.Error("runs of the same named profile should share a series key regardless of args")
	}
}

// TestPickHeadNeverDemotesDone guards the core invariant: a later failed/interrupted run must not
// become the head over an earlier clean done run.
func TestPickHeadNeverDemotesDone(t *testing.T) {
	done := mkDone("done", "nmap", "-sT", 100)
	laterFailed := mkFailed("failed", "nmap", "-sT", 200) // newer, but failed
	head := pickHead([]*scan.Run{done, laterFailed})
	if head.GetId() != "done" {
		t.Errorf("head = %q, want the clean done run (failed must not supersede done)", head.GetId())
	}

	// Among two clean done runs, the more recent wins.
	older := mkDone("older", "nmap", "-sT", 100)
	newer := mkDone("newer", "nmap", "-sT", 300)
	if pickHead([]*scan.Run{older, newer}).GetId() != "newer" {
		t.Error("among equally-clean runs the most recent should be head")
	}
}

// TestComputeCleanupCollapsesAndIsIdempotent runs three instances of one definition through cleanup:
// two are tombstoned onto the newest done head, FormerRuns reflects the count, the tombstoned runs
// drop out of the visible view but remain reachable as the series, and a second pass changes nothing.
func TestComputeCleanupCollapsesAndIsIdempotent(t *testing.T) {
	r1 := mkDone("r1", "nmap", "-sT localhost", 100)
	r2 := mkDone("r2", "nmap", "localhost -sT", 200) // reordered args -> same series
	r3 := mkDone("r3", "nmap", "-sT localhost", 300) // newest -> head
	// A run of a different definition must be left alone.
	other := mkDone("other", "nmap", "-sU localhost", 150)
	all := []*scan.Run{r1, r2, r3, other}

	plan := ComputeCleanup(all)
	if plan.Empty() {
		t.Fatal("expected a non-empty cleanup plan")
	}
	if r3.GetSupersededBy() != "" {
		t.Errorf("newest done run should be the head, not superseded (got %q)", r3.GetSupersededBy())
	}
	if r1.GetSupersededBy() != "r3" || r2.GetSupersededBy() != "r3" {
		t.Errorf("r1/r2 should be tombstoned onto r3, got %q / %q", r1.GetSupersededBy(), r2.GetSupersededBy())
	}
	if other.GetSupersededBy() != "" {
		t.Error("a distinct definition must not be collapsed")
	}
	if r3.GetFormerRuns() != 2 {
		t.Errorf("head FormerRuns = %d, want 2", r3.GetFormerRuns())
	}

	// Visible view hides the tombstones; the series browse still reaches them.
	visible := VisibleRuns(all)
	if len(visible) != 2 { // r3 head + other
		t.Errorf("visible runs = %d, want 2 (head + distinct definition)", len(visible))
	}
	series := SeriesOf(all, r3)
	if len(series) != 3 {
		t.Errorf("series of r3 = %d runs, want 3 (head + 2 tombstoned)", len(series))
	}

	// Idempotence: a second pass over the now-collapsed set proposes no new tombstones.
	plan2 := ComputeCleanup(all)
	if len(plan2.Tombstoned) != 0 {
		t.Errorf("second cleanup pass should be a no-op, got %d new tombstones", len(plan2.Tombstoned))
	}
}

// TestComputeCleanupLeavesRunningAlone asserts a live run in a series is never tombstoned.
func TestComputeCleanupLeavesRunningAlone(t *testing.T) {
	done := mkDone("done", "nmap", "-sT localhost", 100)
	running := &scan.Run{Id: "running", Scanner: "nmap", Args: "-sT localhost", Begin: []*scan.ScanTask{{Task: "SYN"}}}
	all := []*scan.Run{done, running}

	ComputeCleanup(all)
	if running.GetSupersededBy() != "" {
		t.Error("a running scan must not be tombstoned")
	}
	if done.GetSupersededBy() != "" {
		t.Error("the lone finished run has no sibling to collapse against a running one")
	}
}

// TestPrunableIsByteIdenticalOnly asserts only a tombstoned run whose RawXML equals the head's is
// hard-prunable; a same-definition run with different output is tombstoned but never pruned.
func TestPrunableIsByteIdenticalOnly(t *testing.T) {
	head := mkDone("head", "nmap", "-sT localhost", 300)
	head.RawXML = "<nmaprun>IDENTICAL</nmaprun>"
	dupe := mkDone("dupe", "nmap", "-sT localhost", 200)
	dupe.RawXML = "<nmaprun>IDENTICAL</nmaprun>" // byte-identical re-import
	drift := mkDone("drift", "nmap", "-sT localhost", 100)
	drift.RawXML = "<nmaprun>DIFFERENT</nmaprun>" // same definition, drifted output
	all := []*scan.Run{head, dupe, drift}

	plan := ComputeCleanup(all)
	if len(plan.Prunable) != 1 || plan.Prunable[0].GetId() != "dupe" {
		t.Fatalf("prunable = %v, want exactly [dupe] (byte-identical output only)", ids(plan.Prunable))
	}
	// Both are still tombstoned; only one is prunable.
	if dupe.GetSupersededBy() != "head" || drift.GetSupersededBy() != "head" {
		t.Error("both siblings should be tombstoned onto the head")
	}
}

func ids(runs []*scan.Run) []string {
	out := make([]string, len(runs))
	for i, r := range runs {
		out[i] = r.GetId()
	}
	return out
}
