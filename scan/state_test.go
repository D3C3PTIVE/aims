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
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	scan "github.com/d3c3ptive/aims/scan/pb"
)

// TestRunPercent verifies the running-scan percent reflects the CURRENT nmap task, not the max across
// tasks. nmap runs each task (SYN Stealth Scan, Service scan, …) 0→100% then resets, so maxing would
// latch at 100% once the first task finished and mislabel a scan still early in a later task as
// "● 100% while running" — the reported bug.
func TestRunPercent(t *testing.T) {
	// SYN scan finished (100%, earlier Time); Service scan is the current task at 18.5% (later Time).
	r := &scan.Run{Progress: []*scan.TaskProgress{
		{Task: "SYN Stealth Scan", Percent: 100, Time: 100},
		{Task: "Service scan", Percent: 18.5, Time: 200},
	}}
	if got := runPercent(r); got < 18.4 || got > 18.6 {
		t.Errorf("runPercent = %v, want ~18.5 (the current task, not the maxed 100)", got)
	}
	// Order independence: run.Progress is rebuilt from a map, so the current task may appear first.
	r2 := &scan.Run{Progress: []*scan.TaskProgress{
		{Task: "Service scan", Percent: 18.5, Time: 200},
		{Task: "SYN Stealth Scan", Percent: 100, Time: 100},
	}}
	if got := runPercent(r2); got < 18.4 || got > 18.6 {
		t.Errorf("runPercent (reordered) = %v, want ~18.5", got)
	}
	// No progress frames → 0, not a panic (nil-safe getters).
	if got := runPercent(&scan.Run{}); got != 0 {
		t.Errorf("runPercent(empty) = %v, want 0", got)
	}
}

// TestFmtTimeLocal guards the detail-view timezone consistency fix: fmtTime must render in the
// operator's local zone (like finishedStr/StartStr), not the UTC that protobuf's AsTime() returns —
// a UTC "Updated" next to a local "Finished" read as a phantom timezone gap.
func TestFmtTimeLocal(t *testing.T) {
	ts := timestamppb.New(time.Date(2026, 7, 21, 19, 9, 0, 0, time.UTC))
	if got, want := fmtTime(ts), ts.AsTime().Local().Format("2006-01-02 15:04"); got != want {
		t.Errorf("fmtTime = %q, want the local-zone rendering %q (not UTC)", got, want)
	}
	if fmtTime(nil) != "" {
		t.Error("fmtTime(nil) must be empty")
	}
}

// TestStateOfHeartbeat covers the run-state axis, including the heartbeat-derived distinction a
// killed scan needs: a non-final run with a FRESH UpdatedAt is running; the same run once its
// UpdatedAt has gone stale (the owning process died) is interrupted, not "queued forever".
func TestStateOfHeartbeat(t *testing.T) {
	fresh := timestamppb.New(time.Now())
	stale := timestamppb.New(time.Now().Add(-2 * runStaleAfter))
	done := &scan.Stats{Finished: &scan.Finished{Time: time.Now().Unix(), Exit: "success"}}
	failed := &scan.Stats{Finished: &scan.Finished{Time: time.Now().Unix(), Exit: "error", ErrorMsg: "boom"}}

	cases := []struct {
		name string
		run  *scan.Run
		want runState
	}{
		{"finished-clean", &scan.Run{Stats: done, UpdatedAt: stale}, stateDone},
		{"finished-error", &scan.Run{Stats: failed, UpdatedAt: fresh}, stateFailed},
		{"live-fresh-heartbeat", &scan.Run{UpdatedAt: fresh}, stateRunning},
		{"orphan-stale-heartbeat", &scan.Run{UpdatedAt: stale}, stateInterrupted},
		{"never-persisted", &scan.Run{}, stateCreated},
	}
	for _, c := range cases {
		if got := stateOf(c.run); got != c.want {
			t.Errorf("%s: stateOf = %d, want %d", c.name, got, c.want)
		}
	}
}

// TestFinishedBeatsStaleHeartbeat asserts Finished stats are authoritative: a completed run stays
// done even if its heartbeat is ancient, and never reports IsRunning.
func TestFinishedBeatsStaleHeartbeat(t *testing.T) {
	r := &scan.Run{
		Stats:     &scan.Stats{Finished: &scan.Finished{Time: time.Now().Unix(), Exit: "success"}},
		UpdatedAt: timestamppb.New(time.Now().Add(-time.Hour)),
	}
	if got := stateOf(r); got != stateDone {
		t.Errorf("stateOf = %d, want stateDone (Finished is authoritative)", got)
	}
	if IsRunning(r) {
		t.Error("a finished run must not report IsRunning")
	}
}

// TestInterruptedNotRunning guards the `scan rm` path: a stale orphan is interrupted, so IsRunning
// is false and destructive ops are no longer blocked by a stuck run.
func TestInterruptedNotRunning(t *testing.T) {
	orphan := &scan.Run{UpdatedAt: timestamppb.New(time.Now().Add(-2 * runStaleAfter))}
	if stateOf(orphan) != stateInterrupted {
		t.Fatalf("stale orphan should be interrupted")
	}
	if IsRunning(orphan) {
		t.Error("an interrupted run must not report IsRunning (it must be removable)")
	}
}
