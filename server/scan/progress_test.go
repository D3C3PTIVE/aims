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

	scanpb "github.com/d3c3ptive/aims/scan/pb"
)

// TestPersistRunUpdatesProgress is the persistence contract the cross-process live progress view
// depends on (SCAN.md Part C): a running scan re-snapshots the SAME TaskProgress row (stable Id,
// keyed by task name) with a climbing Percent on each heartbeat, and persistRun must UPDATE that row
// in place — one row, latest Percent — not duplicate it per snapshot nor keep the stale value. If
// this fails, the DB-attach progress bar would either stall at the first percent or fan out a row per
// tick.
func TestPersistRunUpdatesProgress(t *testing.T) {
	s, gdb, ctx := newTestServer(t)

	run := &scanpb.Run{
		Id:       "prog-1",
		Scanner:  "nmap",
		Args:     "-sT -p1-1000",
		Progress: []*scanpb.TaskProgress{{Id: "p-1", Task: "SYN Stealth Scan", Percent: 10}},
	}
	if _, err := s.persistRun(ctx, run); err != nil {
		t.Fatalf("persist snapshot 1: %v", err)
	}

	// A later heartbeat re-persists the same run with the same progress row advanced to 60%.
	run.Progress[0].Percent = 60
	if _, err := s.persistRun(ctx, run); err != nil {
		t.Fatalf("persist snapshot 2: %v", err)
	}

	// Stable-Id progress must upsert, not duplicate: one row, one join link.
	if n := countRows(t, gdb, "task_progresses"); n != 1 {
		t.Errorf("task_progresses = %d, want 1 (a stable-Id progress row must not duplicate per heartbeat)", n)
	}
	if n := countRows(t, gdb, "run_task_progresses"); n != 1 {
		t.Errorf("run_task_progresses = %d, want 1", n)
	}

	// And it must carry the LATEST percent, read back through the run.
	got, err := s.readRun(ctx, "prog-1")
	if err != nil {
		t.Fatalf("readRun: %v", err)
	}
	if got == nil {
		t.Fatal("readRun returned nil")
	}
	if len(got.GetProgress()) != 1 {
		t.Fatalf("progress rows = %d, want 1", len(got.GetProgress()))
	}
	if p := got.GetProgress()[0].GetPercent(); p != 60 {
		t.Errorf("persisted percent = %.0f, want 60 (latest heartbeat value)", p)
	}
}
