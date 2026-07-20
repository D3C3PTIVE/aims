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
	"testing"

	scanpb "github.com/d3c3ptive/aims/scan/pb"
	scanrpcpb "github.com/d3c3ptive/aims/scan/pb/rpc"
)

// TestJobsSeesCrossProcessRun asserts Jobs surfaces a scan visible only through the shared DB — as a
// scan running in another aims process would be, since the all-in-one binary's job registry is
// per-process — reporting its args and structured targets, and that re-persisting the same running
// snapshot on each heartbeat does NOT duplicate the target row or its join link.
func TestJobsSeesCrossProcessRun(t *testing.T) {
	s, gdb, ctx := newTestServer(t)

	// A running run as consume() snapshots it: no Finished stats (so the fresh heartbeat reads as
	// running), with args and one structured target carrying a stable Id.
	run := &scanpb.Run{
		Id:      "job-1",
		Scanner: "nmap",
		Args:    "-sT -p1-100",
		Targets: []*scanpb.Target{{Id: "t-1", Address: "10.0.0.5"}},
	}
	if _, err := s.persistRun(ctx, run); err != nil {
		t.Fatalf("persist snapshot 1: %v", err)
	}
	if _, err := s.persistRun(ctx, run); err != nil { // a second heartbeat
		t.Fatalf("persist snapshot 2: %v", err)
	}

	// Idempotent target persistence: two heartbeats must not duplicate the target or its run link.
	if n := countRows(t, gdb, "targets"); n != 1 {
		t.Errorf("targets = %d, want 1 (a stable-Id target must not duplicate per heartbeat)", n)
	}
	if n := countRows(t, gdb, "run_targets"); n != 1 {
		t.Errorf("run_targets = %d, want 1", n)
	}

	// Jobs surfaces the DB-only running run with its definition.
	res, err := s.Jobs(ctx, &scanrpcpb.JobsRequest{})
	if err != nil {
		t.Fatalf("jobs: %v", err)
	}
	var job *scanrpcpb.ScanJob
	for _, j := range res.GetJobs() {
		if j.GetId() == "job-1" {
			job = j
		}
	}
	if job == nil {
		t.Fatal("Jobs did not surface the cross-process running run")
	}
	if job.GetScanner() != "nmap" {
		t.Errorf("job scanner = %q, want nmap", job.GetScanner())
	}
	if got := strings.Join(job.GetArgs(), " "); got != "-sT -p1-100" {
		t.Errorf("job args = %q, want the run's args", got)
	}
	if len(job.GetTargets()) != 1 || job.GetTargets()[0].GetAddress() != "10.0.0.5" {
		t.Errorf("job targets = %v, want the one structured target", job.GetTargets())
	}
}

// TestJobsExcludesFinishedRun asserts a finished run is never reported as a running job.
func TestJobsExcludesFinishedRun(t *testing.T) {
	s, _, ctx := newTestServer(t)

	done := &scanpb.Run{
		Id:      "done-1",
		Scanner: "nmap",
		Stats:   &scanpb.Stats{Finished: &scanpb.Finished{Time: 100, Exit: "success"}},
	}
	if _, err := s.persistRun(ctx, done); err != nil {
		t.Fatalf("persist: %v", err)
	}

	res, err := s.Jobs(ctx, &scanrpcpb.JobsRequest{})
	if err != nil {
		t.Fatalf("jobs: %v", err)
	}
	for _, j := range res.GetJobs() {
		if j.GetId() == "done-1" {
			t.Error("a finished run must not be reported as a running job")
		}
	}
}
