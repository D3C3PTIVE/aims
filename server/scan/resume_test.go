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
	"context"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/d3c3ptive/aims/scan"
	scanpb "github.com/d3c3ptive/aims/scan/pb"
	scanrpcpb "github.com/d3c3ptive/aims/scan/pb/rpc"
)

// interruptedRun builds a stored-shape run in the interrupted state (terminal, resumable) carrying
// the given structured targets and their statuses.
func interruptedRun(args string, targets ...*scanpb.Target) *scanpb.Run {
	return &scanpb.Run{
		Scanner: "nmap", Args: args, Targets: targets,
		Stats: &scanpb.Stats{Finished: &scanpb.Finished{Time: 1, Exit: scan.ExitInterrupted}},
	}
}

// TestReforgeResumeTargetDiff: an interrupted run with one done and one unreached target reforges
// the command over ONLY the unreached target — the target-diff at the heart of resume.
func TestReforgeResumeTargetDiff(t *testing.T) {
	run := interruptedRun("-sT -p1-1000",
		&scanpb.Target{Id: "a", Address: "10.0.0.1", Status: scan.TargetDone},
		&scanpb.Target{Id: "b", Address: "10.0.0.2"}, // never reached
	)

	req, err := reforgeResume(run)
	if err != nil {
		t.Fatalf("reforgeResume: %v", err)
	}
	if req.GetScanner() != "nmap" {
		t.Errorf("scanner = %q, want nmap", req.GetScanner())
	}
	if got := req.GetArgs(); len(got) != 2 || got[0] != "-sT" || got[1] != "-p1-1000" {
		t.Errorf("args = %v, want [-sT -p1-1000]", got)
	}
	specs := scan.TargetSpecs(req.GetTargets())
	if len(specs) != 1 || specs[0] != "10.0.0.2" {
		t.Errorf("resume targets = %v, want [10.0.0.2] (only the unreached one)", specs)
	}
}

// TestReforgeResumeRawArgsWholeRerun: a run whose targets rode inside Args (no structured Targets)
// has no per-target record, so resume re-runs the whole command — Args intact, no appended targets.
func TestReforgeResumeRawArgsWholeRerun(t *testing.T) {
	run := interruptedRun("-sT 10.0.0.0/24") // targets inside Args, none structured

	req, err := reforgeResume(run)
	if err != nil {
		t.Fatalf("reforgeResume: %v", err)
	}
	if len(req.GetTargets()) != 0 {
		t.Errorf("structured targets = %d, want 0 (raw-args scan re-runs whole)", len(req.GetTargets()))
	}
	if got := req.GetArgs(); len(got) != 2 || got[1] != "10.0.0.0/24" {
		t.Errorf("args = %v, want the original command incl. its target", got)
	}
}

// TestReforgeResumeGuards: a done or running run is not resumable, and an interrupted run whose every
// target completed has nothing to resume — each is an error, not a wasted re-scan.
func TestReforgeResumeGuards(t *testing.T) {
	done := &scanpb.Run{
		Id: "d", Scanner: "nmap", Args: "-sT",
		Stats: &scanpb.Stats{Finished: &scanpb.Finished{Time: 1, Exit: "success"}},
	}
	if _, err := reforgeResume(done); err == nil {
		t.Error("a clean done run must not be resumable")
	}

	running := &scanpb.Run{
		Id: "r", Scanner: "nmap", Args: "-sT",
		UpdatedAt: timestamppb.New(time.Now()),
		Progress:  []*scanpb.TaskProgress{{Task: "SYN Stealth Scan", Percent: 20}},
	}
	if _, err := reforgeResume(running); err == nil {
		t.Error("a running run must be stopped before resuming")
	}

	allDone := interruptedRun("-sT",
		&scanpb.Target{Id: "a", Address: "10.0.0.1", Status: scan.TargetDone},
	)
	if _, err := reforgeResume(allDone); err == nil {
		t.Error("an interrupted run with every target done has nothing to resume")
	}
}

// TestConsumeResumeStampsChainAndTombstonesParent drives consume with a resumedFrom set (as a resume
// does) and asserts the resulting run links to the parent (ResumedFrom) and tombstones it under the
// child — so `scan history` shows the parent→child chain and `scan list` shows only the resumed head.
func TestConsumeResumeStampsChainAndTombstonesParent(t *testing.T) {
	s, _, ctx := newTestServer(t)

	// A stored, interrupted parent run.
	parent := interruptedRun("-sT -p1-1000", &scanpb.Target{Id: "pt", Address: "10.0.0.2"})
	parent.Id = "parent"
	if _, err := s.persistRun(ctx, parent, nil); err != nil {
		t.Fatalf("persist parent: %v", err)
	}

	// The resumed job (resumedFrom = parent) completes cleanly over the remaining target.
	jobCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	job := newScanJob(&scanrpcpb.RunScanRequest{
		Scanner: "nmap", Args: []string{"-sT", "-p1-1000"},
		Targets: []*scanpb.Target{{Id: "ct", Address: "10.0.0.2"}},
	}, "child", jobCtx, cancel, time.Now().Unix())
	job.resumedFrom = "parent"
	s.addJob(job)

	results, progress := feed(upHost("10.0.0.2"), &scanpb.TaskProgress{Task: "SYN Stealth Scan", Percent: 100})
	s.consume(job, results, progress, errChan(nil))

	child, err := s.readRun(ctx, "child")
	if err != nil || child == nil {
		t.Fatalf("readRun child: %v", err)
	}
	if child.GetResumedFrom() != "parent" {
		t.Errorf("child ResumedFrom = %q, want parent", child.GetResumedFrom())
	}

	// The parent is tombstoned under the child (resume chain is a series; child is the head).
	got, err := s.readRun(ctx, "parent")
	if err != nil || got == nil {
		t.Fatalf("readRun parent: %v", err)
	}
	if got.GetSupersededBy() != "child" {
		t.Errorf("parent SupersededBy = %q, want child (resume tombstones the parent)", got.GetSupersededBy())
	}
}
