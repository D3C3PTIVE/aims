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

	hostpb "github.com/d3c3ptive/aims/host/pb"
	network "github.com/d3c3ptive/aims/network/pb"
	"github.com/d3c3ptive/aims/scan"
	scanpb "github.com/d3c3ptive/aims/scan/pb"
	scanrpcpb "github.com/d3c3ptive/aims/scan/pb/rpc"
)

// feed builds the result/progress channels consume drains, pre-loaded with one host result and one
// progress frame, then closed so consume runs to its final persist.
func feed(host *hostpb.Host, prog *scanpb.TaskProgress) (<-chan *scanpb.Result, <-chan *scanpb.TaskProgress) {
	results := make(chan *scanpb.Result, 1)
	progress := make(chan *scanpb.TaskProgress, 1)
	results <- &scanpb.Result{Host: host}
	progress <- prog
	close(results)
	close(progress)
	return results, progress
}

func upHost(addr string) *hostpb.Host {
	return &hostpb.Host{
		Addresses: []*network.Address{{Addr: addr}},
		Status:    &hostpb.Status{State: "up"},
	}
}

// TestConsumeInterruptedStampsInterrupted asserts the interrupt-aware final persist: when the job's
// context is cancelled (a Stop) before the scan drains, consume stamps the partial run as
// interrupted (terminal, resumable) — not a false "done" — keeps the hosts and progress it gathered,
// and does NOT collapse the run's series, so it stays visible for a later resume even when a
// fuller-history sibling of the same definition exists.
func TestConsumeInterruptedStampsInterrupted(t *testing.T) {
	s, _, ctx := newTestServer(t)

	// A cleanly-finished sibling of the same definition (scanner + args + target).
	sib := &scanpb.Run{
		Id: "sib", Scanner: "nmap", Args: "-sT -p1-100",
		Targets: []*scanpb.Target{{Id: "st", Address: "10.0.0.9"}},
		Stats:   &scanpb.Stats{Finished: &scanpb.Finished{Time: 1000, Exit: "success"}},
	}
	if _, err := s.persistRun(ctx, sib); err != nil {
		t.Fatalf("persist sibling: %v", err)
	}

	jobCtx, cancel := context.WithCancel(context.Background())
	cancel() // simulate a Stop before the scan drained
	job := newScanJob(&scanrpcpb.RunScanRequest{
		Scanner: "nmap",
		Args:    []string{"-sT", "-p1-100"},
		Targets: []*scanpb.Target{{Id: "jt", Address: "10.0.0.9"}},
	}, "job-int", jobCtx, cancel, time.Now().Unix())
	s.addJob(job)

	results, progress := feed(upHost("10.0.0.9"), &scanpb.TaskProgress{Task: "SYN Stealth Scan", Percent: 45})
	s.consume(job, results, progress)

	run, err := s.readRun(ctx, "job-int")
	if err != nil || run == nil {
		t.Fatalf("readRun: %v (run=%v)", err, run)
	}
	if exit := run.GetStats().GetFinished().GetExit(); exit != scan.ExitInterrupted {
		t.Errorf("exit = %q, want %q", exit, scan.ExitInterrupted)
	}
	if scan.IsRunning(run) {
		t.Error("an interrupted run must not read as running")
	}
	if len(run.GetHosts()) != 1 {
		t.Errorf("hosts = %d, want 1 (partial results kept)", len(run.GetHosts()))
	}
	if len(run.GetProgress()) != 1 || run.GetProgress()[0].GetPercent() != 45 {
		t.Errorf("progress = %v, want one row at 45%%", run.GetProgress())
	}
	if run.GetSupersededBy() != "" {
		t.Errorf("interrupted run tombstoned (SupersededBy=%q); it must stay visible for resume", run.GetSupersededBy())
	}

	// The interrupted run must not have collapsed its series: the sibling stays a visible head too.
	got, err := s.readRun(ctx, "sib")
	if err != nil || got == nil {
		t.Fatalf("readRun sibling: %v", err)
	}
	if got.GetSupersededBy() != "" {
		t.Errorf("sibling tombstoned by an interrupted run (SupersededBy=%q); must not happen", got.GetSupersededBy())
	}
}

// TestConsumeCleanRunCompletesAndSupersedes is the counterpart: a job that drains without a cancel
// stamps a clean "success" (reads as done) AND collapses its series — the older completed sibling is
// tombstoned under it — proving auto-supersede runs on a clean completion but is skipped on an
// interruption.
func TestConsumeCleanRunCompletesAndSupersedes(t *testing.T) {
	s, _, ctx := newTestServer(t)

	sib := &scanpb.Run{
		Id: "sib", Scanner: "nmap", Args: "-sT -p1-100",
		Targets: []*scanpb.Target{{Id: "st", Address: "10.0.0.9"}},
		Stats:   &scanpb.Stats{Finished: &scanpb.Finished{Time: 1000, Exit: "success"}},
	}
	if _, err := s.persistRun(ctx, sib); err != nil {
		t.Fatalf("persist sibling: %v", err)
	}

	jobCtx, cancel := context.WithCancel(context.Background())
	defer cancel() // NOT cancelled before consume: a clean completion
	job := newScanJob(&scanrpcpb.RunScanRequest{
		Scanner: "nmap",
		Args:    []string{"-sT", "-p1-100"},
		Targets: []*scanpb.Target{{Id: "jt", Address: "10.0.0.9"}},
	}, "job-ok", jobCtx, cancel, time.Now().Unix())
	s.addJob(job)

	results, progress := feed(upHost("10.0.0.9"), &scanpb.TaskProgress{Task: "SYN Stealth Scan", Percent: 100})
	s.consume(job, results, progress)

	run, err := s.readRun(ctx, "job-ok")
	if err != nil || run == nil {
		t.Fatalf("readRun: %v", err)
	}
	if exit := run.GetStats().GetFinished().GetExit(); exit != "success" {
		t.Errorf("exit = %q, want success", exit)
	}
	if scan.IsRunning(run) {
		t.Error("a completed run must not read as running")
	}
	if run.GetFormerRuns() != 1 {
		t.Errorf("FormerRuns = %d, want 1 (the clean run superseded its sibling)", run.GetFormerRuns())
	}

	// The older sibling was collapsed under the fresh head.
	got, err := s.readRun(ctx, "sib")
	if err != nil || got == nil {
		t.Fatalf("readRun sibling: %v", err)
	}
	if got.GetSupersededBy() != "job-ok" {
		t.Errorf("sibling SupersededBy = %q, want job-ok (auto-supersede on clean completion)", got.GetSupersededBy())
	}
}

// TestAttachFromDBStreamsProgress asserts the cross-process attach now streams the persisted progress
// (the #1 payoff): a DB-only terminal run carrying a progress row and a host is replayed as a
// progress frame + a host frame + the terminal Final frame, so an operator attaching from another
// process sees the same progress the owning process wrote — not a bar frozen at zero.
func TestAttachFromDBStreamsProgress(t *testing.T) {
	s, _, ctx := newTestServer(t)

	run := &scanpb.Run{
		Id: "att-1", Scanner: "nmap",
		Progress: []*scanpb.TaskProgress{{Id: "p", Task: "SYN Stealth Scan", Percent: 70}},
		Hosts:    []*hostpb.Host{upHost("10.0.0.9")},
		Stats:    &scanpb.Stats{Finished: &scanpb.Finished{Time: 1, Elapsed: 2, Exit: scan.ExitInterrupted}},
	}
	if _, err := s.persistRun(ctx, run); err != nil {
		t.Fatalf("persist: %v", err)
	}

	stream := &fakeRunStream{ctx: context.Background()}
	if err := s.attachFromDB(context.Background(), "att-1", stream); err != nil {
		t.Fatalf("attachFromDB: %v", err)
	}

	stream.mu.Lock()
	updates := stream.updates
	stream.mu.Unlock()

	var sawProgress, sawHost, sawFinal bool
	for _, u := range updates {
		switch upd := u.GetUpdate().(type) {
		case *scanrpcpb.RunUpdate_Progress:
			if upd.Progress.GetPercent() == 70 {
				sawProgress = true
			}
		case *scanrpcpb.RunUpdate_Host:
			sawHost = true
		case *scanrpcpb.RunUpdate_Final:
			sawFinal = true
		}
	}
	if !sawProgress {
		t.Error("attachFromDB did not stream the persisted progress frame")
	}
	if !sawHost {
		t.Error("attachFromDB did not stream the host frame")
	}
	if !sawFinal {
		t.Error("attachFromDB did not stream the terminal Final frame")
	}
}
