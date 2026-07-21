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
	"errors"
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

// errChan builds the terminal-outcome channel consume drains: one value (the scanner's terminal
// error, or nil for a clean completion) then closed, exactly as the drivers deliver it.
func errChan(err error) <-chan error {
	c := make(chan error, 1)
	c <- err
	close(c)
	return c
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
	// The killed scanner also reports an exit error; interrupted must WIN over failed — a deliberate
	// Stop is not a scan failure.
	s.consume(job, results, progress, errChan(errors.New("signal: killed")))

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
	s.consume(job, results, progress, errChan(nil)) // clean terminal outcome

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

// TestConsumeCoalescesConsecutiveFailures is the auto-path payoff of failure-coalescing: a second
// resultless failure of the same definition tombstones the first under itself (latest wins, with a
// count), so a misconfigured cron collapses to one "✗ failed ×N" row instead of piling up — while a
// clean run of the same series, added after, still heads a SEPARATE visible success row.
func TestConsumeCoalescesConsecutiveFailures(t *testing.T) {
	s, _, ctx := newTestServer(t)

	// runFailed drives one resultless failure (no host produced, an errc error, no cancel) to its
	// stored terminal state under the given job id.
	runFailed := func(id string) {
		jobCtx, cancel := context.WithCancel(context.Background())
		defer cancel()
		job := newScanJob(&scanrpcpb.RunScanRequest{
			Scanner: "nmap", Args: []string{"-sU", "-p1-100"},
			Targets: []*scanpb.Target{{Id: id + "-t", Address: "10.0.0.9"}},
		}, id, jobCtx, cancel, time.Now().Unix())
		s.addJob(job)
		results := make(chan *scanpb.Result)
		progress := make(chan *scanpb.TaskProgress)
		close(results)
		close(progress)
		s.consume(job, results, progress, errChan(errors.New("requires root privileges. QUITTING!")))
	}

	runFailed("fail-1")
	runFailed("fail-2") // its autoSupersede should coalesce fail-1 under fail-2

	// fail-1 is tombstoned under fail-2 (the latest failure heads the failure line).
	f1, err := s.readRun(ctx, "fail-1")
	if err != nil || f1 == nil {
		t.Fatalf("readRun fail-1: %v", err)
	}
	if f1.GetSupersededBy() != "fail-2" {
		t.Errorf("fail-1 SupersededBy = %q, want fail-2 (consecutive failures coalesce)", f1.GetSupersededBy())
	}
	f2, err := s.readRun(ctx, "fail-2")
	if err != nil || f2 == nil {
		t.Fatalf("readRun fail-2: %v", err)
	}
	if f2.GetSupersededBy() != "" {
		t.Errorf("fail-2 should head the failure line, not be superseded (got %q)", f2.GetSupersededBy())
	}
	if f2.GetFormerRuns() != 1 {
		t.Errorf("failure head FormerRuns = %d, want 1", f2.GetFormerRuns())
	}

	// A clean run of the SAME definition, completed after, heads a separate visible success row — the
	// failure head is not buried under it, nor it under the failure.
	jobCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	okJob := newScanJob(&scanrpcpb.RunScanRequest{
		Scanner: "nmap", Args: []string{"-sU", "-p1-100"},
		Targets: []*scanpb.Target{{Id: "ok-t", Address: "10.0.0.9"}},
	}, "ok", jobCtx, cancel, time.Now().Unix())
	s.addJob(okJob)
	okRes, okProg := feed(upHost("10.0.0.9"), &scanpb.TaskProgress{Task: "SYN Stealth Scan", Percent: 100})
	s.consume(okJob, okRes, okProg, errChan(nil))

	ok, err := s.readRun(ctx, "ok")
	if err != nil || ok == nil {
		t.Fatalf("readRun ok: %v", err)
	}
	if ok.GetSupersededBy() != "" {
		t.Errorf("clean run tombstoned by a failure head (SupersededBy=%q); classes must not cross", ok.GetSupersededBy())
	}
	// The latest failure must still be visible — a success must not bury the regression signal.
	f2, err = s.readRun(ctx, "fail-2")
	if err != nil || f2 == nil {
		t.Fatalf("readRun fail-2 (post-success): %v", err)
	}
	if f2.GetSupersededBy() != "" {
		t.Errorf("failure head buried under a later success (SupersededBy=%q); classes must not cross", f2.GetSupersededBy())
	}
}

// TestConsumeTracksTargetCompletion is the resume foundation (SCAN.md Phase 6): a streamed run with
// structured Targets, interrupted before it reached them all, must persist which targets were
// scanned. A target that produced a result is marked done; a target never reached stays unmarked and
// is exactly what RemainingTargets (the reforged work of a `scan resume`) returns. This proves the
// Target.Status column survives the snapshot upsert path — an association insert alone would freeze
// it empty and a resume would wastefully re-scan everything.
func TestConsumeTracksTargetCompletion(t *testing.T) {
	s, _, ctx := newTestServer(t)

	jobCtx, cancel := context.WithCancel(context.Background())
	cancel() // interrupted before draining every target
	job := newScanJob(&scanrpcpb.RunScanRequest{
		Scanner: "nmap",
		Args:    []string{"-sT", "-p1-100"},
		Targets: []*scanpb.Target{
			{Id: "t-a", Address: "10.0.0.1"},
			{Id: "t-b", Address: "10.0.0.2"}, // never reached before the interrupt
		},
	}, "job-track", jobCtx, cancel, time.Now().Unix())
	s.addJob(job)

	// Only 10.0.0.1 produced a result.
	results, progress := feed(upHost("10.0.0.1"), &scanpb.TaskProgress{Task: "SYN Stealth Scan", Percent: 50})
	s.consume(job, results, progress, errChan(errors.New("signal: killed")))

	run, err := s.readRun(ctx, "job-track")
	if err != nil || run == nil {
		t.Fatalf("readRun: %v (run=%v)", err, run)
	}
	status := map[string]string{}
	for _, tg := range run.GetTargets() {
		status[tg.GetAddress()] = tg.GetStatus()
	}
	if status["10.0.0.1"] != scan.TargetDone {
		t.Errorf("target 10.0.0.1 status = %q, want %q (it produced a result)", status["10.0.0.1"], scan.TargetDone)
	}
	if status["10.0.0.2"] == scan.TargetDone {
		t.Error("target 10.0.0.2 marked done but was never reached")
	}

	remaining := scan.TargetSpecs(scan.RemainingTargets(run.GetTargets()))
	if len(remaining) != 1 || remaining[0] != "10.0.0.2" {
		t.Errorf("remaining = %v, want [10.0.0.2] (the untouched target a resume re-scans)", remaining)
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

// TestConsumeFailedRunStampsError is the third terminal outcome: a job that drains WITHOUT a cancel
// but whose scanner reported an error after launching (the driver's errc carries it — e.g. nmap
// "requires root privileges. QUITTING!") must be stamped Exit="error" with the reason so it reads as
// FAILED, not a false clean "done" over zero hosts. A failed run must NOT collapse a good sibling of
// the same definition — it has no results and burying real history would be worse than the bug we fix.
func TestConsumeFailedRunStampsError(t *testing.T) {
	s, _, ctx := newTestServer(t)

	// A previously-good sibling of the same definition. It must survive the failed run untouched.
	sib := &scanpb.Run{
		Id: "sib", Scanner: "nmap", Args: "-sU -p1-100",
		Targets: []*scanpb.Target{{Id: "st", Address: "10.0.0.9"}},
		Stats:   &scanpb.Stats{Finished: &scanpb.Finished{Time: 1000, Exit: "success"}},
	}
	if _, err := s.persistRun(ctx, sib); err != nil {
		t.Fatalf("persist sibling: %v", err)
	}

	jobCtx, cancel := context.WithCancel(context.Background())
	defer cancel() // NOT cancelled: this is a genuine failure, not a Stop
	job := newScanJob(&scanrpcpb.RunScanRequest{
		Scanner: "nmap",
		Args:    []string{"-sU", "-p1-100"},
		Targets: []*scanpb.Target{{Id: "jt", Address: "10.0.0.9"}},
	}, "job-fail", jobCtx, cancel, time.Now().Unix())
	s.addJob(job)

	// The scanner produced no host (it quit before scanning) and signalled a terminal error.
	reason := "You requested a scan type which requires root privileges. QUITTING! (exit status 1)"
	results := make(chan *scanpb.Result)
	progress := make(chan *scanpb.TaskProgress)
	close(results)
	close(progress)
	s.consume(job, results, progress, errChan(errors.New(reason)))

	run, err := s.readRun(ctx, "job-fail")
	if err != nil || run == nil {
		t.Fatalf("readRun: %v (run=%v)", err, run)
	}
	fin := run.GetStats().GetFinished()
	if fin.GetExit() != "error" {
		t.Errorf("exit = %q, want error", fin.GetExit())
	}
	if fin.GetErrorMsg() != reason {
		t.Errorf("errormsg = %q, want the scanner reason %q", fin.GetErrorMsg(), reason)
	}
	if scan.IsRunning(run) {
		t.Error("a failed run must not read as running")
	}
	if run.GetSupersededBy() != "" {
		t.Errorf("failed run tombstoned (SupersededBy=%q); a failure must stay its own row", run.GetSupersededBy())
	}

	// The good sibling must be untouched: a resultless failure must never bury real history.
	got, err := s.readRun(ctx, "sib")
	if err != nil || got == nil {
		t.Fatalf("readRun sibling: %v", err)
	}
	if got.GetSupersededBy() != "" {
		t.Errorf("sibling tombstoned by a failed run (SupersededBy=%q); must not happen", got.GetSupersededBy())
	}
}
