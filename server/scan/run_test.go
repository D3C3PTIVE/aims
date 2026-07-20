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
	"os"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"

	scanpb "github.com/d3c3ptive/aims/scan/pb"
	scanrpcpb "github.com/d3c3ptive/aims/scan/pb/rpc"
)

// fakeRunStream is a minimal Scans_RunServer that records the frames the server sends.
type fakeRunStream struct {
	grpc.ServerStream
	ctx     context.Context
	mu      sync.Mutex
	updates []*scanrpcpb.RunUpdate
}

func (f *fakeRunStream) Send(u *scanrpcpb.RunUpdate) error {
	f.mu.Lock()
	f.updates = append(f.updates, u)
	f.mu.Unlock()
	return nil
}

func (f *fakeRunStream) Context() context.Context { return f.ctx }

// TestRunStreamLive drives a real nmap scan through the streaming Run RPC against localhost and
// asserts the full server path: the first frame is the JobId, the terminal frame is a Final
// carrying a stored run, and the run is actually persisted (with its host folded in). Foreground
// Run blocks until the job finishes, so no polling is needed. Guarded (needs nmap).
func TestRunStreamLive(t *testing.T) {
	if os.Getenv("AIMS_NMAP_IT") == "" {
		t.Skip("set AIMS_NMAP_IT=1 to run (requires the nmap binary)")
	}

	s, gdb, _ := newTestServer(t)
	stream := &fakeRunStream{ctx: context.Background()}

	err := s.Run(&scanrpcpb.RunScanRequest{
		Scanner: "nmap",
		Args:    []string{"-sT", "-p", "22,80,443"},
		Targets: []*scanpb.Target{{Address: "127.0.0.1"}},
	}, stream)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	stream.mu.Lock()
	updates := stream.updates
	stream.mu.Unlock()

	if len(updates) < 2 {
		t.Fatalf("expected at least JobId + Final frames, got %d", len(updates))
	}
	if updates[0].GetJobId() == "" {
		t.Errorf("first frame should be the JobId, got %T", updates[0].GetUpdate())
	}

	final := updates[len(updates)-1].GetFinal()
	if final == nil {
		t.Fatalf("last frame should be Final, got %T", updates[len(updates)-1].GetUpdate())
	}
	if final.GetScanner() != "nmap" {
		t.Errorf("stored run scanner = %q, want nmap", final.GetScanner())
	}

	// The run was persisted, and its host folded into the shared table.
	if n := countRows(t, gdb, "runs"); n != 1 {
		t.Errorf("runs persisted = %d, want 1", n)
	}
	if n := countRows(t, gdb, "hosts"); n < 1 {
		t.Errorf("hosts folded = %d, want >= 1", n)
	}
}

// TestRunUnknownScanner asserts an unknown scanner name is rejected before any job is started
// (no nmap needed).
func TestRunUnknownScanner(t *testing.T) {
	s, _, _ := newTestServer(t)
	stream := &fakeRunStream{ctx: context.Background()}
	if err := s.Run(&scanrpcpb.RunScanRequest{Scanner: "nope"}, stream); err == nil {
		t.Error("Run with unknown scanner should error")
	}
}

// TestJobsAttachStopLive exercises the job model against ONE persistent server instance — the
// piece the all-in-one CLI can't cover (its per-command teamserver is ephemeral). A background
// scan of an unreachable host stays running long enough to: appear in Jobs, be re-followed by
// Attach, and be cancelled by Stop (after which it is no longer running). Guarded (needs nmap).
func TestJobsAttachStopLive(t *testing.T) {
	if os.Getenv("AIMS_NMAP_IT") == "" {
		t.Skip("set AIMS_NMAP_IT=1 to run (requires the nmap binary)")
	}

	s, _, _ := newTestServer(t)

	// Detached scan of a TEST-NET address that drops packets, so nmap sits waiting (bounded by
	// --host-timeout as a backstop) and the job is observably running across the calls below.
	fg := &fakeRunStream{ctx: context.Background()}
	err := s.Run(&scanrpcpb.RunScanRequest{
		Scanner:    "nmap",
		Args:       []string{"-sT", "-p", "1-50", "--host-timeout", "20s"},
		Targets:    []*scanpb.Target{{Address: "192.0.2.1"}},
		Background: true,
	}, fg)
	if err != nil {
		t.Fatalf("Run (background): %v", err)
	}

	fg.mu.Lock()
	jobID := fg.updates[0].GetJobId()
	fg.mu.Unlock()
	if jobID == "" {
		t.Fatal("background Run should emit a JobId frame")
	}

	// Jobs lists it as running.
	if !jobListed(t, s, jobID) {
		t.Fatalf("job %s not listed as running", jobID)
	}

	// Attach re-follows the stream; it returns once the job ends (i.e. after Stop).
	att := &fakeRunStream{ctx: context.Background()}
	attachDone := make(chan error, 1)
	go func() { attachDone <- s.Attach(&scanrpcpb.AttachRequest{JobId: jobID}, att) }()

	// Stop cancels the job.
	stopRes, err := s.Stop(context.Background(), &scanrpcpb.StopRequest{JobId: jobID})
	if err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if !stopRes.GetStopped() {
		t.Error("Stop should report Stopped=true for a running job")
	}

	select {
	case err := <-attachDone:
		if err != nil {
			t.Errorf("Attach returned error: %v", err)
		}
	case <-time.After(25 * time.Second):
		t.Fatal("Attach did not return after Stop")
	}

	// After Stop, the job is no longer running.
	if jobListed(t, s, jobID) {
		t.Errorf("job %s still listed as running after Stop", jobID)
	}
}

func jobListed(t *testing.T, s *server, jobID string) bool {
	t.Helper()
	res, err := s.Jobs(context.Background(), &scanrpcpb.JobsRequest{})
	if err != nil {
		t.Fatalf("Jobs: %v", err)
	}
	for _, j := range res.GetJobs() {
		if j.GetId() == jobID {
			return true
		}
	}
	return false
}
