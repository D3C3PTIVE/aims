package main

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
	"testing"
	"time"

	scanpb "github.com/d3c3ptive/aims/scan/pb"
	scans "github.com/d3c3ptive/aims/scan/pb/rpc"
)

// TestScanJobsOverTeamClient exercises the streaming scan job model over the FULL transport that
// the CLI actually uses — client → teamclient → bufconn → teamserver → server/scan → drive →
// nmap — which the ephemeral all-in-one CLI can't cover (it drops background jobs on process
// exit). Against this one persistent teamserver: a --background scan is submitted, appears in
// Jobs, is re-followed by Attach, cancelled by Stop, and its run persists under the job id.
// Guarded (needs nmap).
func TestScanJobsOverTeamClient(t *testing.T) {
	if os.Getenv("AIMS_NMAP_IT") == "" {
		t.Skip("set AIMS_NMAP_IT=1 to run (requires the nmap binary)")
	}

	con := newInMemoryStack(t)
	ctx := context.Background()

	// Detached scan of an unreachable TEST-NET host, so it lingers long enough to observe.
	stream, err := con.Scans.Run(ctx, &scans.RunScanRequest{
		Scanner:    "nmap",
		Args:       []string{"-sT", "-p", "1-100", "--host-timeout", "30s"},
		Targets:    []*scanpb.Target{{Address: "192.0.2.1"}},
		Background: true,
	})
	if err != nil {
		t.Fatalf("Scans.Run over teamclient: %v", err)
	}

	// First frame is the job id; a background stream then ends (the job keeps running server-side).
	upd, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv job id: %v", err)
	}
	jobID := upd.GetJobId()
	if jobID == "" {
		t.Fatalf("first frame should be JobId, got %T", upd.GetUpdate())
	}
	for {
		if _, e := stream.Recv(); e != nil {
			break // EOF: background stream closed
		}
	}

	// Jobs lists the running scan over the transport.
	listed := false
	for i := 0; i < 100 && !listed; i++ {
		jr, err := con.Scans.Jobs(ctx, &scans.JobsRequest{})
		if err != nil {
			t.Fatalf("Jobs: %v", err)
		}
		for _, j := range jr.GetJobs() {
			if j.GetId() == jobID {
				listed = true
			}
		}
		if !listed {
			time.Sleep(40 * time.Millisecond)
		}
	}
	if !listed {
		t.Fatalf("job %s not listed via teamclient Jobs", jobID)
	}

	// Attach re-follows the job's stream over the transport; it ends when the job does.
	att, err := con.Scans.Attach(ctx, &scans.AttachRequest{JobId: jobID})
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}
	attachDone := make(chan struct{})
	go func() {
		for {
			if _, e := att.Recv(); e != nil {
				break
			}
		}
		close(attachDone)
	}()

	// Stop cancels the job.
	sr, err := con.Scans.Stop(ctx, &scans.StopRequest{JobId: jobID})
	if err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if !sr.GetStopped() {
		t.Error("Stop should report Stopped=true for a running job")
	}

	select {
	case <-attachDone:
	case <-time.After(30 * time.Second):
		t.Fatal("Attach stream did not end after Stop")
	}

	// The run persisted under the job id (the initial snapshot + final persist).
	rd, err := con.Scans.Read(ctx, &scans.ReadScanRequest{
		Scan:    &scanpb.Run{},
		Filters: &scans.RunFilters{},
	})
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	found := false
	for _, r := range rd.GetScans() {
		if r.GetId() == jobID {
			found = true
		}
	}
	if !found {
		t.Error("run should be persisted under the job id after the scan")
	}
}
