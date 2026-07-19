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

	"github.com/d3c3ptive/aims/cmd/display"
	host "github.com/d3c3ptive/aims/host/pb"
	scanpb "github.com/d3c3ptive/aims/scan/pb"
)

func doneRun(id string) *scanpb.Run {
	return &scanpb.Run{
		Id:      id,
		Scanner: "nmap",
		Stats: &scanpb.Stats{
			Finished: &scanpb.Finished{Time: 1000, TimeStr: "Mon", Elapsed: 12, Exit: "success"},
			Hosts:    &scanpb.HostStats{Up: 1, Down: 0, Total: 1},
		},
	}
}

func runningRun(id string) *scanpb.Run {
	return &scanpb.Run{
		Id:       id,
		Scanner:  "nmap",
		Progress: []*scanpb.TaskProgress{{Task: "SYN Scan", Percent: 42, Time: 5}},
	}
}

func failedRun(id string) *scanpb.Run {
	return &scanpb.Run{
		Id:      id,
		Scanner: "nmap",
		Stats:   &scanpb.Stats{Finished: &scanpb.Finished{Time: 1, Exit: "error", ErrorMsg: "boom"}},
	}
}

// stateOf must classify each phase of the live axis correctly: finished-clean is done,
// finished-with-error is failed, task activity without finished stats is running, and a bare run
// is queued.
func TestStateOf(t *testing.T) {
	cases := []struct {
		name string
		run  *scanpb.Run
		want runState
	}{
		{"done", doneRun("d"), stateDone},
		{"running", runningRun("r"), stateRunning},
		{"failed", failedRun("f"), stateFailed},
		{"created", &scanpb.Run{Id: "c", Scanner: "nmap"}, stateCreated},
	}
	for _, c := range cases {
		if got := stateOf(c.run); got != c.want {
			t.Errorf("%s: stateOf = %v, want %v", c.name, got, c.want)
		}
	}
}

// The status token surfaces the state (and, for a live scan, its aggregate percent) in plain text.
func TestStateToken(t *testing.T) {
	cases := []struct {
		run  *scanpb.Run
		want string
	}{
		{doneRun("d"), "done"},
		{failedRun("f"), "failed"},
		{runningRun("r"), "42%"},
		{&scanpb.Run{}, "queued"},
	}
	for _, c := range cases {
		if got := display.StripANSI(stateToken(c.run)); !strings.Contains(got, c.want) {
			t.Errorf("stateToken = %q, want substring %q", got, c.want)
		}
	}
}

// SortRuns puts running scans first (most actionable), then queued, then finished.
func TestSortRuns(t *testing.T) {
	runs := []*scanpb.Run{doneRun("done"), {Id: "created", Scanner: "nmap"}, runningRun("running")}
	SortRuns(runs)

	wantOrder := []string{"running", "created", "done"}
	for i, want := range wantOrder {
		if runs[i].GetId() != want {
			t.Errorf("position %d = %q, want %q (order: %v)", i, runs[i].GetId(), want,
				[]string{runs[0].GetId(), runs[1].GetId(), runs[2].GetId()})
		}
	}
}

// getTasks splits ended tasks from still-running ones, keeping only the furthest-along progress
// record per running task and excluding any task that has since ended.
func TestGetTasksSplit(t *testing.T) {
	r := &scanpb.Run{
		End: []*scanpb.ScanTask{{Task: "A", Time: 10}},
		Progress: []*scanpb.TaskProgress{
			{Task: "A", Percent: 100, Time: 9}, // A ended — must be dropped from running
			{Task: "B", Percent: 30, Time: 5},
			{Task: "B", Percent: 55, Time: 8}, // keep the furthest-along B
		},
	}

	running, done := getTasks(r)
	if len(done) != 1 || done[0].GetTask() != "A" {
		t.Fatalf("done = %+v, want one ended task A", done)
	}
	if len(running) != 1 || running[0].GetTask() != "B" {
		t.Fatalf("running = %+v, want one running task B", running)
	}
	if running[0].GetPercent() != 55 {
		t.Errorf("running B percent = %v, want 55 (furthest-along)", running[0].GetPercent())
	}
}

// A bare run must render through every field and the full Detail without panicking — a partially
// observed run is normal and must never crash the table or the detail view.
func TestDisplayNilSafe(t *testing.T) {
	bare := &scanpb.Run{}
	for name, fn := range DisplayFields {
		func() {
			defer func() {
				if p := recover(); p != nil {
					t.Errorf("DisplayFields[%q] panicked on a bare run: %v", name, p)
				}
			}()
			_ = fn(bare)
		}()
	}

	defer func() {
		if p := recover(); p != nil {
			t.Errorf("Detail panicked on a bare run: %v", p)
		}
	}()
	out := Detail(bare, nil, DetailOpts{Tasks: true, Targets: true, Hosts: true}).Render(0)
	if strings.TrimSpace(out) == "" {
		t.Error("Detail rendered empty for a bare run, want at least a banner")
	}
}

// The cross-run host-sharing insight is the visible payoff of cross-run unification: a run linked
// to a host another run also observed reports the overlap.
func TestDetailSharedHostsInsight(t *testing.T) {
	a := &scanpb.Run{Id: "run-a", Scanner: "nmap", Hosts: []*host.Host{{Id: "host-1"}}}
	b := &scanpb.Run{Id: "run-b", Scanner: "nmap", Hosts: []*host.Host{{Id: "host-1"}}}
	all := []*scanpb.Run{a, b}

	insights := Detail(a, all, DetailOpts{}).Insights
	joined := strings.Join(insights, "\n")
	if !strings.Contains(joined, "shares host") {
		t.Errorf("insights = %v, want a shared-host note", insights)
	}

	// A run that shares nothing reports no such note.
	lonely := &scanpb.Run{Id: "run-c", Scanner: "nmap", Hosts: []*host.Host{{Id: "host-9"}}}
	if got := sharedRunCount(lonely, []*scanpb.Run{lonely, a, b}); got != 0 {
		t.Errorf("sharedRunCount for a non-overlapping run = %d, want 0", got)
	}
}
