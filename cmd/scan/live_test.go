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
	"bytes"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	hostpb "github.com/d3c3ptive/aims/host/pb"
	network "github.com/d3c3ptive/aims/network/pb"
	scandom "github.com/d3c3ptive/aims/scan"
	scanpb "github.com/d3c3ptive/aims/scan/pb"
)

// stripANSI removes any CSI escape sequence (…m colors, …K clear-line, …A cursor-up) so assertions
// can be made on the visible text.
func stripANSI(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] == 0x1b {
			i++
			if i < len(s) && s[i] == '[' {
				i++
				for i < len(s) && (s[i] < 0x40 || s[i] > 0x7e) {
					i++
				}
				if i < len(s) {
					i++ // consume the final byte
				}
			}
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

func openTCP(num uint32, service string) *hostpb.Port {
	return &hostpb.Port{
		Number:   num,
		Protocol: "tcp",
		State:    &hostpb.State{State: "open"},
		Service:  &network.Service{Name: service},
	}
}

// TestHostSummary condenses a host into a table row: address label, hostname, up/down, OS guess,
// open-port count, and the open service names (closed ports excluded).
func TestHostSummary(t *testing.T) {
	h := &hostpb.Host{
		Addresses: []*network.Address{{Addr: "10.0.0.9"}},
		Hostnames: []*hostpb.Hostname{{Name: "box.local"}},
		Status:    &hostpb.Status{State: "up"},
		OS:        &hostpb.OS{Matches: []*hostpb.OSMatch{{Name: "Linux 5.x", Accuracy: 95}}},
		Ports: []*hostpb.Port{
			openTCP(443, "https"),
			openTCP(22, "ssh"),
			{Number: 8080, Protocol: "tcp", State: &hostpb.State{State: "closed"}, Service: &network.Service{Name: "http-proxy"}},
		},
	}

	row := hostSummary(h)
	if row.label != "10.0.0.9" {
		t.Errorf("label = %q, want the address", row.label)
	}
	if row.name != "box.local" {
		t.Errorf("name = %q, want the hostname", row.name)
	}
	if row.state != "up" {
		t.Errorf("state = %q, want up", row.state)
	}
	if !strings.Contains(row.os, "Linux") {
		t.Errorf("os = %q, want an OS guess containing Linux", row.os)
	}
	if row.open != 2 {
		t.Errorf("open = %d, want 2 (closed port excluded)", row.open)
	}
	// Sorted by port number, so ssh (22) before https (443); the closed 8080 is absent.
	if row.services != "ssh · https" {
		t.Errorf("services = %q, want \"ssh · https\"", row.services)
	}
}

// TestHostSummaryLabelFallback falls back to the first hostname when no address is present.
func TestHostSummaryLabelFallback(t *testing.T) {
	h := &hostpb.Host{
		Hostnames: []*hostpb.Hostname{{Name: "only.hostname"}},
		Status:    &hostpb.Status{State: "up"},
	}
	if got := hostSummary(h).label; got != "only.hostname" {
		t.Errorf("label = %q, want the hostname fallback", got)
	}
}

// TestDashboardRender drives the in-place renderer against a buffer (no TTY needed): the block must
// carry the job id, the scanner command, a live percent + task, the host row, and the up-count
// footer — and, once done, the stored-count footer.
func TestDashboardRender(t *testing.T) {
	var buf bytes.Buffer
	d := &dashboard{
		w:     &buf,
		width: 100,
		opts:  streamOpts{scanner: "nmap", args: []string{"-sT", "-p1-1000"}},
		start: time.Now().Add(-42 * time.Second),
		jobID: "7acca412-115b-467f-a1b1-1b3161d3d982",
		task:  "Connect Scan",
		pct:   61.3,
		eta:   32 * time.Second,
		hosts: []hostRow{{label: "127.0.0.1", name: "localhost", state: "up", os: "Linux", open: 3, services: "ssh · http · https"}},
	}

	d.render()
	out := stripANSI(buf.String())

	for _, want := range []string{
		"7acca412",           // small job id in the header
		"nmap -sT -p1-1000",  // the command echoed
		"61.3%",              // live percent
		"Connect Scan",       // current task
		"ETA 0:32",           // eta from d.eta
		"HOST",               // table header
		"NAME",               // new column
		"OS",                 // new column
		"127.0.0.1",          // host row label
		"localhost",          // host row name
		"Linux",              // host row OS
		"ssh · http · https", // host row services
		"1 host(s) up",       // live footer
	} {
		if !strings.Contains(out, want) {
			t.Errorf("render missing %q\n---\n%s", want, out)
		}
	}

	// A second render (done) redraws in place: it must move the cursor up over the first block and
	// switch the footer to the stored count.
	buf.Reset()
	d.done = true
	d.pct = 100
	d.stored = 1
	d.render()
	out2 := buf.String()
	if !strings.Contains(out2, "\x1b[") {
		t.Error("redraw should emit cursor-control escapes")
	}
	if !strings.Contains(stripANSI(out2), "1 host(s) stored") {
		t.Errorf("done footer missing stored count\n---\n%s", stripANSI(out2))
	}
	if !strings.Contains(stripANSI(out2), "done") {
		t.Errorf("done render should mark the scan done\n---\n%s", stripANSI(out2))
	}
}

// TestDashboardElapsed pins the elapsed reconciliation: while live the clock runs from the anchored
// start (so an attach seeded with the real scan start shows true elapsed, not a 0:00 reset), and once
// the Final frame lands the scanner-authoritative elapsed wins over wall-clock — which is what makes
// the dashboard's terminal line agree with `scan list`'s "When" and `scan show`'s Elapsed.
func TestDashboardElapsed(t *testing.T) {
	// Anchored 42s ago: the live footer counts from the anchor, not from "now".
	d := &dashboard{width: 100, opts: streamOpts{scanner: "nmap"}, start: time.Now().Add(-42 * time.Second)}
	if got := stripANSI(strings.Join(d.lines(), "\n")); !strings.Contains(got, "elapsed 0:42") {
		t.Errorf("live elapsed should count from the anchored start (~0:42)\n---\n%s", got)
	}

	// Final frame reports the scanner's own 8:19 duration; it must override the ~42s wall-clock so the
	// terminal line reflects how long the scan actually ran, not how long this client watched it.
	d.done = true
	d.pct = 100
	d.stored = 1
	d.doneElapsed = 8*time.Minute + 19*time.Second
	got := stripANSI(strings.Join(d.lines(), "\n"))
	if !strings.Contains(got, "elapsed 8:19") {
		t.Errorf("done elapsed should use the scanner-authoritative duration (8:19)\n---\n%s", got)
	}
	if strings.Contains(got, "0:42") {
		t.Errorf("done elapsed must not fall back to wall-clock once the run reports its own\n---\n%s", got)
	}

	// elapsedFromRun reads Finished.Elapsed (seconds) as a Duration; 0 when the run never finished.
	if e := elapsedFromRun(&scanpb.Run{Stats: &scanpb.Stats{Finished: &scanpb.Finished{Elapsed: 499}}}); e != 499*time.Second {
		t.Errorf("elapsedFromRun = %v, want 8m19s", e)
	}
	if e := elapsedFromRun(&scanpb.Run{}); e != 0 {
		t.Errorf("elapsedFromRun(no finished) = %v, want 0", e)
	}
}

// TestFinalOutcomeClassifiers pins the three-way terminal classification the live views branch on:
// a clean run is neither failed nor interrupted, a stopped run is interrupted (not failed), and a
// scanner error is failed and carries its reason.
func TestFinalOutcomeClassifiers(t *testing.T) {
	clean := &scanpb.Run{Stats: &scanpb.Stats{Finished: &scanpb.Finished{Exit: "success"}}}
	stopped := &scanpb.Run{Stats: &scanpb.Stats{Finished: &scanpb.Finished{Exit: scandom.ExitInterrupted}}}
	failed := &scanpb.Run{Stats: &scanpb.Stats{Finished: &scanpb.Finished{
		Exit: "error", ErrorMsg: "You requested a scan type which requires root privileges. QUITTING!",
	}}}

	if finalFailed(clean) || finalInterrupted(clean) || failureReason(clean) != "" || finalVerb(clean) != "Scan complete" {
		t.Error("a clean run must classify as complete, not failed/interrupted")
	}
	if !finalInterrupted(stopped) || finalFailed(stopped) || finalVerb(stopped) != "Scan interrupted" {
		t.Error("a stopped run must classify as interrupted, not failed")
	}
	if !finalFailed(failed) || finalInterrupted(failed) || finalVerb(failed) != "Scan failed" {
		t.Error("an errored run must classify as failed")
	}
	if !strings.Contains(failureReason(failed), "requires root privileges") {
		t.Errorf("failureReason = %q, want the scanner reason", failureReason(failed))
	}
}

// TestDashboardRenderFailed asserts a failed terminal frame renders as "✗ failed" with its reason in
// the footer — NOT a green "done" over "0 host(s) stored", which is exactly the false success the
// server fold fixes surfacing on the client side.
func TestDashboardRenderFailed(t *testing.T) {
	var buf bytes.Buffer
	d := &dashboard{
		w:     &buf,
		width: 120,
		opts:  streamOpts{scanner: "nmap", args: []string{"-sU", "--top-ports", "200"}},
		start: time.Now().Add(-1 * time.Second),
		jobID: "c8e6eb9e-115b-467f-a1b1-1b3161d3d982",
	}
	d.done = true
	d.failed = true
	d.reason = "You requested a scan type which requires root privileges. QUITTING! (exit status 1)"
	d.render()

	out := stripANSI(buf.String())
	if !strings.Contains(out, "✗ failed") {
		t.Errorf("failed render must show \"✗ failed\"\n---\n%s", out)
	}
	if !strings.Contains(out, "requires root privileges") {
		t.Errorf("failed footer must carry the reason\n---\n%s", out)
	}
	if strings.Contains(out, "✓ done") || strings.Contains(out, "host(s) stored") {
		t.Errorf("a failed scan must not read as a clean stored success\n---\n%s", out)
	}
}

// TestClipVisible truncates by VISIBLE width, preserving ANSI escapes (which cost no columns) so a
// colored line never wraps.
func TestClipVisible(t *testing.T) {
	// 10 visible chars wrapped in color; clip to 4 visible.
	colored := "\x1b[32mABCDEFGHIJ\x1b[0m"
	got := clipVisible(colored, 4)
	if v := utf8.RuneCountInString(stripANSI(got)); v != 4 {
		t.Errorf("visible length = %d, want 4 (got %q)", v, stripANSI(got))
	}
	if !strings.HasPrefix(got, "\x1b[32m") {
		t.Errorf("clip dropped the leading color escape: %q", got)
	}

	// A string already within budget is returned unchanged.
	if got := clipVisible("short", 20); got != "short" {
		t.Errorf("clipVisible should not alter a short string, got %q", got)
	}
}

// TestBarFill renders the filled proportion of the progress bar.
func TestBarFill(t *testing.T) {
	full := stripANSI(bar(100, 10))
	if strings.Count(full, "█") != 10 {
		t.Errorf("100%% bar should be fully filled, got %q", full)
	}
	empty := stripANSI(bar(0, 10))
	if strings.Count(empty, "█") != 0 || strings.Count(empty, "░") != 10 {
		t.Errorf("0%% bar should be all empty, got %q", empty)
	}
	half := stripANSI(bar(50, 10))
	if strings.Count(half, "█") != 5 {
		t.Errorf("50%% bar should be half filled, got %q", half)
	}
}

// TestFmtDur formats durations as M:SS.
func TestFmtDur(t *testing.T) {
	cases := map[time.Duration]string{
		0:                               "0:00",
		32 * time.Second:                "0:32",
		90 * time.Second:                "1:30",
		(3*time.Minute + 5*time.Second): "3:05",
		-5 * time.Second:                "0:00", // negatives clamp to zero
	}
	for d, want := range cases {
		if got := fmtDur(d); got != want {
			t.Errorf("fmtDur(%s) = %q, want %q", d, got, want)
		}
	}
}
