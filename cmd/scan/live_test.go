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

// TestHostSummary condenses a host into a table row: address label, up/down, open-port count, and
// the open service names (closed ports excluded).
func TestHostSummary(t *testing.T) {
	h := &hostpb.Host{
		Addresses: []*network.Address{{Addr: "10.0.0.9"}},
		Hostnames: []*hostpb.Hostname{{Name: "box.local"}},
		Status:    &hostpb.Status{State: "up"},
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
	if row.state != "up" {
		t.Errorf("state = %q, want up", row.state)
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
		hosts: []hostRow{{label: "127.0.0.1", state: "up", open: 3, services: "ssh · http · https"}},
	}

	d.render()
	out := stripANSI(buf.String())

	for _, want := range []string{
		"7acca412",           // small job id in the header
		"nmap -sT -p1-1000",  // the command echoed
		"61.3%",              // live percent
		"Connect Scan",       // current task
		"ETA 0:32",           // eta from d.eta
		"127.0.0.1",          // host row label
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
		0:                              "0:00",
		32 * time.Second:               "0:32",
		90 * time.Second:               "1:30",
		(3*time.Minute + 5*time.Second): "3:05",
		-5 * time.Second:               "0:00", // negatives clamp to zero
	}
	for d, want := range cases {
		if got := fmtDur(d); got != want {
			t.Errorf("fmtDur(%s) = %q, want %q", d, got, want)
		}
	}
}
