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
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/fatih/color"
	"golang.org/x/term"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	aims "github.com/d3c3ptive/aims/cmd"
	"github.com/d3c3ptive/aims/cmd/display"
	hostdomain "github.com/d3c3ptive/aims/host"
	hostpb "github.com/d3c3ptive/aims/host/pb"
	scandom "github.com/d3c3ptive/aims/scan"
	scanpb "github.com/d3c3ptive/aims/scan/pb"
	scans "github.com/d3c3ptive/aims/scan/pb/rpc"
)

// finalInterrupted reports whether a terminal run was deliberately stopped (interrupted) rather than
// run to completion, so the live views can show the right terminal word instead of a false "done".
func finalInterrupted(r *scanpb.Run) bool {
	return r.GetStats().GetFinished().GetExit() == scandom.ExitInterrupted
}

// finalFailed reports whether a terminal run FAILED — the scanner errored after launching (e.g. nmap
// "requires root privileges. QUITTING!"), stamped Exit="error"/ErrorMsg by the server. Without this
// the live views would render a failed scan as a green "✓ done" over zero hosts, the client-side face
// of the same bug the server fold fixes. Mirrors scan.stateOf's failed rule; interrupted is not a
// failure and is excluded.
func finalFailed(r *scanpb.Run) bool {
	fin := r.GetStats().GetFinished()
	if fin.GetExit() == scandom.ExitInterrupted {
		return false
	}
	return fin.GetErrorMsg() != "" || (fin.GetExit() != "" && fin.GetExit() != ExitSuccess)
}

// failureReason is the human message for a failed run: the scanner's errormsg, else a bare fallback.
// Empty for a run that did not fail, so callers can branch on it.
func failureReason(r *scanpb.Run) string {
	if !finalFailed(r) {
		return ""
	}
	if msg := r.GetStats().GetFinished().GetErrorMsg(); msg != "" {
		return msg
	}
	return "scan failed"
}

// updateReceiver is the common receive side of the Run and Attach client streams, so one set of
// renderers serves both `scan run` and `scan attach`.
type updateReceiver interface {
	Recv() (*scans.RunUpdate, error)
}

// streamOpts selects how a live scan stream is rendered. scanner/args are known client-side (they
// are not on the wire) and only decorate the dashboard header; the three booleans pick the mode.
type streamOpts struct {
	scanner    string
	args       []string
	background bool
	quiet      bool
	json       bool
}

// renderScan consumes a Run/Attach stream and renders it per opts. Mode precedence: machine formats
// first (--json, then --quiet), then --background (submit-and-return), then the interactive
// dashboard when stdout is a TTY, else a plain line log (pipes, CI, `| tee`).
func renderScan(stream updateReceiver, opts streamOpts) error {
	switch {
	case opts.json:
		return jsonStream(stream, opts)
	case opts.quiet:
		return quietStream(stream, opts)
	case opts.background:
		return backgroundStream(stream)
	case isTTY(os.Stdout):
		return dashboardStream(stream, opts)
	default:
		return lineStream(stream)
	}
}

// isTTY reports whether f is a terminal (so the dashboard can degrade to a line log when piped).
func isTTY(f *os.File) bool { return term.IsTerminal(int(f.Fd())) }

// -------------------------------------------------------------------------------------------------
// Interactive dashboard (default when stdout is a TTY)
// -------------------------------------------------------------------------------------------------

// dashboard is a fixed, in-place region redrawn on every frame: a header (job + command), a progress
// bar with task/ETA/elapsed, and a growing table of hosts as they are found. It uses only cursor-up
// + clear-line escapes (no new dependency), and every emitted line is clipped to the terminal width
// so nothing wraps and the redraw line-count stays exact.
type dashboard struct {
	w     io.Writer
	width int
	opts  streamOpts
	start time.Time

	jobID       string
	task        string
	pct         float64
	eta         time.Duration
	hosts       []hostRow
	warnings    []string // most-recent live scanner notices (capped), oldest first
	warnCount   int      // total notices seen (so the footer can say how many were elided)
	done        bool
	interrupted bool
	failed      bool
	reason      string
	stored      int

	prev int // lines emitted by the last render (how far to move the cursor up)
}

// maxWarnings bounds how many recent notice lines the dashboard keeps on screen — enough to show a
// full NSE traceback (which spans several lines) without letting a chatty scan push the host table
// off the terminal.
const maxWarnings = 8

func dashboardStream(stream updateReceiver, opts streamOpts) error {
	d := &dashboard{w: os.Stdout, opts: opts, start: time.Now()}
	d.resize()

	// Receive frames in a goroutine so the render loop can ALSO repaint on a 1s timer. Without this
	// the loop blocks on stream.Recv(), and a scan that goes quiet between frames (nmap can pause many
	// seconds between progress ticks) would freeze the elapsed clock and look completely hung. The
	// channel is buffered so the receiver never blocks handing off its final frame after we return.
	type recv struct {
		u   *scans.RunUpdate
		err error
	}
	updates := make(chan recv, 1)
	go func() {
		for {
			u, err := stream.Recv()
			updates <- recv{u, err}
			if err != nil {
				return
			}
		}
	}()

	tick := time.NewTicker(time.Second)
	defer tick.Stop()

	for {
		var update *scans.RunUpdate
		select {
		case <-tick.C:
			// Repaint on the timer so elapsed keeps advancing and the view stays alive between frames.
			d.resize()
			d.render()
			continue
		case r := <-updates:
			if r.err == io.EOF {
				d.render()
				return nil
			}
			if r.err != nil {
				if status.Code(r.err) == codes.Canceled || errors.Is(r.err, context.Canceled) {
					d.render()
					fmt.Fprintln(d.w, display.Dim+"Detached; the scan keeps running (see `scan jobs`)."+display.Reset)
					return nil
				}
				return aims.CheckError(r.err)
			}
			update = r.u
		}

		switch u := update.GetUpdate().(type) {
		case *scans.RunUpdate_JobId:
			d.jobID = u.JobId
		case *scans.RunUpdate_Progress:
			p := u.Progress
			d.task = p.GetTask()
			d.pct = float64(p.GetPercent())
			d.eta = etaOf(p)
		case *scans.RunUpdate_Host:
			d.hosts = append(d.hosts, hostSummary(u.Host))
		case *scans.RunUpdate_Warning:
			d.warnCount++
			d.warnings = append(d.warnings, u.Warning)
			if len(d.warnings) > maxWarnings {
				d.warnings = d.warnings[len(d.warnings)-maxWarnings:]
			}
		case *scans.RunUpdate_Final:
			d.done = true
			d.interrupted = finalInterrupted(u.Final)
			d.failed = finalFailed(u.Final)
			d.reason = failureReason(u.Final)
			if !d.interrupted && !d.failed {
				d.pct = 100 // a stopped or failed scan keeps the percent it reached, not a false 100%
			}
			d.stored = len(u.Final.GetHosts())
			d.jobID = u.Final.GetId()
			d.render()
			return nil
		case *scans.RunUpdate_Error:
			d.render()
			return fmt.Errorf("scan error: %s", u.Error)
		}

		d.resize()
		d.render()
	}
}

func (d *dashboard) resize() {
	d.width = 100
	if w, _, err := term.GetSize(int(os.Stdout.Fd())); err == nil && w > 0 {
		d.width = w
	}
}

// render redraws the region in place: move the cursor up over the previous block, then clear-and-
// print each line. The block only ever grows (hosts accumulate), so moving up by the previous count
// always lands on its first line.
func (d *dashboard) render() {
	lines := d.lines()
	var b strings.Builder
	if d.prev > 0 {
		fmt.Fprintf(&b, "\x1b[%dA", d.prev)
	}
	for _, ln := range lines {
		b.WriteString("\x1b[2K") // clear the whole line before reprinting
		b.WriteString(ln)
		b.WriteString("\n")
	}
	fmt.Fprint(d.w, b.String())
	d.prev = len(lines)
}

func (d *dashboard) lines() []string {
	var out []string

	// Header: "scan <id> · nmap -sT -p... ".
	id := d.jobID
	if id != "" {
		id = display.FormatSmallID(id)
	}
	head := "scan " + id
	if d.opts.scanner != "" {
		head += " · " + strings.TrimSpace(d.opts.scanner+" "+strings.Join(d.opts.args, " "))
	}
	out = append(out, display.Dim+head+display.Reset)

	// Progress: bar + percent + (task / ETA while running | ✓ done) + elapsed.
	barW := d.width - 40
	if barW > 28 {
		barW = 28
	}
	if barW < 8 {
		barW = 8
	}
	prog := bar(d.pct, barW) + fmt.Sprintf(" %5.1f%%", d.pct)
	if d.done {
		switch {
		case d.failed:
			prog += "  " + color.RedString("✗ failed")
		case d.interrupted:
			prog += "  " + color.RedString("⚠ interrupted")
		default:
			prog += "  " + color.GreenString("✓ done")
		}
	} else {
		if d.task != "" {
			prog += "  " + color.YellowString(d.task)
		}
		if d.eta > 0 {
			prog += "  ETA " + fmtDur(d.eta)
		}
	}
	prog += "  elapsed " + fmtDur(time.Since(d.start))
	out = append(out, prog)

	// Hosts table (only once at least one host has landed).
	if len(d.hosts) > 0 {
		out = append(out, "")
		out = append(out, display.Dim+hostTableHeader()+display.Reset)
		for _, h := range d.hosts {
			out = append(out, hostRowLine(h))
		}
	}

	// Live notices: the most recent scanner stderr lines (warnings/notices), so a long scan that is
	// plainly busy is not shown as silent. Warnings are amber, other notices dim; the raw text is
	// always kept. A header notes how many were elided when the scan is chatty.
	if len(d.warnings) > 0 {
		out = append(out, "")
		hdr := display.Dim + "notices" + display.Reset
		if d.warnCount > len(d.warnings) {
			hdr = display.Dim + fmt.Sprintf("notices (latest %d of %d)", len(d.warnings), d.warnCount) + display.Reset
		}
		out = append(out, hdr)
		for _, w := range d.warnings {
			out = append(out, clipVisible("  "+noticeLine(w), d.width))
		}
	}

	// Footer: live count of up hosts, or the terminal summary once done. A failed run shows its
	// reason in red instead of a host count — "0 host(s) stored" would read like a clean empty scan.
	if d.done && d.failed {
		out = append(out, color.RedString("── ✗ %s ──", d.reason))
	} else {
		var foot string
		if d.done {
			verb := "stored"
			if d.interrupted {
				verb = "stored (interrupted)"
			}
			foot = fmt.Sprintf("── %d host(s) %s · elapsed %s ──", d.stored, verb, fmtDur(time.Since(d.start)))
		} else {
			up := 0
			for _, h := range d.hosts {
				if h.state == hostdomain.StateUp {
					up++
				}
			}
			foot = fmt.Sprintf("── %d host(s) up ──", up)
		}
		out = append(out, display.Dim+foot+display.Reset)
	}

	for i := range out {
		out[i] = clipVisible(out[i], d.width)
	}
	return out
}

// hostRow is one line of the live hosts table.
type hostRow struct {
	label    string
	name     string
	state    string
	os       string
	open     int
	services string
}

// hostSummary condenses a streamed host into a table row: its address, first hostname, up/down
// state, OS guess, open-port count, and the first handful of open service names.
func hostSummary(h *hostpb.Host) hostRow {
	label := "?"
	if len(h.GetAddresses()) > 0 && h.GetAddresses()[0].GetAddr() != "" {
		label = h.GetAddresses()[0].GetAddr()
	} else if len(h.GetHostnames()) > 0 {
		label = h.GetHostnames()[0].GetName()
	}
	name := ""
	if len(h.GetHostnames()) > 0 && h.GetHostnames()[0].GetName() != label {
		name = h.GetHostnames()[0].GetName()
	}
	state := h.GetStatus().GetState()
	if state == "" {
		state = "?"
	}

	ports := h.GetPorts()
	sort.SliceStable(ports, func(i, j int) bool { return ports[i].GetNumber() < ports[j].GetNumber() })
	open := 0
	var svcs []string
	for _, p := range ports {
		if p.GetState().GetState() != hostdomain.PortOpen {
			continue
		}
		open++
		name := p.GetService().GetName()
		if name == "" {
			name = fmt.Sprintf("%d", p.GetNumber())
		}
		if len(svcs) < 6 {
			svcs = append(svcs, name)
		}
	}
	return hostRow{label: label, name: name, state: state, os: osLabel(h), open: open, services: strings.Join(svcs, " · ")}
}

// osLabel is a short OS guess for the host table: the derived OS family, else the top OS match name.
func osLabel(h *hostpb.Host) string {
	if fam := h.GetOSFamily(); fam != "" {
		return fam
	}
	if os := h.GetOS(); os != nil && len(os.GetMatches()) > 0 {
		return os.GetMatches()[0].GetName()
	}
	return ""
}

// hostTableCols are the fixed column widths of the live hosts table (services take the remainder).
const (
	colHost  = 18
	colName  = 16
	colState = 5
	colOS    = 14
	colOpen  = 4
)

func hostTableHeader() string {
	return "  " + padRight("HOST", colHost) + " " + padRight("NAME", colName) + " " +
		padRight("STATE", colState) + " " + padRight("OS", colOS) + " " + padRight("OPEN", colOpen) + " SERVICES"
}

func hostRowLine(h hostRow) string {
	st := padRight(h.state, colState)
	switch h.state {
	case hostdomain.StateUp:
		st = color.GreenString(st)
	case hostdomain.StateDown:
		st = color.RedString(st)
	default:
		st = color.YellowString(st)
	}
	return "  " + padRight(h.label, colHost) + " " + padRight(h.name, colName) + " " + st + " " +
		padRight(h.os, colOS) + " " + padRight(fmt.Sprintf("%d", h.open), colOpen) + " " + h.services
}

// -------------------------------------------------------------------------------------------------
// Non-interactive renderers
// -------------------------------------------------------------------------------------------------

// jsonStream emits every frame as one line of JSON (ndjson) for piping into jq/files. Ends after the
// JobId frame in --background mode, else after the Final/Error frame.
func jsonStream(stream updateReceiver, opts streamOpts) error {
	m := protojson.MarshalOptions{}
	for {
		update, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			if status.Code(err) == codes.Canceled || errors.Is(err, context.Canceled) {
				return nil
			}
			return aims.CheckError(err)
		}
		b, mErr := m.Marshal(update)
		if mErr != nil {
			return mErr
		}
		fmt.Println(string(b))
		switch update.GetUpdate().(type) {
		case *scans.RunUpdate_JobId:
			if opts.background {
				return nil
			}
		case *scans.RunUpdate_Final, *scans.RunUpdate_Error:
			return nil
		}
	}
}

// quietStream suppresses progress/hosts and prints only the final one-liner (or the background job
// id, or a fatal error).
func quietStream(stream updateReceiver, opts streamOpts) error {
	for {
		update, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			if status.Code(err) == codes.Canceled || errors.Is(err, context.Canceled) {
				return nil
			}
			return aims.CheckError(err)
		}
		switch u := update.GetUpdate().(type) {
		case *scans.RunUpdate_JobId:
			if opts.background {
				fmt.Printf("Scan job %s started (running in background).\n", display.FormatSmallID(u.JobId))
				return nil
			}
		case *scans.RunUpdate_Final:
			printFinal(u.Final)
			return nil
		case *scans.RunUpdate_Error:
			return fmt.Errorf("scan error: %s", u.Error)
		}
	}
}

// finalVerb is the terminal-frame headline word: a failed scan is "Scan failed", a stopped one
// "Scan interrupted", a clean one "Scan complete".
func finalVerb(r *scanpb.Run) string {
	switch {
	case finalFailed(r):
		return "Scan failed"
	case finalInterrupted(r):
		return "Scan interrupted"
	default:
		return "Scan complete"
	}
}

// printFinal writes the one-line terminal summary shared by the quiet and line renderers: a failed
// run reports its reason (not a misleading "0 host(s) stored"), every other outcome its stored count.
func printFinal(r *scanpb.Run) {
	if reason := failureReason(r); reason != "" {
		fmt.Printf("%s: %s — %s\n", finalVerb(r), display.FormatSmallID(r.GetId()), reason)
		return
	}
	fmt.Printf("%s: %s — %d host(s) stored.\n", finalVerb(r), display.FormatSmallID(r.GetId()), len(r.GetHosts()))
}

// backgroundStream reads until the JobId frame, prints it, and returns (the job keeps running
// server-side).
func backgroundStream(stream updateReceiver) error {
	for {
		update, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			if status.Code(err) == codes.Canceled || errors.Is(err, context.Canceled) {
				return nil
			}
			return aims.CheckError(err)
		}
		switch u := update.GetUpdate().(type) {
		case *scans.RunUpdate_JobId:
			fmt.Printf("Scan job %s started (running in background).\n", display.FormatSmallID(u.JobId))
			return nil
		case *scans.RunUpdate_Error:
			return fmt.Errorf("scan error: %s", u.Error)
		}
	}
}

// lineStream is the plain fallback for non-TTY stdout (pipes, CI): no cursor tricks, one line per
// host found plus the final summary. Progress ticks are dropped (they are noise in a log).
func lineStream(stream updateReceiver) error {
	for {
		update, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			if status.Code(err) == codes.Canceled || errors.Is(err, context.Canceled) {
				fmt.Println("Detached; the scan keeps running (see `scan jobs`).")
				return nil
			}
			return aims.CheckError(err)
		}
		switch u := update.GetUpdate().(type) {
		case *scans.RunUpdate_JobId:
			fmt.Printf("Scan job %s started.\n", display.FormatSmallID(u.JobId))
		case *scans.RunUpdate_Host:
			h := hostSummary(u.Host)
			line := "[+] " + h.label
			if h.name != "" {
				line += " (" + h.name + ")"
			}
			if h.os != "" {
				line += "  " + h.os
			}
			line += fmt.Sprintf("  %d open", h.open)
			if h.services != "" {
				line += ": " + h.services
			}
			fmt.Println(line)
		case *scans.RunUpdate_Warning:
			fmt.Println("[!] " + u.Warning)
		case *scans.RunUpdate_Final:
			printFinal(u.Final)
			return nil
		case *scans.RunUpdate_Error:
			return fmt.Errorf("scan error: %s", u.Error)
		}
	}
}

// -------------------------------------------------------------------------------------------------
// Small rendering helpers
// -------------------------------------------------------------------------------------------------

// etaOf derives a remaining duration from a progress frame: nmap's `remaining` seconds if present,
// else the gap to its estimated-completion timestamp (`etc`).
func etaOf(p *scanpb.TaskProgress) time.Duration {
	if r := p.GetRemaining(); r > 0 {
		return time.Duration(r) * time.Second
	}
	if e := p.GetEtc(); e > 0 {
		if d := time.Until(time.Unix(e, 0)); d > 0 {
			return d
		}
	}
	return 0
}

// bar renders a w-wide progress bar: filled blocks then dimmed empties, bracketed by ▕ ▏.
func bar(pct float64, w int) string {
	if w < 1 {
		w = 1
	}
	fill := int(pct/100*float64(w) + 0.5)
	if fill < 0 {
		fill = 0
	}
	if fill > w {
		fill = w
	}
	return "▕" + strings.Repeat("█", fill) + display.Dim + strings.Repeat("░", w-fill) + display.Reset + "▏"
}

// fmtDur formats a duration as M:SS.
func fmtDur(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	total := int(d.Seconds())
	return fmt.Sprintf("%d:%02d", total/60, total%60)
}

// noticeLine colours one raw scanner notice by a light, robust severity read — the only typing
// nmap's free-text stderr reliably supports (see the investigation): a "Warning:"/"WARNING:" line
// is amber, everything else (bare notices, NSE traceback lines) is dim. The raw text is never
// altered, only coloured, so nothing is lost to a misclassification.
func noticeLine(raw string) string {
	if warningPrefixRE.MatchString(raw) {
		return color.YellowString(raw)
	}
	return display.Dim + raw + display.Reset
}

// warningPrefixRE matches nmap's/masscan's warning prefix in either case.
var warningPrefixRE = regexp.MustCompile(`(?i)^\s*warning:`)

// clipPlain truncates a plain (escape-free) string to n runes, marking a cut with an ellipsis.
func clipPlain(s string, n int) string {
	if n <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n == 1 {
		return "…"
	}
	return string(r[:n-1]) + "…"
}

// padRight clips s to n runes then right-pads with spaces to width n.
func padRight(s string, n int) string {
	s = clipPlain(s, n)
	if l := utf8.RuneCountInString(s); l < n {
		return s + strings.Repeat(" ", n-l)
	}
	return s
}

// clipVisible truncates a possibly-ANSI-colored string to max VISIBLE columns, copying escape
// sequences verbatim (they cost no width) so the dashboard's lines never wrap and the redraw
// line-count stays exact. A truncated line is closed with a reset.
func clipVisible(s string, max int) string {
	if max <= 0 {
		return ""
	}
	var b strings.Builder
	visible := 0
	truncated := false
	for i := 0; i < len(s); {
		if s[i] == 0x1b { // ESC: copy the whole CSI sequence unchanged (it costs no columns)
			j := i + 1
			if j < len(s) && s[j] == '[' {
				j++
				for j < len(s) && (s[j] < 0x40 || s[j] > 0x7e) { // params, until the final byte
					j++
				}
				if j < len(s) {
					j++ // include the final byte (m, K, A, …)
				}
			}
			b.WriteString(s[i:j])
			i = j
			continue
		}
		if visible >= max {
			truncated = true
			break
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		b.WriteRune(r)
		visible++
		i += size
	}
	if truncated {
		b.WriteString(display.Reset)
	}
	return b.String()
}
