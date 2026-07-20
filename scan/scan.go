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
	"cmp"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/fatih/color"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/d3c3ptive/aims/cmd/display"
	hostmerge "github.com/d3c3ptive/aims/host"
	host "github.com/d3c3ptive/aims/host/pb"
	scan "github.com/d3c3ptive/aims/scan/pb"
	"github.com/d3c3ptive/aims/scan/pb/nmap"
)

// Run - Represents a scan before, after or while being run.
// This run can be the one of any scanner: fields are not mandatorily used
// by all scanners for all scans, but this type gives a common tree in which
// to store hosts, ports, services, statistics and various other information.
//
// The type provides many convenience methods to process all the output of the
// scan, either at once or continuously, or even to refine the objects based on/
// with those already in a database. Therefore, all the methods of this type
// are meant to be used server-side, and not in an implant.
//
// For having similar functionality from within an implant, use the Protobuf
// scan.Run type, which itself has some convenience methods that do NOT need
// any database or its related libraries.
type Run scan.Run

// NewRun - Create a new scan.Run based on a tool (scanner) name, and with an
// optional Options type holding various settings to be customized for your use.
func NewRun(scanner string, args ...string) *Run {
	return &Run{
		Scanner: scanner,
		Args:    strings.Join(args, " "),
	}
}

// ToPB - Get the Protobuf object for the Result.
func (r *Run) ToPB() *scan.Run {
	return (*scan.Run)(r)
}

// Functionality
//
// Return a concurrent spinner/progress bar / interface for progress
// unction to update progress

// when they are needed by the service probing stack used by the scan.
func (r *Run) AddTarget(t *Target) {
}

// InitResult - Instantiate a new result that has the Run UUID in ref.
// The rest of the object can be populated by the user as he wishes.
func (r *Run) InitResult() *Result {
	return &Result{}
}

// AddResult folds one feeder Result into the Run's host tree. The Result is the
// universal adapter output (one {Host, Address, Port, Service, Data} tuple emitted by
// any scanner); AddResult assembles it into a single-host subtree and merges that in
// via the non-destructive fold (see fold.go / DEDUP.md). Calling it twice with the
// same observation is idempotent — the second call merges into the row the first
// created and changes nothing.
//
// If the Result carries Data (a custom scanner's opaque payload), it is preserved as
// a script observation on the port (or host) so nothing is lost; mapping structured
// payloads into the recursive NSE Script/Table/Element tree (jsonToScript, SCAN.md §D)
// is the richer, philosophy-true follow-on.
func (r *Run) AddResult(res *Result) (err error) {
	if res == nil {
		return errors.New("nil result")
	}

	h := res.Host
	if h == nil {
		h = &host.Host{}
	}

	// Address: ensure the Result's address is on the host (identity anchor).
	if res.Address != nil && res.Address.Addr != "" {
		if !hasAddress(h, res.Address.Addr) {
			h.Addresses = append(h.Addresses, res.Address)
		}
	}

	// Port + Service: attach the service to the port, the port to the host.
	if res.Port != nil {
		if res.Service != nil && res.Port.Service == nil {
			res.Port.Service = res.Service
		}
		if !hasPort(h, res.Port) {
			h.Ports = append(h.Ports, res.Port)
		}
	}

	// Opaque Data: keep it as a script observation rather than dropping it.
	if res.Data != "" {
		script := &nmap.Script{Name: "scan.data", Output: res.Data}
		if res.Port != nil && hasPort(h, res.Port) {
			res.Port.Scripts = append(res.Port.Scripts, script)
		} else {
			h.HostScripts = append(h.HostScripts, script)
		}
	}

	r.foldHost(h)

	return nil
}

func hasAddress(h *host.Host, addr string) bool {
	for _, a := range h.Addresses {
		if a != nil && a.Addr == addr {
			return true
		}
	}
	return false
}

func hasPort(h *host.Host, p *host.Port) bool {
	for _, existing := range h.Ports {
		if hostmerge.SamePort(existing, p) {
			return true
		}
	}
	return false
}

//
// [ Run State ] ----------------------------------------------------------
//
// A Run is the one object in the catalog with a live axis — it exists before,
// during and after execution. runState collapses that axis into a single value,
// computed once, that drives every state-dependent bit of presentation (the ID
// colour, the Status column, the detail banner badge). Mirrors how the credential
// domain derives "loot" colouring from one predicate.

type runState int

const (
	stateCreated     runState = iota // persisted stub, no heartbeat yet (rare/transient)
	stateRunning                     // non-final, heartbeat fresh — a live scan is driving it
	stateDone                        // finished, clean exit
	stateFailed                      // finished with a non-success exit or error
	stateInterrupted                 // non-final, heartbeat stale — the owning process died
)

// runStaleAfter bounds how long a non-final run may go without a fresh snapshot before it is judged
// orphaned. A live scan re-persists a snapshot every few seconds (server/scan/run.go heartbeats
// consume), which bumps UpdatedAt; well above that interval, a still-non-final run whose UpdatedAt
// has frozen is one whose owning process died (operator killed the command, teamserver crashed).
const runStaleAfter = 30 * time.Second

// stateOf classifies a run. Finished stats are authoritative for done/failed. For a non-final run,
// UpdatedAt doubles as a liveness heartbeat: fresh means some process is still driving the scan
// (running), stale means it was orphaned (interrupted). Deriving liveness from the heartbeat is
// correct across processes — a `scan list` in another terminal reads the live run's fresh
// UpdatedAt — and self-heals a killed scan with no background sweeper.
func stateOf(r *scan.Run) runState {
	if fin := r.GetStats().GetFinished(); fin != nil && (fin.Time != 0 || fin.TimeStr != "" || fin.Elapsed != 0) {
		if fin.ErrorMsg != "" || (fin.Exit != "" && fin.Exit != "success") {
			return stateFailed
		}
		return stateDone
	}
	// Non-final. A persisted run whose heartbeat (UpdatedAt) has frozen is an orphan — its owning
	// process died mid-scan — regardless of whatever partial progress it had captured; that check
	// comes first so a stale run never reads as running.
	persisted := false
	if ts := r.GetUpdatedAt(); ts != nil && !ts.AsTime().IsZero() {
		persisted = true
		if time.Since(ts.AsTime()) > runStaleAfter {
			return stateInterrupted
		}
	}
	// Task activity (Begin/Progress), or a live persisted run (fresh heartbeat), is running.
	if len(r.GetProgress()) > 0 || len(r.GetBegin()) > 0 || persisted {
		return stateRunning
	}
	return stateCreated // built in memory, never persisted, no task activity
}

// IsRunning reports whether the run is mid-flight — a non-final run with a fresh heartbeat. A killed
// scan goes stale and reads as interrupted (not running), so it no longer blocks destructive
// operations (`scan rm`) the way a perpetually-"running" orphan would.
func IsRunning(r *scan.Run) bool { return stateOf(r) == stateRunning }

// runPercent is the aggregate completion of a running scan: the furthest-along task's percent.
func runPercent(r *scan.Run) float32 {
	var max float32
	for _, p := range r.GetProgress() {
		if p.GetPercent() > max {
			max = p.GetPercent()
		}
	}
	return max
}

// stateToken is the coloured one-word status shown in the list and the detail banner.
func stateToken(r *scan.Run) string {
	switch stateOf(r) {
	case stateDone:
		return color.HiGreenString("✓ done")
	case stateFailed:
		return color.HiRedString("✗ failed")
	case stateRunning:
		if p := runPercent(r); p > 0 {
			return color.HiYellowString("● %.0f%%", p)
		}
		return color.HiYellowString("● running")
	case stateInterrupted:
		return color.RedString("⚠ interrupted")
	default:
		return color.HiBlackString("⋯ queued")
	}
}

//
// [ Display Contracts ] --------------------------------------------------
//

// DisplayHeaders returns all weighted table headers for a table of scans. Weight-1 columns are
// the always-on signal (identity, scanner, live status, host outcome, recency); heavier columns
// shed first on narrow terminals.
func DisplayHeaders() []display.Options {
	return display.Headers().
		Add("ID", 1).
		Add("Scanner", 1).
		Add("Status", 1).
		Add("Hosts", 1).
		Add("When", 1).
		Add("Name", 2).
		Add("Series", 2).
		Add("Targets", 2).
		Add("Args", 2).
		Add("Info", 3).
		Add("Tasks", 3).
		Options()
}

// DisplayDetails is retained only for the c2 agent/channel `show` placeholders, which reuse this
// weighted header set against their own DisplayFields map. Scan's own `show` uses the richer
// Detail renderer (banner + panes + insights + sections); prefer that. Deprecated: do not build on
// this for the scan domain.
func DisplayDetails() []display.Options {
	return display.Headers().
		Add("ID", 1).
		Add("Scanner", 1).
		Add("Name", 1).
		Add("Status", 1).
		Add("Info", 1).
		Add("Hosts", 1).
		Add("Tasks", 1).
		Add("Targets", 1).
		Add("Args", 1).
		Options()
}

// Completions returns the columns combined into completion candidates and their descriptions.
func Completions() []display.Options {
	return display.Headers().
		Add("ID", 1).
		Add("Scanner", 1).
		Add("Status", 1).
		Add("Name", 2).
		Add("Info", 2).
		Add("Args", 3).
		Options()
}

// DisplayFields maps column names to per-run value generators — the single source of truth feeding
// the table and completions. Every accessor is nil-safe (a partially observed run must never
// panic the table), and state-dependent fields route through stateOf so the whole view agrees.
var DisplayFields = map[string]func(r *scan.Run) string{
	"ID": func(r *scan.Run) string {
		id := display.FormatSmallID(r.GetId())
		switch stateOf(r) {
		case stateDone:
			return color.HiGreenString(id)
		case stateFailed:
			return color.HiRedString(id)
		case stateRunning:
			return color.HiYellowString(id)
		case stateInterrupted:
			return color.HiBlackString(id)
		default:
			return id
		}
	},
	"Scanner": func(r *scan.Run) string { return r.GetScanner() },
	"Name":    func(r *scan.Run) string { return r.GetProfileName() },
	"Status":  func(r *scan.Run) string { return stateToken(r) },
	"Info": func(r *scan.Run) string {
		info := r.GetInfo()
		if info == nil {
			return ""
		}
		var parts []string
		if info.Protocol != "" {
			parts = append(parts, info.Protocol)
		}
		if info.Type != "" {
			parts = append(parts, info.Type)
		}
		return strings.Join(parts, "/")
	},
	// Args shows the full command as invoked — the scanner name (the `nmap`/`zgrab` leaf of
	// `aims scan run <scanner> …`) then its arguments — so the column reads as a complete,
	// copy-pasteable command rather than a bare flag list. Scanner is also its own column, but
	// leading the command with it keeps Args self-describing wherever the Scanner column is dropped.
	"Args": func(r *scan.Run) string { return strings.TrimSpace(r.GetScanner() + " " + r.GetArgs()) },
	"Series": func(r *scan.Run) string {
		// On a surviving head, advertise how many earlier runs of the same definition it absorbed.
		if n := r.GetFormerRuns(); n > 0 {
			return color.HiBlackString("+%d", n)
		}
		return ""
	},
	"When":    func(r *scan.Run) string { return whenLabel(r) },
	"Hosts":   func(r *scan.Run) string { return hostsUpDown(r) },
	"Targets": func(r *scan.Run) string { return targetsSummary(r) },
	"Tasks":   func(r *scan.Run) string { return tasksSummary(r) },
}

// SortRuns orders runs for listing: running scans first (most actionable), then interrupted
// (orphaned, likely need attention), then freshly-created, then the rest — each group by
// most-recent activity. Stable, so equal keys keep their read order.
func SortRuns(runs []*scan.Run) {
	slices.SortStableFunc(runs, func(a, b *scan.Run) int {
		if c := cmp.Compare(sortRank(a), sortRank(b)); c != 0 {
			return c
		}
		return cmp.Compare(activityTime(b), activityTime(a)) // newer first
	})
}

func sortRank(r *scan.Run) int {
	switch stateOf(r) {
	case stateRunning:
		return 0
	case stateInterrupted:
		return 1
	case stateCreated:
		return 2
	default:
		return 3
	}
}

// activityTime is the run's most-recent timestamp for recency sorting: finished, else started,
// else created.
func activityTime(r *scan.Run) int64 {
	if fin := r.GetStats().GetFinished(); fin != nil && fin.Time != 0 {
		return fin.Time
	}
	if r.GetStart() != 0 {
		return r.GetStart()
	}
	if ts := r.GetCreatedAt(); ts != nil {
		return ts.AsTime().Unix()
	}
	return 0
}

//
// [ Detail View ] --------------------------------------------------------
//

// DetailOpts selects which trailing sections a detail view includes. They are flag-gated at the
// CLI because each is verbose (task streams, full target lists, the shared-host table) and off by
// default keeps `scan show` scannable.
type DetailOpts struct {
	Tasks   bool // the running/done task tables (the live view)
	Targets bool // the full target list with per-target status/reason
	Hosts   bool // the scanned hosts rendered as a compact table
}

// Detail assembles the full `show` view for a single run: the state banner, the side-by-side info
// panes, derived insights (including the cross-run host-sharing count, which needs the whole set
// `all` to compute), and any flag-selected trailing sections. It hands these to the shared
// display.Detail renderer, so a run's detail view is laid out identically to every other domain's.
func Detail(r *scan.Run, all []*scan.Run, opt DetailOpts) display.Detail {
	return display.Detail{
		Title:    bannerTitle(r),
		Badges:   bannerBadges(r),
		Panes:    infoPanes(r),
		Insights: insights(r, all),
		Sections: sections(r, opt),
	}
}

// bannerTitle is "<scanner> · <profile|args>", bold scanner with a dim-separated qualifier.
func bannerTitle(r *scan.Run) string {
	name := r.GetScanner()
	if name == "" {
		name = "scan"
	}
	title := display.Bold + name + display.Reset
	if p := r.GetProfileName(); p != "" {
		title += display.Dim + " · " + display.Reset + p
	} else if a := r.GetArgs(); a != "" {
		title += display.Dim + " · " + display.Reset + shorten(a, 52)
	}
	return title
}

// bannerBadges are the run's status badges: live state, elapsed time, and the host up/down tally.
func bannerBadges(r *scan.Run) (badges []string) {
	badges = append(badges, stateToken(r))
	if e := elapsedStr(r); e != "" {
		badges = append(badges, color.HiBlackString(e))
	}
	if hs := r.GetStats().GetHosts(); hs != nil && (hs.Up > 0 || hs.Down > 0) {
		badges = append(badges, color.HiGreenString("%d up", hs.Up)+color.HiBlackString("/")+color.HiRedString("%d down", hs.Down))
	}
	return badges
}

// infoPanes groups a run's detail into titled panes (Run / Timing / Scope / Results) for
// side-by-side layout via display.Columns, mirroring the credential and service info views.
func infoPanes(r *scan.Run) []display.Pane {
	run := display.KVLines([][2]string{
		{"Scanner", r.GetScanner()},
		{"Version", r.GetVersion()},
		{"Profile", r.GetProfileName()},
		{"Args", r.GetArgs()},
	})
	timing := display.KVLines([][2]string{
		{"Started", r.GetStartStr()},
		{"Finished", finishedStr(r)},
		{"Elapsed", elapsedStr(r)},
		{"Exit", exitStr(r)},
	})
	info := r.GetInfo()
	scope := display.KVLines([][2]string{
		{"Protocol", info.GetProtocol()},
		{"Type", info.GetType()},
		{"Services", info.GetServices()},
		{"Targets", targetsSummary(r)},
	})
	results := display.KVLines([][2]string{
		{"Hosts", hostsTotal(r)},
		{"ID", display.FormatSmallID(r.GetId())},
		{"Updated", fmtTime(r.GetUpdatedAt())},
	})

	return []display.Pane{
		{Title: "Run", Lines: run},
		{Title: "Timing", Lines: timing},
		{Title: "Scope", Lines: scope},
		{Title: "Results", Lines: results},
	}
}

// insights returns the cross-cutting observations for a single run: how many other runs share its
// hosts (the payoff of cross-run unification), any scanner warnings/errors, the finished summary,
// and — for a live run — the in-progress task tally. `all` is the set the run is viewed within;
// host-sharing cannot be computed from one run alone.
func insights(r *scan.Run, all []*scan.Run) (lines []string) {
	if shared := sharedRunCount(r, all); shared > 0 {
		lines = append(lines, fmt.Sprintf("shares host(s) with %d other run(s)", shared))
	}
	if stateOf(r) == stateRunning {
		running, done := getTasks(r)
		lines = append(lines, fmt.Sprintf("in progress — %d task(s) done, %d running", len(done), len(running)))
	}
	if fin := r.GetStats().GetFinished(); fin != nil {
		if fin.ErrorMsg != "" {
			lines = append(lines, color.HiRedString("✗ ")+fin.ErrorMsg)
		} else if fin.Summary != "" {
			lines = append(lines, color.HiBlackString(fin.Summary))
		}
	}
	for _, e := range r.GetNmapErrors() {
		if strings.TrimSpace(e) != "" {
			lines = append(lines, color.HiYellowString("⚠ ")+e)
		}
	}
	return lines
}

// sharedRunCount counts other runs in `all` that observed at least one of r's (persisted) hosts —
// the cross-run host-row unification made visible. Requires the runs' Hosts to be loaded.
func sharedRunCount(r *scan.Run, all []*scan.Run) int {
	mine := map[string]bool{}
	for _, h := range r.GetHosts() {
		if h.GetId() != "" {
			mine[h.GetId()] = true
		}
	}
	if len(mine) == 0 {
		return 0
	}
	count := 0
	for _, other := range all {
		if other.GetId() == r.GetId() {
			continue
		}
		for _, h := range other.GetHosts() {
			if mine[h.GetId()] {
				count++
				break
			}
		}
	}
	return count
}

// sections builds the flag-selected trailing blocks (empty ones drop out in display.Detail).
func sections(r *scan.Run, opt DetailOpts) (out []display.Section) {
	if opt.Tasks {
		if body := formatTasks(r); strings.TrimSpace(body) != "" {
			out = append(out, display.Section{Title: "Tasks", Body: body})
		}
	}
	if opt.Targets {
		if body := formatTargets(r); strings.TrimSpace(body) != "" {
			out = append(out, display.Section{Title: "Targets", Body: body})
		}
	}
	if opt.Hosts {
		if body := formatHosts(r); strings.TrimSpace(body) != "" {
			out = append(out, display.Section{Title: "Hosts", Body: body})
		}
	}
	return out
}

//
// [ Field Formatters ] ---------------------------------------------------
//

// whenLabel is the run's recency for the list: a live run shows running elapsed, others show a
// relative "N ago" of their most-recent timestamp.
func whenLabel(r *scan.Run) string {
	if stateOf(r) == stateRunning && r.GetStart() != 0 {
		return "running " + shortDur(time.Since(time.Unix(r.GetStart(), 0)))
	}
	if t := activityTime(r); t != 0 {
		return relTime(time.Unix(t, 0))
	}
	return ""
}

// hostsUpDown is the coloured "up/down" tally for the list, from finished stats when present, else
// counted from the loaded hosts.
func hostsUpDown(r *scan.Run) string {
	var up, down int32
	if hs := r.GetStats().GetHosts(); hs != nil {
		up, down = hs.Up, hs.Down
	} else {
		for _, h := range r.GetHosts() {
			if h.GetStatus().GetState() == "up" {
				up++
			} else {
				down++
			}
		}
	}
	if up == 0 && down == 0 {
		return ""
	}
	return color.HiGreenString("%d", up) + "/" + color.HiRedString("%d", down)
}

// hostsTotal is the verbose up/down/total line for the detail Results pane.
func hostsTotal(r *scan.Run) string {
	if hs := r.GetStats().GetHosts(); hs != nil {
		return fmt.Sprintf("%d up / %d down / %d total", hs.Up, hs.Down, hs.Total)
	}
	if n := len(r.GetHosts()); n > 0 {
		return fmt.Sprintf("%d", n)
	}
	return ""
}

// targetsSummary is the compact "services(n) hosts(n)" scope shown in the list and Scope pane.
func targetsSummary(r *scan.Run) string {
	var b strings.Builder
	if n := r.GetInfo().GetNumServices(); n > 0 {
		fmt.Fprintf(&b, "services(%d) ", n)
	}
	if n := len(r.GetTargets()); n > 0 {
		fmt.Fprintf(&b, "hosts(%d)", n)
	}
	return strings.TrimSpace(b.String())
}

// tasksSummary is the "done/total" task count for the list; the running count is highlighted when
// a scan is still executing.
func tasksSummary(r *scan.Run) string {
	running, done := getTasks(r)
	total := len(done) + len(running)
	if total == 0 {
		return ""
	}
	if len(running) > 0 {
		return color.HiYellowString("%d", len(done)) + fmt.Sprintf("/%d", total)
	}
	return fmt.Sprintf("%d/%d", len(done), total)
}

func finishedStr(r *scan.Run) string {
	if fin := r.GetStats().GetFinished(); fin != nil {
		if fin.TimeStr != "" {
			return fin.TimeStr
		}
		if fin.Time != 0 {
			return time.Unix(fin.Time, 0).Format("2006-01-02 15:04")
		}
	}
	return ""
}

func elapsedStr(r *scan.Run) string {
	if fin := r.GetStats().GetFinished(); fin != nil && fin.Elapsed > 0 {
		return shortDur(time.Duration(float64(fin.Elapsed) * float64(time.Second)))
	}
	return ""
}

func exitStr(r *scan.Run) string {
	fin := r.GetStats().GetFinished()
	if fin == nil {
		return ""
	}
	if fin.ErrorMsg != "" {
		return color.HiRedString("%s (%s)", fin.Exit, fin.ErrorMsg)
	}
	return fin.Exit
}

// shorten truncates s to at most max visible runes, adding an ellipsis.
func shorten(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max-1]) + "…"
}

// shortDur renders a duration compactly: "42s", "3m07s", "1h05m".
func shortDur(d time.Duration) string {
	d = d.Round(time.Second)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm%02ds", int(d.Minutes()), int(d.Seconds())%60)
	default:
		return fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
	}
}

// relTime renders a past time as a coarse "N ago".
func relTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	d := time.Since(t)
	switch {
	case d < 0:
		return t.Format("2006-01-02 15:04")
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours())/24)
	}
}

func fmtTime(t *timestamppb.Timestamp) string {
	if t == nil {
		return ""
	}
	tt := t.AsTime()
	if tt.IsZero() {
		return ""
	}
	return tt.Format("2006-01-02 15:04")
}

//
// [ Section Bodies ] -----------------------------------------------------
//

// formatTargets renders the run's target list with each target's status/reason, for the Targets
// section of the detail view.
func formatTargets(r *scan.Run) string {
	if len(r.GetTargets()) == 0 {
		return ""
	}
	var b strings.Builder
	for _, t := range r.GetTargets() {
		spec := t.GetSpecification()
		if spec == "" {
			spec = t.GetAddress()
		}
		if spec == "" {
			continue
		}
		line := "\n  " + spec
		if t.GetPort() != 0 {
			line += fmt.Sprintf(":%d", t.GetPort())
		}
		if st := t.GetStatus(); st != "" {
			suffix := st
			if rsn := t.GetReason(); rsn != "" {
				suffix += ": " + rsn
			}
			line += " " + display.Dim + "[" + suffix + "]" + display.Reset
		}
		b.WriteString(line)
	}
	return b.String()
}

// formatHosts renders the run's scanned hosts as a compact table, reusing the host domain's own
// display contract so the table matches `hosts list`.
func formatHosts(r *scan.Run) string {
	if len(r.GetHosts()) == 0 {
		return ""
	}
	table := display.Table(r.GetHosts(), hostmerge.DisplayFields, hostmerge.DisplayHeaders()...)
	return "\n" + table.Render()
}

// formatTasks renders the run's task streams as up to two tables — running (progress) and done —
// for the Tasks section. This is the live view of an in-flight scan.
func formatTasks(r *scan.Run) string {
	var out string
	running, done := getTasks(r)

	if len(running) > 0 {
		table := display.Table(running, tasksProgressFields, tasksProgressHeaders()...)
		table.SetTitle("%s", "\n"+color.HiYellowString("Running tasks"))
		out += table.Render()
	}
	if len(done) > 0 {
		table := display.Table(done, tasksFields, tasksHeaders()...)
		table.SetTitle("%s", "\n"+color.HiYellowString("Done tasks"))
		out += table.Render()
	}
	return out
}

// getTasks splits a run's task records into the still-running (latest progress per task, minus any
// that have since ended) and the done (ended) tasks, each sorted by time.
func getTasks(r *scan.Run) (running []*scan.TaskProgress, done []*scan.ScanTask) {
	done = append(done, r.GetEnd()...)
	slices.SortFunc(done, func(a, b *scan.ScanTask) int {
		return cmp.Compare(a.GetTime(), b.GetTime())
	})

	// A task that has an End record is finished, even if it also has progress records.
	ended := make(map[string]bool, len(done))
	for _, t := range done {
		ended[t.GetTask()] = true
	}

	// Keep only the furthest-along progress record per still-running task name.
	latest := map[string]*scan.TaskProgress{}
	for _, p := range r.GetProgress() {
		if ended[p.GetTask()] {
			continue
		}
		if cur, ok := latest[p.GetTask()]; !ok || p.GetPercent() >= cur.GetPercent() {
			latest[p.GetTask()] = p
		}
	}
	for _, p := range latest {
		running = append(running, p)
	}
	slices.SortFunc(running, func(a, b *scan.TaskProgress) int {
		return cmp.Compare(a.GetTime(), b.GetTime())
	})

	return running, done
}

func tasksHeaders() []display.Options {
	return display.Headers().
		Add("Time", 1).
		Add("Name", 1).
		Add("Info", 1).
		Options()
}

var tasksFields = map[string]func(h *scan.ScanTask) string{
	"Time": func(t *scan.ScanTask) string {
		return color.HiBlackString(time.Unix(t.GetTime(), 0).Format("15:04:05"))
	},
	"Name": func(t *scan.ScanTask) string { return t.GetTask() },
	"Info": func(t *scan.ScanTask) string { return t.GetExtraInfo() },
}

func tasksProgressHeaders() []display.Options {
	return display.Headers().
		Add("Time", 1).
		Add("Name", 1).
		Add("Percent", 1).
		Options()
}

var tasksProgressFields = map[string]func(h *scan.TaskProgress) string{
	"Name": func(t *scan.TaskProgress) string { return t.GetTask() },
	"Time": func(t *scan.TaskProgress) string {
		return color.HiBlackString(time.Unix(t.GetTime(), 0).Format("15:04:05"))
	},
	"Percent": func(t *scan.TaskProgress) string {
		return color.HiYellowString("%.0f%%", t.GetPercent())
	},
}
