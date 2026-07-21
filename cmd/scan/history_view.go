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
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/fatih/color"

	hostdomain "github.com/d3c3ptive/aims/host"
	"github.com/d3c3ptive/aims/scan"
)

// renderSeriesHistory renders a series' evolution: a header (the command + cadence), a newest-first
// drift timeline (each run's change vs the previous, unchanged runs collapsed), and a stability
// panel classifying every port ever seen across the series. It reuses the scan domain's own
// state-coloured ID/When formatters so a run reads the same as it does in `scan list`.
func renderSeriesHistory(h scan.SeriesHistory) string {
	if len(h.Runs) == 0 {
		return "empty series"
	}
	var b strings.Builder
	newest := h.Runs[len(h.Runs)-1]

	// Header: full command · N runs over span · cadence · last.
	cmd := strings.TrimSpace(newest.GetScanner() + " " + newest.GetArgs())
	fmt.Fprint(&b, color.New(color.Bold).Sprint(cmd))
	meta := []string{fmt.Sprintf("%d runs", len(h.Runs))}
	if h.Span > 0 {
		meta = append(meta, "over "+histDur(time.Duration(h.Span)*time.Second))
	}
	if h.Cadence > 0 {
		meta = append(meta, "~every "+histDur(time.Duration(h.Cadence)*time.Second))
	}
	if w := scan.DisplayFields["When"](newest); w != "" {
		meta = append(meta, "last "+w)
	}
	fmt.Fprintf(&b, "   %s\n", color.HiBlackString(strings.Join(meta, " · ")))

	// Drift timeline (newest first) — one line per run: id, when, then the change tokens inline.
	fmt.Fprintf(&b, "\n%s\n", color.New(color.Bold).Sprint("Drift"))
	for _, e := range h.Timeline {
		if e.Unchanged > 0 {
			fmt.Fprintf(&b, "  %s   %s\n", color.HiBlackString("⋯"), color.HiBlackString("×%d unchanged", e.Unchanged))
			continue
		}
		id := scan.DisplayFields["ID"](e.Run)
		when := padVisible(scan.DisplayFields["When"](e.Run), 9)
		change := color.HiBlackString("baseline")
		if e.Delta != nil {
			change = compactDelta(e.Summary)
		}
		fmt.Fprintf(&b, "  %s  %s  %s\n", id, when, change)
	}

	// Stability panel.
	if len(h.Surface) > 0 {
		fmt.Fprintf(&b, "\n%s\n", color.New(color.Bold).Sprint("Attack surface"))
		for _, ps := range h.Surface {
			portCol := fmt.Sprintf("%d/%s", ps.Port, ps.Proto)
			fmt.Fprintf(&b, "  %-15s %-9s %-16s %s  %-8s %s\n",
				ps.Addr, portCol, truncate(ps.Service, 16),
				colorSpark(ps.Class, ps.Sparkline()), classLabel(ps.Class), ps.Ratio())
		}
	}

	return b.String()
}

// compactDelta joins a run's change tokens onto one line, coloured by marker, capped so a busy run
// stays a glance.
func compactDelta(summary []string) string {
	const max = 5
	var parts []string
	for i, s := range summary {
		if i == max {
			parts = append(parts, color.HiBlackString("…+%d", len(summary)-max))
			break
		}
		parts = append(parts, colorChange(s))
	}
	return strings.Join(parts, "   ")
}

// padVisible right-pads s to n visible columns (ANSI-agnostic; here s is plain).
func padVisible(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// histDur renders a duration compactly for the history header ("42s", "3m", "1h05m").
func histDur(d time.Duration) string {
	d = d.Round(time.Second)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	default:
		return fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
	}
}

var stateCountRE = regexp.MustCompile(`(\d+) (open|filtered|closed)`)

// colorChange tints a drift summary token. The leading marker sets the base colour (added green,
// removed red, changed yellow); inside a port digest like "(1 open, 307 closed)" each state count is
// tinted on its own — open green, filtered yellow, closed dim — so the port picture reads at a glance
// rather than as one flat block.
func colorChange(line string) string {
	m := marker(line)
	if i := strings.Index(line, "("); i >= 0 && strings.HasSuffix(line, ")") {
		return tint(m, line[:i]) + colorStates(line[i:])
	}
	return tint(m, line)
}

// tint applies the change-direction colour to a fragment.
func tint(m byte, s string) string {
	switch m {
	case '+':
		return color.HiGreenString("%s", s)
	case '-':
		return color.HiRedString("%s", s)
	case '~':
		return color.HiYellowString("%s", s)
	default:
		return s
	}
}

// colorStates tints each "N open|filtered|closed" count inside a port digest by state.
func colorStates(digest string) string {
	return stateCountRE.ReplaceAllStringFunc(digest, func(m string) string {
		sub := stateCountRE.FindStringSubmatch(m)
		switch sub[2] {
		case hostdomain.PortOpen:
			return color.HiGreenString("%s open", sub[1])
		case hostdomain.PortFiltered:
			return color.HiYellowString("%s filtered", sub[1])
		default: // closed
			return color.HiBlackString("%s closed", sub[1])
		}
	})
}

func marker(line string) byte {
	t := strings.TrimSpace(line)
	if t == "" {
		return 0
	}
	return t[0]
}

// classLabel is the coloured stability word shown in the surface panel.
func classLabel(c scan.Stability) string {
	switch c {
	case scan.Stable:
		return color.HiGreenString("stable")
	case scan.Emerging:
		return color.HiCyanString("emerging")
	case scan.Receding:
		return color.HiRedString("receding")
	default:
		return color.HiYellowString("flapping")
	}
}

// colorSpark tints a presence sparkline to match its stability class.
func colorSpark(c scan.Stability, spark string) string {
	switch c {
	case scan.Stable:
		return color.HiGreenString("%s", spark)
	case scan.Emerging:
		return color.HiCyanString("%s", spark)
	case scan.Receding:
		return color.HiRedString("%s", spark)
	default:
		return color.HiYellowString("%s", spark)
	}
}
