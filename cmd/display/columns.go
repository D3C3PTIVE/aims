package display

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
	"strings"

	"github.com/fatih/color"
)

// KVLines renders key/value pairs into aligned "key : value" detail lines: the key subdued (cyan)
// and right-aligned to the widest *shown* key, a dim " : " separator, then the value (which keeps
// its own colour). Pairs whose value is empty are skipped entirely, so callers can pass a fixed
// field list and let absent fields drop out. This is the shared line renderer behind the
// side-by-side info panes (see Pane / Columns), so every domain's detail view colours keys alike.
func KVLines(pairs [][2]string) (lines []string) {
	max := 0
	for _, p := range pairs {
		if strings.TrimSpace(p[1]) != "" && len(p[0]) > max {
			max = len(p[0])
		}
	}
	for _, p := range pairs {
		if strings.TrimSpace(p[1]) == "" {
			continue
		}
		name := fmt.Sprintf("%*s", max, p[0])
		lines = append(lines, color.CyanString(name)+color.HiBlackString(" : ")+p[1])
	}
	return lines
}

// Pane is a titled block of pre-rendered content lines, laid out side by side with other panes
// by Columns. Lines may already contain ANSI colour/style; alignment accounts for that.
type Pane struct {
	Title string   // optional heading, rendered bold above Lines
	Lines []string // content lines, already formatted
}

// VisibleWidth returns the number of visible columns a string occupies, ignoring ANSI SGR escape
// sequences (colour/style) and counting each remaining rune as one column. This is what makes
// column alignment correct for coloured content.
func VisibleWidth(s string) int {
	n, inEsc := 0, false
	for _, r := range s {
		switch {
		case r == '\x1b':
			inEsc = true
		case inEsc:
			if r == 'm' {
				inEsc = false
			}
		default:
			n++
		}
	}
	return n
}

// StripANSI removes ANSI SGR escape sequences (colour/style) from a string, returning plain text.
// Used to sanitize values destined for completion candidates/descriptions, which must be plain so
// they don't bleed colour or get inserted verbatim into the command line.
func StripANSI(s string) string {
	if !strings.ContainsRune(s, '\x1b') {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	inEsc := false
	for _, r := range s {
		switch {
		case r == '\x1b':
			inEsc = true
		case inEsc:
			if r == 'm' {
				inEsc = false
			}
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// padVisible right-pads s with spaces to w visible columns.
func padVisible(s string, w int) string {
	if d := w - VisibleWidth(s); d > 0 {
		return s + strings.Repeat(" ", d)
	}
	return s
}

// Columns arranges panes side by side, packing as many as fit within width (0 = detect the
// terminal), then wrapping to a new band below. A pane is never split; each is padded to its own
// widest line, and gap spaces separate adjacent panes. Layout is display-width aware, so ANSI
// escapes don't throw off alignment. This is the reusable primitive for "categories as columns"
// detail views (e.g. Identity | Provenance | Classification).
func Columns(width, gap int, panes ...Pane) string {
	if len(panes) == 0 {
		return ""
	}
	if width <= 0 {
		width, _ = terminalSize()
	}
	if gap < 1 {
		gap = 1
	}

	// Measure each pane's column width (widest of its title and lines).
	widths := make([]int, len(panes))
	for i, p := range panes {
		w := VisibleWidth(p.Title)
		for _, l := range p.Lines {
			if lw := VisibleWidth(l); lw > w {
				w = lw
			}
		}
		widths[i] = w
	}

	sep := strings.Repeat(" ", gap)
	var out strings.Builder

	for i := 0; i < len(panes); {
		// Greedily pack a band of panes that fit within width (always at least one).
		j, used := i, 0
		for j < len(panes) {
			need := widths[j]
			if j > i {
				need += gap
			}
			if used+need > width && j > i {
				break
			}
			used += need
			j++
		}

		band, bandW := panes[i:j], widths[i:j]

		hasTitle, height := false, 0
		for _, p := range band {
			if p.Title != "" {
				hasTitle = true
			}
			if len(p.Lines) > height {
				height = len(p.Lines)
			}
		}

		writeRow := func(cells []string) {
			out.WriteString(strings.TrimRight(strings.Join(cells, sep), " ") + "\n")
		}

		if hasTitle {
			row := make([]string, len(band))
			for k, p := range band {
				row[k] = padVisible(Bold+p.Title+Reset, bandW[k])
			}
			writeRow(row)
		}

		for line := 0; line < height; line++ {
			row := make([]string, len(band))
			for k, p := range band {
				cell := ""
				if line < len(p.Lines) {
					cell = p.Lines[line]
				}
				row[k] = padVisible(cell, bandW[k])
			}
			writeRow(row)
		}

		if j < len(panes) {
			out.WriteString("\n")
		}
		i = j
	}

	return strings.TrimRight(out.String(), "\n")
}
