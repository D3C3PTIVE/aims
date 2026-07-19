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

import "strings"

// bannerRuleWidth is the width of the horizontal rule drawn under a detail banner.
const bannerRuleWidth = 66

// detailGap is the number of spaces between side-by-side info panes in a detail view.
const detailGap = 4

// Banner renders the one-line header of a single-object detail view: a title on the left and
// optional status badges on the right, joined by a dim " · ", followed by a dim horizontal rule.
// The title and badges are rendered verbatim — callers colour/bold them as they wish — so this
// only owns the shared mechanics (badge separator, spacing, rule). Empty badges are skipped.
// It is the shared header behind every domain's `info` view.
func Banner(title string, badges ...string) string {
	head := title

	var shown []string
	for _, b := range badges {
		if strings.TrimSpace(b) != "" {
			shown = append(shown, b)
		}
	}
	if len(shown) > 0 {
		head += "   " + strings.Join(shown, Dim+" · "+Reset)
	}

	rule := Dim + strings.Repeat("─", bannerRuleWidth) + Reset
	return head + "\n" + rule
}

// Section is an optional titled block appended below the info panes of a detail view (e.g. a
// port's NSE scripts). A Section whose Body is blank is skipped; a Section with an empty Title
// prints its Body with no heading.
type Section struct {
	Title string // bold heading, printed above Body
	Body  string // pre-rendered content, may be multi-line
}

// Detail is the assembled content of a single-object `info` view: a banner (title + badges), a
// row of side-by-side info panes, a derived-insights block, and any trailing sections. A domain
// supplies the pieces; Render lays them out identically everywhere, so every domain's detail
// view — credential, service, and the next guinea pig — shares one structure and one look.
//
// Render returns the block with no trailing newline, mirroring Columns/Banner, so callers print
// it with fmt.Println (and a following fmt.Println for the blank separator between objects).
type Detail struct {
	Title    string    // banner title, already coloured/bold by the domain
	Badges   []string  // banner status badges, already coloured
	Panes    []Pane    // side-by-side info columns; empty panes are dropped
	Insights []string  // derived observations, listed under an "Insights" header
	Sections []Section // trailing titled blocks (scripts, etc.)
}

// Render lays the detail out to a string. width is the layout width for the panes (0 = detect
// the terminal), matching Columns.
func (d Detail) Render(width int) string {
	var b strings.Builder

	b.WriteString(Banner(d.Title, d.Badges...))

	if panes := NonEmptyPanes(d.Panes); len(panes) > 0 {
		b.WriteString("\n")
		b.WriteString(Columns(width, detailGap, panes...))
	}

	if len(d.Insights) > 0 {
		b.WriteString("\n\n")
		b.WriteString(Bold + "Insights" + Reset)
		for _, l := range d.Insights {
			b.WriteString("\n  " + l)
		}
	}

	for _, s := range d.Sections {
		if strings.TrimSpace(s.Body) == "" {
			continue
		}
		b.WriteString("\n\n")
		if s.Title != "" {
			b.WriteString(Bold + s.Title + Reset)
		}
		b.WriteString(s.Body)
	}

	return b.String()
}

// NonEmptyPanes returns the panes that have at least one content line, so a section with no data
// never prints a bare title. It is what lets a domain hand Render a fixed pane list and let the
// absent ones fall away.
func NonEmptyPanes(panes []Pane) []Pane {
	var out []Pane
	for _, p := range panes {
		if len(p.Lines) > 0 {
			out = append(out, p)
		}
	}
	return out
}
