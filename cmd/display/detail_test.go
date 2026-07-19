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
	"bytes"
	"fmt"
	"testing"
)

// printLegacy replays the exact fmt.Println sequence the domain CLIs used before Detail.Render
// existed (banner, then Columns, then an optional Insights block, then optional trailing
// sections, then the blank separator). It is the behavioural spec Render must reproduce.
func printLegacy(w *bytes.Buffer, width int, d Detail) {
	fmt.Fprintln(w, Banner(d.Title, d.Badges...))
	fmt.Fprintln(w, Columns(width, detailGap, NonEmptyPanes(d.Panes)...))

	if len(d.Insights) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, Bold+"Insights"+Reset)
		for _, l := range d.Insights {
			fmt.Fprintln(w, "  "+l)
		}
	}

	for _, s := range d.Sections {
		if s.Body == "" {
			continue
		}
		fmt.Fprintln(w)
		fmt.Fprintln(w, Bold+s.Title+Reset+s.Body)
	}

	fmt.Fprintln(w) // blank separator between objects
}

// printNew is how the CLIs render a detail view now: one Render call, then the blank separator.
func printNew(w *bytes.Buffer, width int, d Detail) {
	fmt.Fprintln(w, d.Render(width))
	fmt.Fprintln(w)
}

// TestDetailRenderMatchesLegacy asserts the hoisted Detail.Render produces byte-identical output
// to the old inline fmt.Println orchestration, across the shapes the domains actually emit
// (with/without insights, with/without a trailing section). This is what makes the extraction
// safe: the visible CLI output cannot have moved.
func TestDetailRenderMatchesLegacy(t *testing.T) {
	panes := []Pane{
		{Title: "Service", Lines: KVLines([][2]string{{"Port", "443/tcp"}, {"Name", "https"}})},
		{Title: "State", Lines: KVLines([][2]string{{"State", "open"}, {"Reason", "syn-ack"}})},
	}

	cases := map[string]Detail{
		"panes only": {
			Title:  Bold + "example" + Reset,
			Badges: []string{"● open"},
			Panes:  panes,
		},
		"panes + insights": {
			Title:    Bold + "example" + Reset,
			Badges:   []string{"● open", "2 script(s)"},
			Panes:    panes,
			Insights: []string{"⚠ cleartext protocol", "✓ used in 1 login(s)"},
		},
		"panes + section": {
			Title:    "10.0.0.1" + Dim + ":" + Reset + Bold + "443" + Reset,
			Badges:   []string{"● open"},
			Panes:    panes,
			Sections: []Section{{Title: "Scripts", Body: "\nName: ssl-cert\nOutput: ...\n"}},
		},
		"panes + insights + section": {
			Title:    Bold + "example" + Reset,
			Badges:   []string{"● open"},
			Panes:    panes,
			Insights: []string{"⚠ cleartext protocol"},
			Sections: []Section{{Title: "Scripts", Body: "\nName: ssl-cert\n"}},
		},
		"no badges": {
			Title: Bold + "example" + Reset,
			Panes: panes,
		},
		"empty section is skipped": {
			Title:    Bold + "example" + Reset,
			Panes:    panes,
			Sections: []Section{{Title: "Scripts", Body: ""}},
		},
	}

	const width = 100
	for name, d := range cases {
		t.Run(name, func(t *testing.T) {
			var legacy, current bytes.Buffer
			printLegacy(&legacy, width, d)
			printNew(&current, width, d)

			if legacy.String() != current.String() {
				t.Errorf("Render output diverged from legacy orchestration\n--- legacy ---\n%q\n--- new ---\n%q",
					legacy.String(), current.String())
			}
		})
	}
}

// TestBannerBadges checks the badge mechanics Banner owns: the dim separator between badges, the
// three-space gap before the first, empties dropped, and no badge run when none are present. The
// banner's second line is the rule, so we assert on the first line (up to the newline).
func TestBannerBadges(t *testing.T) {
	sep := Dim + " · " + Reset

	firstLine := func(s string) string {
		if i := indexByte(s, '\n'); i >= 0 {
			return s[:i]
		}
		return s
	}

	if got, want := firstLine(Banner("title", "a", "", "b")), "title   a"+sep+"b"; got != want {
		t.Errorf("badge join: got %q want %q", got, want)
	}
	if got, want := firstLine(Banner("title")), "title"; got != want {
		t.Errorf("no badges: got %q want %q", got, want)
	}
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// TestNonEmptyPanes drops only the panes with no lines.
func TestNonEmptyPanes(t *testing.T) {
	in := []Pane{
		{Title: "a", Lines: []string{"x"}},
		{Title: "b", Lines: nil},
		{Title: "c", Lines: []string{}},
		{Title: "d", Lines: []string{"y", "z"}},
	}
	got := NonEmptyPanes(in)
	if len(got) != 2 || got[0].Title != "a" || got[1].Title != "d" {
		t.Errorf("NonEmptyPanes = %+v, want panes a and d", got)
	}
}
