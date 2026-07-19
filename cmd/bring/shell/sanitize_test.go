package shell

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
)

func TestSanitizeDisplay(t *testing.T) {
	cases := map[string]string{
		"web01":             "web01",
		"web-01.corp.local": "web-01.corp.local",
		"/root/work dir":    "/root/work dir", // spaces and slashes are fine
		"$(touch OWNED)":    "(touch OWNED)",  // '$' stripped -> no command substitution
		"`id`":              "id",             // backticks stripped
		"100%done":          "100done",        // '%' stripped (zsh prompt escape)
		"line1\nline2":      "line1line2",     // newline stripped
		"col1\tcol2":        "col1col2",       // TAB (the field separator) stripped
		"a\x7fb":            "ab",             // DEL stripped
		"":                  "",
	}
	for in, want := range cases {
		if got := SanitizeDisplay(in); got != want {
			t.Errorf("SanitizeDisplay(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSanitizeDisplayCapsLength(t *testing.T) {
	got := SanitizeDisplay(strings.Repeat("x", 200))
	if len([]rune(got)) != maxDisplayRunes {
		t.Errorf("SanitizeDisplay(200 runes) length = %d, want %d", len([]rune(got)), maxDisplayRunes)
	}
}
