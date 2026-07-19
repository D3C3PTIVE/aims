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
)

// A faithful slice of nmap's real script.db format.
const scriptDBSample = `Entry { filename = "acarsd-info.nse", categories = { "discovery", "safe", } }
Entry { filename = "afp-brute.nse", categories = { "brute", "intrusive", } }
Entry { filename = "http-title.nse", categories = { "default", "discovery", "safe", } }
# a comment line that must be ignored
Entry { filename = "smb-os-discovery.nse", categories = { "default", "discovery", "safe", } }`

func TestParseScriptDB(t *testing.T) {
	scripts, categories := parseScriptDB(strings.NewReader(scriptDBSample))

	if len(scripts) != 4 {
		t.Fatalf("want 4 scripts parsed, got %d (%v)", len(scripts), scripts)
	}

	// Scripts are sorted by name; names carry the .nse stripped.
	want := map[string]string{
		"acarsd-info":      "discovery, safe",
		"afp-brute":        "brute, intrusive",
		"http-title":       "default, discovery, safe",
		"smb-os-discovery": "default, discovery, safe",
	}
	for _, s := range scripts {
		desc, ok := want[s[0]]
		if !ok {
			t.Errorf("unexpected script %q", s[0])
			continue
		}
		if s[1] != desc {
			t.Errorf("script %q: want categories %q, got %q", s[0], desc, s[1])
		}
	}

	// Categories are the sorted union plus the synthetic "all".
	catSet := map[string]bool{}
	for _, c := range categories {
		catSet[c] = true
	}
	for _, must := range []string{"all", "brute", "default", "discovery", "intrusive", "safe"} {
		if !catSet[must] {
			t.Errorf("missing category %q in %v", must, categories)
		}
	}

	// Sorted ascending.
	for i := 1; i < len(categories); i++ {
		if categories[i-1] > categories[i] {
			t.Errorf("categories not sorted: %v", categories)
			break
		}
	}
}

func TestParseScriptDBEmpty(t *testing.T) {
	scripts, categories := parseScriptDB(strings.NewReader("garbage\nno entries here\n"))
	if len(scripts) != 0 {
		t.Errorf("want no scripts, got %v", scripts)
	}
	// Even with no entries, the synthetic "all" selector is present.
	if len(categories) != 1 || categories[0] != "all" {
		t.Errorf("want just [all], got %v", categories)
	}
}
