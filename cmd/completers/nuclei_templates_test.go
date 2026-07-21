package completers

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
	"reflect"
	"testing"
)

// TestChildrenAt pins the directory-by-directory split the path completer (Templates) renders from:
// subdirectories are counted (not listed), direct files are returned in full, and entries outside
// the given prefix are excluded.
func TestChildrenAt(t *testing.T) {
	entries := []templateEntry{
		{Path: "http/technologies/wordpress-eol.yaml"},
		{Path: "http/technologies/apache-detect.yaml"},
		{Path: "http/cves/2023/cve-2023-1234.yaml"},
		{Path: "dns/generic-nameserver-fingerprint.yaml"},
	}

	t.Run("root", func(t *testing.T) {
		dirs, files := childrenAt(entries, "")
		want := map[string]int{"http": 3, "dns": 1}
		if !reflect.DeepEqual(dirs, want) {
			t.Errorf("dirs = %#v, want %#v", dirs, want)
		}
		if len(files) != 0 {
			t.Errorf("expected no direct files at root, got %d", len(files))
		}
	})

	t.Run("one level down", func(t *testing.T) {
		dirs, files := childrenAt(entries, "http/")
		want := map[string]int{"technologies": 2, "cves": 1}
		if !reflect.DeepEqual(dirs, want) {
			t.Errorf("dirs = %#v, want %#v", dirs, want)
		}
		if len(files) != 0 {
			t.Errorf("expected no direct files under http/, got %d", len(files))
		}
	})

	t.Run("leaf directory", func(t *testing.T) {
		dirs, files := childrenAt(entries, "http/technologies/")
		if len(dirs) != 0 {
			t.Errorf("expected no subdirectories, got %#v", dirs)
		}
		if len(files) != 2 {
			t.Fatalf("expected 2 direct files, got %d", len(files))
		}
	})

	t.Run("nonexistent prefix", func(t *testing.T) {
		dirs, files := childrenAt(entries, "ssl/")
		if len(dirs) != 0 || len(files) != 0 {
			t.Errorf("expected nothing under an unused prefix, got dirs=%#v files=%#v", dirs, files)
		}
	})
}

// TestDirLabels checks alphabetical ordering and the trailing "/" + count-description shape the
// multipart path completer relies on for its NoSpace continuation.
func TestDirLabels(t *testing.T) {
	pairs := dirLabels(map[string]int{"cves": 1, "technologies": 2})
	want := []string{"cves/", "1 template", "technologies/", "2 templates"}
	if !reflect.DeepEqual(pairs, want) {
		t.Errorf("dirLabels = %#v, want %#v", pairs, want)
	}
}

func TestTemplateCountLabel(t *testing.T) {
	if got := templateCountLabel(1); got != "1 template" {
		t.Errorf("templateCountLabel(1) = %q", got)
	}
	if got := templateCountLabel(2); got != "2 templates" {
		t.Errorf("templateCountLabel(2) = %q", got)
	}
	if got := templateCountLabel(0); got != "0 templates" {
		t.Errorf("templateCountLabel(0) = %q", got)
	}
}

// TestTemplateDescription covers the three name fallbacks (Name, then ID, then Path) and the
// "unknown" severity fallback for a header that never set info.severity.
func TestTemplateDescription(t *testing.T) {
	cases := []struct {
		name  string
		entry templateEntry
		want  string
	}{
		{"full", templateEntry{Name: "WordPress EOL", Severity: "info"}, "[info] WordPress EOL"},
		{"falls back to id", templateEntry{ID: "wordpress-eol", Severity: "high"}, "[high] wordpress-eol"},
		{"falls back to path", templateEntry{Path: "http/x.yaml"}, "[unknown] http/x.yaml"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := templateDescription(c.entry); got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

// TestRankByFrequency pins the ordering bucketedByFrequency's common/other split depends on: count
// descending, ties broken alphabetically, empty keys dropped.
func TestRankByFrequency(t *testing.T) {
	counts := map[string]int{
		"vuln": 100,
		"cve":  100, // ties with vuln: alphabetical tiebreak puts cve first
		"rare": 1,
		"":     5, // no tag recorded — must never appear as a candidate
	}
	want := []string{"cve", "vuln", "rare"}
	if got := rankByFrequency(counts); !reflect.DeepEqual(got, want) {
		t.Errorf("rankByFrequency = %#v, want %#v", got, want)
	}
	if got := rankByFrequency(map[string]int{}); len(got) != 0 {
		t.Errorf("expected no ranked values for an empty count map, got %#v", got)
	}
}

func TestTemplateProtocolTypesShape(t *testing.T) {
	if len(templateProtocolTypes)%2 != 0 {
		t.Fatalf("templateProtocolTypes must be (value, description) pairs, got odd length %d", len(templateProtocolTypes))
	}
	seen := make(map[string]bool)
	for i := 0; i < len(templateProtocolTypes); i += 2 {
		value, desc := templateProtocolTypes[i], templateProtocolTypes[i+1]
		if value == "" || desc == "" {
			t.Errorf("empty value or description at index %d: %q / %q", i, value, desc)
		}
		if seen[value] {
			t.Errorf("duplicate protocol type %q", value)
		}
		seen[value] = true
	}
}
