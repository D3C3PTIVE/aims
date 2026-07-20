package drive

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

import "testing"

// TestMasscanProgressRE pins the percent extraction from masscan's stderr progress line — the one
// piece of the masscan driver that parses without a live binary. Lines that carry no "% done" (the
// banner, blank lines, the final summary) must not match.
func TestMasscanProgressRE(t *testing.T) {
	cases := []struct {
		line string
		want string // "" means no match expected
	}{
		{"rate: 10.00-kpps,  42.13% done,   0:00:12 remaining", "42.13"},
		{"rate:  0.00-kpps,   0.00% done, waiting...", "0.00"},
		{"rate:  0.00-kpps, 100.00% done", "100.00"},
		{"Starting masscan 1.3.2", ""},
		{"", ""},
		{"Scanning 256 hosts [1 port/host]", ""},
	}
	for _, c := range cases {
		m := masscanProgressRE.FindStringSubmatch(c.line)
		switch {
		case c.want == "":
			if m != nil {
				t.Errorf("%q: expected no match, got %v", c.line, m)
			}
		case m == nil:
			t.Errorf("%q: expected match %q, got none", c.line, c.want)
		case m[1] != c.want:
			t.Errorf("%q: got percent %q, want %q", c.line, m[1], c.want)
		}
	}
}
