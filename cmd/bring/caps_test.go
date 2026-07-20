package bring

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

// TestCapsOutputHasRaw pins the getcap-output parse across libcap's format variants — the check that
// makes `aims init caps` idempotent (skip a scanner that is already capped). Empty output (no caps)
// and unrelated caps must read as "raw absent".
func TestCapsOutputHasRaw(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want bool
	}{
		{"newer format", "/usr/bin/nmap cap_net_admin,cap_net_raw=eip\n", true},
		{"older format", "/usr/bin/nmap = cap_net_raw+eip\n", true},
		{"bind only", "/usr/bin/nmap cap_net_bind_service=eip\n", false},
		{"empty (no caps)", "", false},
	}
	for _, c := range cases {
		if got := capsOutputHasRaw(c.out); got != c.want {
			t.Errorf("%s: capsOutputHasRaw(%q) = %v, want %v", c.name, c.out, got, c.want)
		}
	}
}
