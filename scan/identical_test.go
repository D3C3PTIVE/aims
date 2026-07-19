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
	"testing"

	scan "github.com/d3c3ptive/aims/scan/pb"
)

func TestAreScansIdentical(t *testing.T) {
	cases := []struct {
		name string
		a, b *scan.RunORM
		want bool
	}{
		{
			name: "same RawXML is decisive",
			a:    &scan.RunORM{RawXML: "<xml>same</xml>"},
			b:    &scan.RunORM{RawXML: "<xml>same</xml>"},
			want: true,
		},
		{
			name: "different RawXML rules identity out even if every other field agrees",
			a:    &scan.RunORM{RawXML: "<xml>A</xml>", Args: "-sT", Scanner: "nmap", Start: 100},
			b:    &scan.RunORM{RawXML: "<xml>B</xml>", Args: "-sT", Scanner: "nmap", Start: 100},
			want: false,
		},
		{
			name: "two dataless runs are NOT identical (shared absence is not evidence)",
			a:    &scan.RunORM{},
			b:    &scan.RunORM{},
			want: false,
		},
		{
			name: "no RawXML, matching identity fields => identical",
			a:    &scan.RunORM{Args: "-sT -p22", Scanner: "nmap", Start: 1700000000, StartStr: "now"},
			b:    &scan.RunORM{Args: "-sT -p22", Scanner: "nmap", Start: 1700000000, StartStr: "now"},
			want: true,
		},
		{
			name: "no RawXML, same command but different start time => distinct",
			a:    &scan.RunORM{Args: "-sT -p22", Scanner: "nmap", Start: 1700000000},
			b:    &scan.RunORM{Args: "-sT -p22", Scanner: "nmap", Start: 1700009999},
			want: false,
		},
		{
			name: "one field of agreement, none in conflict => identical",
			a:    &scan.RunORM{Args: "-sT -p22"},
			b:    &scan.RunORM{Args: "-sT -p22"},
			want: true,
		},
		{
			name: "a populated conflict disqualifies despite other agreement",
			a:    &scan.RunORM{Args: "-sT", Scanner: "nmap"},
			b:    &scan.RunORM{Args: "-sV", Scanner: "nmap"},
			want: false,
		},
		{
			name: "empty on one side is neutral, not evidence",
			a:    &scan.RunORM{Args: "-sT", Scanner: "nmap"},
			b:    &scan.RunORM{Scanner: "nmap"},
			want: true, // Scanner agrees, Args neutral (empty on b) — one agreement, no conflict
		},
		{
			name: "nil is never identical",
			a:    nil,
			b:    &scan.RunORM{RawXML: "x"},
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := AreScansIdentical(tc.a, tc.b); got != tc.want {
				t.Errorf("AreScansIdentical = %v, want %v", got, tc.want)
			}
		})
	}
}
