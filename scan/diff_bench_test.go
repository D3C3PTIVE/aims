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

// BenchmarkScanDiff measures DiffRuns — the run-to-run drift computation behind the headline
// v0.2.0 diff/history features, which had zero benchmark coverage (reviews/benchmark-review.md §B
// #4). findHost/findPort are O(n·m) linear scans (diff.go), so cost grows with the host×port
// product; two runs of N hosts with a controlled delta make that visible. Pure CPU (no DB), so the
// fixtures are built once and the timer reset before the loop.
import (
	"fmt"
	"testing"

	host "github.com/d3c3ptive/aims/host/pb"
	scan "github.com/d3c3ptive/aims/scan/pb"
)

// diffBenchSizes is the host count per run swept. The diff is O(n·m) in hosts×ports, so this stays
// modest.
var diffBenchSizes = []int{50, 200, 500}

// benchDiffRuns builds two runs of n hosts sharing the same addresses, with a controlled delta:
// every 10th host has its ssh version bumped and gains a new port in run b, the last host is
// dropped from b (gone), and one brand-new host is added to b. This exercises the changed /
// gone / new branches of DiffRuns rather than a trivially-equal pair.
func benchDiffRuns(n int) (a, b *scan.Run) {
	hostsA := make([]*host.Host, 0, n)
	hostsB := make([]*host.Host, 0, n)
	for i := 0; i < n; i++ {
		addr := fmt.Sprintf("10.%d.%d.%d", (i>>16)&0xff, (i>>8)&0xff, i&0xff)
		hostsA = append(hostsA, diffHostAt(addr,
			diffPort(22, "ssh", "OpenSSH", "8.9", "open"),
			diffPort(80, "http", "nginx", "1.20", "open"),
		))

		if i == n-1 {
			continue // drop the last host from b → GoneHosts
		}
		if i%10 == 0 {
			hostsB = append(hostsB, diffHostAt(addr,
				diffPort(22, "ssh", "OpenSSH", "9.6", "open"), // version changed
				diffPort(80, "http", "nginx", "1.20", "open"),
				diffPort(8080, "http-proxy", "", "", "open"), // newly open
			))
		} else {
			hostsB = append(hostsB, diffHostAt(addr,
				diffPort(22, "ssh", "OpenSSH", "8.9", "open"),
				diffPort(80, "http", "nginx", "1.20", "open"),
			))
		}
	}
	// One brand-new host only in b → NewHosts.
	hostsB = append(hostsB, diffHostAt("172.16.0.1", diffPort(443, "https", "", "", "open")))

	return &scan.Run{Hosts: hostsA}, &scan.Run{Hosts: hostsB}
}

func BenchmarkScanDiff(b *testing.B) {
	for _, n := range diffBenchSizes {
		n := n
		runA, runB := benchDiffRuns(n)

		b.Run(fmt.Sprintf("N=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if DiffRuns(runA, runB).Empty() {
					b.Fatal("expected a non-empty diff")
				}
			}
		})
	}
}
