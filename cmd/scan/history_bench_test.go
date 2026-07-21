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

// BenchmarkRenderHistory measures the drift-timeline / stability-surface render — the new
// `scan history` view (renderSeriesHistory: sparklines, colorStates, port digest) that had zero
// benchmark coverage (reviews/benchmark-review.md §B #5). The analysis itself (scan.BuildHistory)
// is built once per size outside the timed region so the benchmark isolates the render hot path;
// the swept K is the number of runs (timeline entries) in the series.
import (
	"fmt"
	"testing"

	hostpb "github.com/d3c3ptive/aims/host/pb"
	scandom "github.com/d3c3ptive/aims/scan"
	scanpb "github.com/d3c3ptive/aims/scan/pb"

	network "github.com/d3c3ptive/aims/network/pb"
)

// benchHistoryRun builds one run in a series: a scan of 127.0.0.1 finished at t, observing the
// given open ports.
func benchHistoryRun(t int64, ports ...*hostpb.Port) *scanpb.Run {
	return &scanpb.Run{
		Scanner: "nmap",
		Args:    "-sV 127.0.0.1",
		Stats:   &scanpb.Stats{Finished: &scanpb.Finished{Time: t, Exit: "success"}},
		Hosts: []*hostpb.Host{{
			Addresses: []*network.Address{{Addr: "127.0.0.1"}},
			Ports:     ports,
		}},
	}
}

func benchHistoryOpenPort(num uint32, svc string) *hostpb.Port {
	return &hostpb.Port{
		Number:   num,
		Protocol: "tcp",
		State:    &hostpb.State{State: "open"},
		Service:  &network.Service{Name: svc},
	}
}

// benchHistory builds a K-run series with real drift: a stable baseline port plus a new port opened
// on every other run, so the timeline carries a mix of changed and collapsed-unchanged entries and
// the surface classifies several ports.
func benchHistory(k int) scandom.SeriesHistory {
	svcs := []string{"http", "https", "ssh", "smtp", "dns", "ftp", "telnet", "rdp"}
	runs := make([]*scanpb.Run, 0, k)
	for i := 0; i < k; i++ {
		ports := []*hostpb.Port{benchHistoryOpenPort(22, "ssh")} // stable baseline
		for p := 0; p <= i/2; p++ {
			ports = append(ports, benchHistoryOpenPort(uint32(1000+p), svcs[p%len(svcs)]))
		}
		runs = append(runs, benchHistoryRun(int64((i+1)*100), ports...))
	}
	return scandom.BuildHistory(runs)
}

func BenchmarkRenderHistory(b *testing.B) {
	for _, k := range []int{5, 20, 50} {
		k := k
		h := benchHistory(k)

		b.Run(fmt.Sprintf("runs=%d", k), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = renderSeriesHistory(h)
			}
		})
	}
}
