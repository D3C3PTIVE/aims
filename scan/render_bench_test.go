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

// BenchmarkTableScans renders a real scan list through the shared display engine with the scan
// domain's own DisplayFields, so the per-domain field-func cost (state-coloured ID/When, host
// counts, series/target rendering) is measured — not just the generic engine's synthetic
// BenchmarkTable (reviews/benchmark-review.md §B #6). Pure CPU (no DB): the rows are built once and
// the timer reset before the render loop.
import (
	"fmt"
	"testing"

	"github.com/d3c3ptive/aims/cmd/display"
	scanpb "github.com/d3c3ptive/aims/scan/pb"
)

func benchTableRuns(n int) []*scanpb.Run {
	runs := make([]*scanpb.Run, 0, n)
	for i := 0; i < n; i++ {
		addr := fmt.Sprintf("10.0.%d.%d", (i>>8)&0xff, i&0xff)
		runs = append(runs, runAt(int64(i*100), addr, openPort(22, "ssh"), openPort(80, "http")))
	}
	return runs
}

func BenchmarkTableScans(b *testing.B) {
	headers := DisplayHeaders()
	for _, n := range []int{100, 1000, 10000} {
		n := n
		runs := benchTableRuns(n)

		b.Run(fmt.Sprintf("N=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = display.Table(runs, DisplayFields, headers...).Render()
			}
		})
	}
}
