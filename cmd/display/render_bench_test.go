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

// BenchmarkTable / BenchmarkDetails measure the pure-CPU cost of the shared render engine — no
// DB, no gRPC. Every `list` builds a table by calling one fieldFunc per cell, then runs the
// post-processing pipeline (removeEmptyColumns over every cell, responsive column dropping via
// adaptTableSize, go-pretty layout+render). That cost is paid on every command and grows with row
// count; it was never benchmarked, and the display layer was recently reworked (scan live-state,
// provenance Sources column), so this guards against silent regressions there.
import (
	"fmt"
	"testing"

	"github.com/fatih/color"
)

// benchRow is a synthetic display object so the benchmark stays in the leaf display package (no
// domain imports). It carries coloured cells (to exercise width measurement over ANSI) and one
// column that is empty on every row (to exercise removeEmptyColumns doing real work).
type benchRow struct {
	id, name, os, ports, state, empty string
}

var benchRenderFields = map[string]func(benchRow) string{
	"ID":    func(r benchRow) string { return r.id },
	"Name":  func(r benchRow) string { return r.name },
	"OS":    func(r benchRow) string { return r.os },
	"Ports": func(r benchRow) string { return r.ports },
	"State": func(r benchRow) string { return r.state },
	"Empty": func(r benchRow) string { return r.empty }, // always "" -> dropped by removeEmptyColumns
}

func benchRenderHeaders() []Options {
	return Headers().
		Add("ID", 1).
		Add("Name", 1).
		Add("OS", 1).
		Add("Ports", 2).
		Add("State", 2).
		Add("Empty", 3).
		Options()
}

func benchRenderRows(n int) []benchRow {
	rows := make([]benchRow, 0, n)
	for i := 0; i < n; i++ {
		rows = append(rows, benchRow{
			id:    color.HiGreenString(FormatSmallID(fmt.Sprintf("%08d-aaaa-bbbb-cccc-0123456789ab", i))),
			name:  fmt.Sprintf("host%05d.corp.local", i),
			os:    color.HiBlueString("Linux 5.x"),
			ports: color.HiWhiteString("22/tcp, 80/tcp, 443/tcp"),
			state: color.HiGreenString("up"),
		})
	}
	return rows
}

func BenchmarkTable(b *testing.B) {
	for _, n := range []int{100, 1000, 10000} {
		n := n
		rows := benchRenderRows(n)
		headers := benchRenderHeaders()

		b.Run(fmt.Sprintf("N=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = Table(rows, benchRenderFields, headers...).Render()
			}
		})
	}
}

func BenchmarkDetails(b *testing.B) {
	row := benchRenderRows(1)[0]
	headers := benchRenderHeaders()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Details(row, benchRenderFields, headers...)
	}
}
