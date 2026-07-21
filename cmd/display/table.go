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

import (
	"os"
	"strconv"

	"github.com/jedib0t/go-pretty/v6/table"
	"golang.org/x/term"
)

// TableWith requires a type parameter consisting of a type for which a corresponding map
// of "Column Field" to a function generating its table value exits, passed as the fields
// function argument.
// The values argument is the list of objects to be cmd/displayed in the table, with options.
func Table[T any](values []T, fields map[string]func(T) string, opts ...Options) *table.Table {
	options := defaultOpts(opts...)

	// Generate all values for each row. Both dimensions are known up front (one row per
	// value, at most one cell per header), so preallocate to avoid append regrowth — at 10k
	// rows the nil-append path churned ~590k allocs just building this scratch grid.
	rows := make([][]string, 0, len(values))

	for _, val := range values {
		row := make([]string, 0, len(options.headers))

		for _, column := range options.headers {
			if fieldFunc, ok := fields[column]; ok {
				row = append(row, fieldFunc(val))
			}
		}

		rows = append(rows, row)
	}

	// All fields and rows are generated, populate the table.
	return populate(rows, options)
}

func populate(rows [][]string, options *opts) *table.Table {
	tb := &table.Table{}
	tb.SetStyle(options.style)

	if len(rows) == 0 {
		return tb
	}

	headers := options.headers

	// Filterings && Formating
	if options.removeEmpty {
		headers, rows = removeEmptyColumns()(headers, rows)
	}

	// Adapt to terminal size: drop columns (by weight priority) only when they don't actually
	// fit the available width — see adaptTableSize.
	width, _ := terminalSize()

	// By default, give some hints to the table itself.
	tb.SetAllowedRowLength(width)

	headers, rows = adaptTableSize(headers, rows, width, options)

	// Add final headers
	var heads table.Row
	for _, header := range headers {
		heads = append(heads, header)
	}

	tb.AppendHeader(heads)

	// Add final rows
	for _, row := range rows {
		var list table.Row
		for _, column := range row {
			list = append(list, column)
		}

		tb.AppendRow(list)
	}

	// 3 - Last settings

	return tb
}

// terminalSize returns the width/height of the controlling terminal. It tries the output streams
// in turn — stdout is the usual render sink, so it is measured first; stderr (the previous sole
// source) is unreliable when a teamserver redirects it for logging — then falls back to $COLUMNS
// and finally a sane default. A width of 0 (non-tty) is treated as "unknown" and skipped.
func terminalSize() (width, height int) {
	for _, f := range []*os.File{stdoutTerm, stderrTerm, stdinTerm} {
		if f == nil {
			continue
		}
		if w, h, err := term.GetSize(int(f.Fd())); err == nil && w > 0 {
			return w, h
		}
	}

	if c, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && c > 0 {
		return c, 50
	}

	return 80, 50
}

// columnCleaner filters a series of column headers and their contents in rows.
type columnCleaner func(raw []string, rows [][]string) (headers []string, cleaned [][]string)

// removeEmptyColumns removes headers and columns for which there is no value on any row.
func removeEmptyColumns() columnCleaner {
	return func(headers []string, rows [][]string) ([]string, [][]string) {
		var filteredHeaders []string
		filteredRows := make([][]string, len(rows))

		for index, header := range headers {
			empty := true

			for _, row := range rows {
				if len(row) > index {
					if row[index] != "" {
						empty = false
						break
					}
				}
			}

			if !empty {
				filteredHeaders = append(filteredHeaders, header)
				for i := range filteredRows {
					filteredRows[i] = append(filteredRows[i], rows[i][index])
				}
			}
		}

		return filteredHeaders, filteredRows
	}
}
