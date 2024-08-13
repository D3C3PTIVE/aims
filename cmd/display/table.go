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
	"github.com/jedib0t/go-pretty/v6/table"
	"golang.org/x/term"
)

// TableWith requires a type parameter consisting of a type for which a corresponding map
// of "Column Field" to a function generating its table value exits, passed as the fields
// function argument.
// The values argument is the list of objects to be cmd/displayed in the table, with options.
func Table[T any](values []T, fields map[string]func(T) string, opts ...Options) *table.Table {
	options := defaultOpts(opts...)

	// Generate all values for each row.
	var rows [][]string

	for _, val := range values {
		var row []string

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

	if len(options.weights) != 0 {
		headers, rows = withWeight(options.weights)(headers, rows)
	}

	// Adapt to terminal size.
	// The index of the value range obtained also gives the
	// maximum weight allowed for the table.
	width, height, err := term.GetSize(int(stderrTerm.Fd()))
	if err != nil {
		width, height = 80, 80
	}

	// By default, give some hints to the table itself.
	tb.SetAllowedRowLength(width)
	maxWeight := getMaximumWeight(width, height)

	// But ensure we don't get too far anyway.
	headers, rows = adaptTableSize(headers, rows, maxWeight, options)

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

// withWeight applies filters some columns depending on terminal size ranges.
func withWeight(headers map[string]int) columnCleaner {
	return func(raw []string, rows [][]string) (headers []string, cleaned [][]string) {
		return raw, rows
	}
}
