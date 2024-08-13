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
	"fmt"
	"strings"
)

// Completions returns a list of results that can be passed to a carapace.Action (described or not), to be used as completions.
func Completions[T any](values []T, fields map[string]func(T) string, opts ...Options) (results []string) {
	var headers []string
	var weights []int

	// Prepare default weights.
	options := defaultOpts(opts...)
	headers = options.headers
	for _, header := range headers {
		weights = append(weights, options.weights[header])
	}

	var candidateColumn int
	var fallbackColumn int

	rows := make([][]string, len(values))
	lengths := make([]int, len(headers))

	// Gather all required "table cells" elements first.
	// Save the index of our candidates columns if any.
	for j, h := range values {
		for i, column := range headers {
			if fieldFunc, ok := fields[column]; ok {

				val := fieldFunc(h)

				if column == options.candidate && column != "" {
					candidateColumn = i
				}
				if column == options.fallback && column != "" {
					fallbackColumn = i
				}

				rows[j] = append(rows[j], val)
				if lengths[i] < len(val) {
					lengths[i] = len(val)
				}
			}
		}
	}

	// For each row, use either the candidate or the fallback
	// columns for one ore more candidates values to insert.
	for _, row := range rows {
		frow := make([]string, len(row))

		// Apply padding to all columns but the first.
		for i := 0; i < len(row); i++ {
			if i == candidateColumn && row[i] != "" {
				frow[i] = row[i]
			} else {
				frow[i] = fmt.Sprintf("%*s", lengths[i]+3, row[i])
			}
		}

		// Some fields are lists, which means they might be aliased completions.
		splitCandidates := []string{frow[candidateColumn]}
		splitFallbacks := []string{frow[fallbackColumn]}

		if options.sep != "" {
			splitCandidates = strings.Split(frow[candidateColumn], options.sep)
			splitFallbacks = strings.Split(frow[fallbackColumn], options.sep)
		}

		// Generate the completion rows (candidate + description)
		if strings.TrimSpace(frow[candidateColumn]) != "" {
			for _, split := range splitCandidates {
				if split == "" {
					continue
				}
				results = append(results, strings.TrimSpace(split))
				results = append(results, formatDesc(frow, candidateColumn))
			}
		} else if strings.TrimSpace(frow[fallbackColumn]) != "" {
			for _, split := range splitFallbacks {
				if split == "" {
					continue
				}
				results = append(results, strings.TrimSpace(split))
				results = append(results, formatDesc(frow, candidateColumn))
			}
		}
	}

	sanitized := make([]string, len(results))

	// Ensure there are no newlines in each string/description/candidate, replace them with a space.
	for i := range results {
		sanitized[i] = strings.ReplaceAll(results[i], "\n", " ")
	}

	return sanitized
}

func formatDesc(fields []string, skip int) string {
	var desc string
	for i := 0; i < len(fields); i++ {
		if i != skip {
			desc += fields[i]
		}
	}

	return desc
}
