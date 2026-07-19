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

// Completions returns (candidate, description) pairs for carapace.ActionValuesDescribed.
func Completions[T any](values []T, fields map[string]func(T) string, opts ...Options) []string {
	triples := CompletionsStyled(values, fields, nil, opts...)

	// Drop the style column from each (candidate, description, style) triple.
	pairs := make([]string, 0, len(triples)/3*2)
	for i := 0; i+2 < len(triples); i += 3 {
		pairs = append(pairs, triples[i], triples[i+1])
	}

	return pairs
}

// CompletionsStyled is like Completions but also emits a per-candidate style, returning
// (candidate, description, style) triples for carapace.ActionStyledValuesDescribed. styleOf maps
// each source value to a carapace style string (e.g. style.Green); a nil styleOf yields empty
// styles. The candidate is inserted verbatim, so all values are ANSI-stripped here — colour comes
// from the returned style, never from embedded escape codes.
func CompletionsStyled[T any](values []T, fields map[string]func(T) string, styleOf func(T) string, opts ...Options) (results []string) {
	options := defaultOpts(opts...)
	headers := options.headers

	var candidateColumn, fallbackColumn int

	rows := make([][]string, len(values))
	lengths := make([]int, len(headers))

	// Gather all "table cells", ANSI-stripped so candidate text and padding widths are real.
	for j, h := range values {
		for i, column := range headers {
			if fieldFunc, ok := fields[column]; ok {
				val := StripANSI(fieldFunc(h))

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

	for j, row := range rows {
		st := ""
		if styleOf != nil {
			st = styleOf(values[j])
		}

		frow := make([]string, len(row))

		// Apply padding to all columns but the candidate.
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

		emit := func(splits []string) {
			for _, split := range splits {
				if strings.TrimSpace(split) == "" {
					continue
				}
				results = append(results, strings.TrimSpace(split), formatDesc(frow, candidateColumn), st)
			}
		}

		// Generate the completion rows (candidate + description + style).
		if strings.TrimSpace(frow[candidateColumn]) != "" {
			emit(splitCandidates)
		} else if strings.TrimSpace(frow[fallbackColumn]) != "" {
			emit(splitFallbacks)
		}
	}

	// Ensure there are no newlines in any candidate/description/style.
	for i := range results {
		results[i] = strings.ReplaceAll(results[i], "\n", " ")
	}

	return results
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
