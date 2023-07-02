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

	"github.com/fatih/color"
)

// Details is almost identical to Table and requires a type parameter for displaying an object with more details.
// The headers function parameter can either be one also used for displaying the type in a table, or another with
// different output for all/some of the fields.
// If the headers are weighted, a newline is left between each group of headers (grouped by weight).
func Details[T any](value T, fields map[string]func(T) string, opts ...Options) string {
	var details string
	var headers []string
	var weights []int

	// Prepare default weights.
	options := defaultOpts(opts...)
	headers = options.headers
	for _, header := range headers {
		weights = append(weights, options.weights[header])
	}

	currentWeight := weights[0]
	var groupHeaders []string

	for i, head := range headers {
		// Continue to scan fields for the current weight.
		weight := weights[i]
		if weight > currentWeight {
			group := displayGroup[T](value, groupHeaders, fields)
			if group != "" {
				details += group + "\n"
			}
			groupHeaders = make([]string, 0)
		} else {
			groupHeaders = append(groupHeaders, head)
		}
	}

	return strings.TrimSuffix(details, "\n\n")
}

func displayGroup[T any](value T, headers []string, fields map[string]func(T) string) string {
	var maxLength int
	var group string

	// Get the padding for headers
	for _, head := range headers {
		if len(head) > maxLength {
			maxLength = len(color.HiBlueString(head))
		}
	}

	for _, head := range headers {
		var val string
		if fieldFunc, ok := fields[head]; ok {
			val = fieldFunc(value)
		}

		if val == "" {
			continue
		}

		headName := fmt.Sprintf("%*s", maxLength+5, color.HiBlueString(head))

		group += fmt.Sprintf("%s : %s\n", headName, val)
	}

	return group
}
