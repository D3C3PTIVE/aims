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

// Details is almost identical to Table and requires a type parameter for
// displaying an object with more details. The headers function parameter can
// either be one also used for displaying the type in a table, or another with
// different output for all/some of the fields.
// If the headers are weighted, a newline is left between each group of headers (grouped by weight).
func Details[T any](value T, fields map[string]func(T) string, opts ...Options) string {
	var details string

	// Prepare default weights.
	options := defaultOpts(opts...)

	headers := options.headers
	weights := make([]int, len(headers))
	for i, header := range headers {
		weights[i] = options.weights[header]
	}

	grpWeight := weights[0]
	var grp []string

	for i, weight := range weights {
		if weight > grpWeight {
			grpWeight = i
			details += displayGroup[T](value, grp, fields)
			grp = make([]string, 0)
			continue
		}

		grp = append(grp, headers[i])
	}

	if len(grp) > 0 {
		details += displayGroup[T](value, grp, fields)
	}

	return strings.TrimSuffix(details, "\n\n")
}

func displayGroup[T any](value T, headers []string, fields map[string]func(T) string) string {
	var maxLength int
	var group string

	// Get the padding for headers
	for _, head := range headers {
		if len(head) > maxLength {
			maxLength = len(head)
		}
	}

	for _, head := range headers {
		var val string
		if fieldFunc, ok := fields[head]; ok {
			if head == "Purpose" {
			}
			val = fieldFunc(value)
		}

		if head == "Purpose" {
			fmt.Println(val)
		}
		if val == "" {
			continue
		}

		headName := fmt.Sprintf("%*s", maxLength, head)
		fieldName := colorDetailFieldName(headName + " ")
		value := colorDetailFieldValue(val)
		group += fmt.Sprintf("%s: %s\n", fieldName, value)
	}

	return group + "\n"
}
