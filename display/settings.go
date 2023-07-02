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
)

// Options are functions allowing to customize or easily use table adjusment helpers.
type Options func(opts *opts) *opts

type opts struct {
	// Core
	headers []string
	weights map[string]int
	smallID bool

	// Table
	style       table.Style
	removeEmpty bool

	// Completion
	candidate string
	fallback  string
	sep       string
}

func defaultOpts(options ...Options) *opts {
	opts := &opts{
		removeEmpty: true,
		smallID:     false,
		style:       AIMSDefault,
	}

	for _, optFunc := range options {
		optFunc(opts)
	}

	return opts
}

// WithStyle sets the style of the table.
func WithStyle(style table.Style) Options {
	return func(opts *opts) *opts {
		opts.style = style
		return opts
	}
}

// WithAutoSmallID automatically truncates columns named "ID" to maximum 8 characters.
func WithAutoSmallID() Options {
	return func(opts *opts) *opts {
		opts.smallID = true
		return opts
	}
}

// WithHeader adds a specific header for the display using these options.
func WithHeader(name string, weight int) Options {
	return func(opts *opts) *opts {
		if opts.weights == nil {
			opts.weights = make(map[string]int)
		}

		opts.headers = append(opts.headers, name)
		opts.weights[name] = weight

		return opts
	}
}

// WithCandidateValue sets the header name (field) to use as
// the completion candidate to be inserted for the given type.
func WithCandidateValue(header, fallback string) Options {
	return func(opts *opts) *opts {
		opts.candidate = header
		opts.fallback = fallback
		return opts
	}
}

// WithSplitCandidate will attempt to split the headers/fallbacks
// provided with WithCandidateValue() -if used-, and will generate
// aliased/non-aliased completions for each.
// This is useful when you don't use a unique ID with WithCandidateValue.
func WithSplitCandidate(sep string) Options {
	return func(opts *opts) *opts {
		opts.sep = sep
		return opts
	}
}

// FormatSmallID returns a smallened ID for table display.
func FormatSmallID(id string) string {
	if len(id) <= 8 {
		return id
	}

	return id[:8]
}
