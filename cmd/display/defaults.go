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
	"sort"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
)

// Those variables are very important to realine low-level code: all virtual
// terminal escape sequences should always be sent and read through the raw
// terminal file, even if people start using io.MultiWriters and os.Pipes
// involving basic IO.
var (
	stdoutTerm *os.File
	stdinTerm  *os.File
	stderrTerm *os.File
)

func init() {
	stdoutTerm = os.Stdout
	stdinTerm = os.Stdin
	stderrTerm = os.Stderr
}

const (
	Reset = "\x1b[0m"
	Bold  = "\x1b[1m"
	Dim   = "\x1b[2m"
)

// FgYellow is the one named text colour still used directly (the rest of the
// palette went through fatih/color); keep it alongside the SGR helpers below.
var FgYellow = "\x1b[33m"

// Text effects.
const (
	SGRStart = "\x1b["
	Fg       = "38;05;"
	Bg       = "48;05;"
	SGREnd   = "m"
)

// Fmt formats a color code as an ANSI escaped color sequence.
func Fmt(color string) string {
	return SGRStart + color + SGREnd
}

// columnOverhead is the per-column chrome added by AIMSDefault: padding-left + padding-right +
// one column separator. Used to estimate rendered width when deciding what fits.
const columnOverhead = 3

var (
	tableStyles = map[string]table.Style{
		// AIMS styles
		AIMSDefault.Name: AIMSDefault,

		// Go Pretty styles
		table.StyleBold.Name:                    table.StyleBold,
		table.StyleColoredBright.Name:           table.StyleColoredBright,
		table.StyleLight.Name:                   table.StyleLight,
		table.StyleColoredDark.Name:             table.StyleColoredDark,
		table.StyleColoredBlackOnBlueWhite.Name: table.StyleColoredBlackOnBlueWhite,
	}

	AIMSDefault = table.Style{
		Name: "AIMSDefault",
		Box: table.BoxStyle{
			BottomLeft:       " ",
			BottomRight:      " ",
			BottomSeparator:  " ",
			Left:             " ",
			LeftSeparator:    " ",
			MiddleHorizontal: "=",
			MiddleSeparator:  " ",
			MiddleVertical:   " ",
			PaddingLeft:      " ",
			PaddingRight:     " ",
			Right:            " ",
			RightSeparator:   " ",
			TopLeft:          " ",
			TopRight:         " ",
			TopSeparator:     " ",
			UnfinishedRow:    "~~",
		},
		Color: table.ColorOptions{
			IndexColumn:  text.Colors{},
			Footer:       text.Colors{},
			Header:       text.Colors{},
			Row:          text.Colors{},
			RowAlternate: text.Colors{},
		},
		Format: table.FormatOptions{
			Footer: text.FormatDefault,
			Header: text.FormatTitle,
			Row:    text.FormatDefault,
		},
		Options: table.Options{
			DrawBorder:      false,
			SeparateColumns: true,
			SeparateFooter:  false,
			SeparateHeader:  true,
			SeparateRows:    false,
		},
	}

	AIMSBordersDefault = table.Style{
		Name: "AIMSBordersDefault",
		Box: table.BoxStyle{
			BottomLeft:       "+",
			BottomRight:      "+",
			BottomSeparator:  "-",
			Left:             "|",
			LeftSeparator:    "+",
			MiddleHorizontal: "-",
			MiddleSeparator:  "+",
			MiddleVertical:   "|",
			PaddingLeft:      " ",
			PaddingRight:     " ",
			Right:            "|",
			RightSeparator:   "+",
			TopLeft:          "+",
			TopRight:         "+",
			TopSeparator:     "-",
			UnfinishedRow:    "~~",
		},
		Color: table.ColorOptions{
			IndexColumn:  text.Colors{},
			Footer:       text.Colors{},
			Header:       text.Colors{},
			Row:          text.Colors{},
			RowAlternate: text.Colors{},
		},
		Format: table.FormatOptions{
			Footer: text.FormatDefault,
			Header: text.FormatTitle,
			Row:    text.FormatDefault,
		},
		Options: table.Options{
			DrawBorder:      true,
			SeparateColumns: true,
			SeparateFooter:  false,
			SeparateHeader:  true,
			SeparateRows:    false,
		},
	}
)

// adaptTableSize drops columns to fit the available terminal width, using the columns' REAL
// rendered widths rather than fixed width-per-weight thresholds. Weight is the drop *priority*:
// all weight-1 columns (the essential identity floor) are always kept — even if they overflow a
// tiny terminal, in which case go-pretty wraps them — and the remaining columns are then added in
// ascending-weight order, stopping at the first that no longer fits. This means a wide terminal
// shows every column that actually fits, instead of being capped by an arbitrary threshold.
func adaptTableSize(headers []string, rows [][]string, width int, options *opts) ([]string, [][]string) {
	if len(headers) == 0 {
		return headers, rows
	}

	weights := options.weights

	// Real width of each column: widest of its header and cells (ANSI ignored) + chrome.
	colWidth := make([]int, len(headers))
	for i, header := range headers {
		w := VisibleWidth(header)
		for _, row := range rows {
			if i < len(row) {
				if cw := VisibleWidth(row[i]); cw > w {
					w = cw
				}
			}
		}
		colWidth[i] = w + columnOverhead
	}

	kept := make([]bool, len(headers))
	used := 0

	// 1. Always keep the essential (weight <= 1) columns.
	for i, header := range headers {
		if weights[header] <= 1 {
			kept[i] = true
			used += colWidth[i]
		}
	}

	// 2. Add the remaining columns in ascending-weight (priority) order, stopping at the first
	//    that does not fit — so a shown column always implies every higher-priority column shows.
	rest := make([]int, 0, len(headers))
	for i, header := range headers {
		if weights[header] > 1 {
			rest = append(rest, i)
		}
	}
	sort.SliceStable(rest, func(a, b int) bool {
		return weights[headers[rest[a]]] < weights[headers[rest[b]]]
	})
	for _, idx := range rest {
		if used+colWidth[idx] > width {
			break
		}
		kept[idx] = true
		used += colWidth[idx]
	}

	// Emit kept columns in their original declared order.
	var maxed []string
	var keep []int
	for i, header := range headers {
		if kept[i] {
			keep = append(keep, i)
			maxed = append(maxed, header)
		}
	}

	maxRows := make([][]string, len(rows))
	for i, row := range rows {
		var krow []string
		for _, idx := range keep {
			if idx < len(row) {
				krow = append(krow, row[idx])
			}
		}
		maxRows[i] = krow
	}

	return maxed, maxRows
}
