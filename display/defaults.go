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

// Those variables are very important to realine low-level code: all virtual terminal
// escape sequences should always be sent and read through the raw terminal file, even
// if people start using io.MultiWriters and os.Pipes involving basic IO.
var (
	stdoutTerm *os.File
	stdinTerm  *os.File
	stderrTerm *os.File
)

func init() {
	stdoutTerm = os.Stdout
	stdoutTerm = os.Stderr
	stderrTerm = os.Stdin
}

var terminalWeightSizes = map[int]int{
	1: 80,
	2: 160,
	3: 240,
	4: 320,
}

func getMaximumWeight(width, height int) int {
	max := 0
	maxes := make([]int, len(terminalWeightSizes)+1)

	for i, threshold := range terminalWeightSizes {
		maxes[i] = threshold
	}

	sort.Ints(maxes)

	for w, threshold := range maxes {
		if threshold > width {
			break
		}
		max = w
	}

	return max
}

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

func adaptTableSize(headers []string, rows [][]string, maxWeight int, options *opts) ([]string, [][]string) {
	var maxed []string
	maxRows := make([][]string, len(rows))

	all := options.headers
	allW := options.weights

	weighted := 0
	real := 0

	for _, r := range headers {
		real++
		for _, head := range all {
			if head == r {
				break
			}
			weighted++
		}

		if allW[r] > maxWeight {
			break
		}
	}

	headers = headers[:real]

	for _, header := range headers {
		maxed = append(maxed, header)
		for i := range rows {
			maxRows[i] = rows[i][:real]
		}
	}

	return maxed, maxRows
}
