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

const (
	// Table
	ColorIDYellow = "\033"
	ColorIDRed    = "\033"
	ColorIDOrange = "\033"

	// Details
	detailsSection = "\033"

	// All
	ColorHintsDim = "\033"
)

const (
	Reset      = "\x1b[0m"
	Bold       = "\x1b[1m"
	Dim        = "\x1b[2m"
	Underscore = "\x1b[4m"
	Blink      = "\x1b[5m"
	Reverse    = "\x1b[7m"

	// Effects reset.
	BoldReset       = "\x1b[22m" // 21 actually causes underline instead
	DimReset        = "\x1b[22m"
	UnderscoreReset = "\x1b[24m"
	BlinkReset      = "\x1b[25m"
	ReverseReset    = "\x1b[27m"
)

// Text colours.
var (
	FgBlack   = "\x1b[30m"
	FgRed     = "\x1b[31m"
	FgGreen   = "\x1b[32m"
	FgYellow  = "\x1b[33m"
	FgBlue    = "\x1b[34m"
	FgMagenta = "\x1b[35m"
	FgCyan    = "\x1b[36m"
	FgWhite   = "\x1b[37m"
	FgDefault = "\x1b[39m"

	FgBlackBright   = "\x1b[1;30m"
	FgRedBright     = "\x1b[1;31m"
	FgGreenBright   = "\x1b[1;32m"
	FgYellowBright  = "\x1b[1;33m"
	FgBlueBright    = "\x1b[1;34m"
	FgMagentaBright = "\x1b[1;35m"
	FgCyanBright    = "\x1b[1;36m"
	FgWhiteBright   = "\x1b[1;37m"
)

// Background colours.
var (
	BgBlack   = "\x1b[40m"
	BgRed     = "\x1b[41m"
	BgGreen   = "\x1b[42m"
	BgYellow  = "\x1b[43m"
	BgBlue    = "\x1b[44m"
	BgMagenta = "\x1b[45m"
	BgCyan    = "\x1b[46m"
	BgWhite   = "\x1b[47m"
	BgDefault = "\x1b[49m"

	BgDarkGray  = "\x1b[100m"
	BgBlueLight = "\x1b[104m"

	BgBlackBright   = "\x1b[1;40m"
	BgRedBright     = "\x1b[1;41m"
	BgGreenBright   = "\x1b[1;42m"
	BgYellowBright  = "\x1b[1;43m"
	BgBlueBright    = "\x1b[1;44m"
	BgMagentaBright = "\x1b[1;45m"
	BgCyanBright    = "\x1b[1;46m"
	BgWhiteBright   = "\x1b[1;47m"
)

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
