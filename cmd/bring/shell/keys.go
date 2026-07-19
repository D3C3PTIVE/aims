package shell

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

import "strings"

// Payload field keys. The Go emitter (cmd/bring.writePayload) and the shell parser in the init
// templates must agree on these exact strings; the templates receive them via initData so the two
// sides cannot drift apart.
const (
	KeyID   = "id"
	KeyName = "name"
	KeyTool = "tool"
	KeyCWD  = "cwd"
)

// maxDisplayRunes caps a display value so a hostile, oversized agent name cannot blow up the
// prompt.
const maxDisplayRunes = 64

// initData carries the payload key names into the init templates, so the shell-side parser and the
// Go-side emitter share one definition of the wire format.
type initData struct {
	ID, Name, Tool, CWD string
}

// SanitizeDisplay hardens an agent-derived value before it is carried into the shell. It removes:
// control characters — including the newline and the TAB that delimits payload fields; and the
// bytes a prompt might re-interpret — '$' and '`' (command substitution under zsh PROMPT_SUBST)
// and '%' (zsh prompt escapes). The result is also length-capped.
//
// This is display hardening layered on top of the capture-as-data payload (which already prevents
// execution, since the shell parses rather than evals the payload): together they guarantee a
// hostile implant string is inert data — never code — and cannot corrupt the prompt. It is applied
// to every emitted value, including the id, so control bytes can never break the line format.
func SanitizeDisplay(s string) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n >= maxDisplayRunes {
			break
		}
		switch {
		case r < 0x20 || r == 0x7f: // control chars, incl. \t \n \r
			continue
		case r == '$' || r == '`' || r == '%': // prompt re-interpretation vectors
			continue
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}
