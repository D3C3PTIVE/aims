// Package shell is the boundary between AIMS and the operator's interactive shell for the
// `bring` implant-context feature (see BRING.md). It knows the supported shell dialects and,
// crucially, how to quote a value so that a shell reproduces it verbatim without interpreting
// its contents.
//
// Quote is the single trusted escaping boundary of the whole feature. In a C2 setting an
// agent's reported strings (name, working directory, hostname) are attacker-controlled; if any
// such value reached generated shell code unescaped, a malicious implant would gain code
// execution on the operator's box. Every agent-derived value interpolated into a bring payload
// must therefore pass through Quote.
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

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Shell identifies a supported shell dialect. Dialects differ in how they quote string
// literals, which is why quoting is dispatched on the Shell.
type Shell int

const (
	// Bash is the default dialect and the POSIX-family reference.
	Bash Shell = iota
	// Zsh shares POSIX single-quote semantics with bash.
	Zsh
	// Fish quotes single-quoted strings differently (backslash is an escape).
	Fish
)

// String returns the canonical lowercase name of the shell.
func (s Shell) String() string {
	switch s {
	case Zsh:
		return "zsh"
	case Fish:
		return "fish"
	default:
		return "bash"
	}
}

// Supported lists the shell names bring can generate integration for.
func Supported() []string { return []string{"bash", "zsh", "fish"} }

// Parse resolves a shell name to a Shell. It accepts a bare name ("zsh") or the path of a shell
// binary ("/usr/bin/zsh"), case-insensitively, and errors on anything unsupported.
func Parse(name string) (Shell, error) {
	switch strings.ToLower(filepath.Base(strings.TrimSpace(name))) {
	case "bash":
		return Bash, nil
	case "zsh":
		return Zsh, nil
	case "fish":
		return Fish, nil
	default:
		return Bash, fmt.Errorf("unsupported shell %q (want one of: %s)", name, strings.Join(Supported(), ", "))
	}
}

// Detect guesses the operator's shell from the $SHELL environment variable, defaulting to Bash
// when it is unset or unrecognized.
func Detect() Shell {
	if sh, err := Parse(os.Getenv("SHELL")); err == nil {
		return sh
	}
	return Bash
}

// Quote renders s as a single shell token that the given shell expands back to exactly s, with
// no interpretation of its contents. It is the single trusted boundary between
// attacker-controlled agent data and generated shell code (see the package doc): every value
// interpolated into a bring payload MUST pass through Quote. The result is safe for arbitrary
// bytes — including newlines, $(...), backticks, semicolons and quotes.
func Quote(sh Shell, s string) string {
	if sh == Fish {
		return quoteFish(s)
	}
	return quotePOSIX(s)
}

// quotePOSIX wraps s in single quotes for POSIX-family shells (bash, zsh). Inside single quotes
// every byte is literal except the single quote itself, which is emitted with the '\” idiom:
// close the quote, add an escaped literal quote, reopen the quote. This is injection-proof for
// any input.
func quotePOSIX(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// quoteFish wraps s in single quotes for fish, whose single-quoted strings — unlike POSIX —
// treat backslash and single-quote as escapable. Both are backslash-escaped (backslash first,
// so the escapes added for quotes are not themselves doubled); everything else is literal.
func quoteFish(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `'`, `\'`)
	return "'" + s + "'"
}
