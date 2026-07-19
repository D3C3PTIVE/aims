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
	"os"
	"os/exec"
	"testing"
)

// adversarial holds the inputs a hostile implant might report as its name / working directory.
// Every one must survive quoting as inert data — reproduced verbatim, never executed.
var adversarial = []string{
	``,
	`web01`,
	`web-01.corp.local`,
	`with spaces`,
	`o'reilly`,               // a bare single quote
	`'; rm -rf ~; #`,         // break-out-and-run
	`web01'; touch OWNED; #`, // realistic hostile hostname
	`$(touch OWNED)`,         // command substitution
	"`touch OWNED`",          // backtick substitution
	`${IFS}${HOME}`,          // parameter expansion
	`a"b`,                    // a double quote
	`back\slash`,             // a backslash
	"tab\there",              // a tab
	"line1\nline2",           // a newline
	`;|&<>(){}[]*?!#~=`,      // metacharacters
	`%n%s%%`,                 // printf / zsh-prompt escapes
	"\\'\"$\x60",             // a mix of every quote/escape byte: backslash ' " $ `
}

// roundTrip runs `printf %s <quoted>` in the given shell binary and returns what it printed. If
// quoting is correct the output equals the original input for every case, and the side-effecting
// payloads (touch OWNED, rm) never run.
func roundTrip(t *testing.T, shellBin string, sh Shell) {
	t.Helper()
	dir := t.TempDir()
	for _, in := range adversarial {
		q := Quote(sh, in)
		cmd := exec.Command(shellBin, "-c", "printf %s "+q)
		cmd.Dir = dir // any stray file-creating payload lands (and is caught) here
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("%s rejected quoted input %q → %s: %v", sh, in, q, err)
		}
		if string(out) != in {
			t.Errorf("%s round-trip mismatch: input %q quoted %s → %q, want %q", sh, in, q, out, in)
		}
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("%s: quoting let a payload execute — unexpected files created: %v", sh, entries)
	}
}

// TestQuotePOSIXRoundTrip proves the bash/zsh (POSIX single-quote) quoting is injection-proof by
// feeding every adversarial input back through a real POSIX shell.
func TestQuotePOSIXRoundTrip(t *testing.T) {
	bin, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no POSIX sh on PATH")
	}
	// Both dialects share POSIX single-quote semantics, exercised via the same /bin/sh.
	roundTrip(t, bin, Bash)
	roundTrip(t, bin, Zsh)
}

// TestQuoteFishRoundTrip does the same for fish, whose single-quote rules differ. Skipped when
// fish is not installed.
func TestQuoteFishRoundTrip(t *testing.T) {
	bin, err := exec.LookPath("fish")
	if err != nil {
		t.Skip("no fish on PATH")
	}
	roundTrip(t, bin, Fish)
}

// TestQuotePOSIXExact pins the exact rendering so the algorithm can't silently change; runs with
// no external shell.
func TestQuotePOSIXExact(t *testing.T) {
	cases := map[string]string{
		``:      `''`,
		`abc`:   `'abc'`,
		`a'b`:   `'a'\''b'`,
		`'`:     `''\'''`,
		`a\b`:   `'a\b'`, // backslash is literal inside POSIX single quotes
		`$(id)`: `'$(id)'`,
	}
	for in, want := range cases {
		if got := Quote(Bash, in); got != want {
			t.Errorf("Quote(Bash, %q) = %q, want %q", in, got, want)
		}
	}
}

// TestQuoteFishExact pins fish's backslash-escaping rendering.
func TestQuoteFishExact(t *testing.T) {
	cases := map[string]string{
		``:     `''`,
		`abc`:  `'abc'`,
		`a'b`:  `'a\'b'`,
		`a\b`:  `'a\\b'`,
		`a\'b`: `'a\\\'b'`, // backslash doubled first, then the quote escaped
	}
	for in, want := range cases {
		if got := Quote(Fish, in); got != want {
			t.Errorf("Quote(Fish, %q) = %q, want %q", in, got, want)
		}
	}
}

func TestParse(t *testing.T) {
	ok := map[string]Shell{
		"bash":                   Bash,
		"ZSH":                    Zsh,
		"  fish  ":               Fish,
		"/usr/bin/zsh":           Zsh,
		"/bin/bash":              Bash,
		"/opt/homebrew/bin/fish": Fish,
	}
	for name, want := range ok {
		got, err := Parse(name)
		if err != nil {
			t.Errorf("Parse(%q) unexpected error: %v", name, err)
			continue
		}
		if got != want {
			t.Errorf("Parse(%q) = %v, want %v", name, got, want)
		}
	}

	for _, bad := range []string{"csh", "tcsh", "powershell", ""} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("Parse(%q) = nil error, want unsupported-shell error", bad)
		}
	}
}

func TestDetect(t *testing.T) {
	t.Setenv("SHELL", "/usr/bin/zsh")
	if got := Detect(); got != Zsh {
		t.Errorf("Detect() with SHELL=/usr/bin/zsh = %v, want zsh", got)
	}
	t.Setenv("SHELL", "")
	if got := Detect(); got != Bash {
		t.Errorf("Detect() with empty SHELL = %v, want bash (default)", got)
	}
}
