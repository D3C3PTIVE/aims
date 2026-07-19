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
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// fakeAims stands in for the real `aims` binary on PATH: `aims bring <id>` prints the payload from
// $AIMS_TEST_PAYLOAD verbatim. This lets the generated zsh integration be exercised end to end
// without a teamserver or the c2 data model.
const fakeAims = `#!/bin/sh
if [ "$1" = bring ]; then
  printf '%s' "$AIMS_TEST_PAYLOAD"
  exit 0
fi
echo "fake aims: unsupported args: $*" >&2
exit 1
`

// payloadLine builds one key<TAB>value payload line the way cmd/bring.writePayload does: the value
// is display-sanitized, then joined to its key by a tab.
func payloadLine(key, value string) string {
	return key + "\t" + SanitizeDisplay(value) + "\n"
}

// runZshBring generates the zsh integration, sources it in a clean `zsh -f`, runs `bring testid`
// against the given payload, forces a hostile prompt render, then `leave`s. It returns the printed
// KEY=VALUE report and the working directory, so callers can assert both the applied context and
// that no payload byte executed (which would leave a stray file behind).
func runZshBring(t *testing.T, payload string) (map[string]string, string) {
	t.Helper()
	zsh, err := exec.LookPath("zsh")
	if err != nil {
		t.Skip("no zsh on PATH")
	}

	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "aims"), []byte(fakeAims), 0o755); err != nil {
		t.Fatal(err)
	}

	var initBuf bytes.Buffer
	if err := Init(&initBuf, Zsh); err != nil {
		t.Fatalf("Init(zsh): %v", err)
	}
	initPath := filepath.Join(dir, "init.zsh")
	if err := os.WriteFile(initPath, initBuf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	// The runner drives one bring/leave cycle and reports the resulting shell state. `setopt
	// prompt_subst` + `${(%)PROMPT}` forces a full prompt expansion — the exact place a hostile
	// agent name could execute if it were not sanitized.
	const runner = `
source "$1"
bring testid
print -r -- "ID=$AIMS_AGENT_ID"
print -r -- "NAME=$AIMS_AGENT_NAME"
print -r -- "TOOL=$AIMS_AGENT_TOOL"
print -r -- "CWD=$AIMS_AGENT_CWD"
print -r -- "PROMPT=$PROMPT"
print -r -- "AIMSI=${aliases[aimsi]}"
setopt prompt_subst
: "${(%)PROMPT}"
leave
print -r -- "AFTER_ID=$AIMS_AGENT_ID"
print -r -- "AFTER_PROMPT=$PROMPT"
`
	runnerPath := filepath.Join(dir, "runner.zsh")
	if err := os.WriteFile(runnerPath, []byte(runner), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(zsh, "-f", runnerPath, initPath)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"AIMS_TEST_PAYLOAD="+payload,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("zsh runner failed: %v\n%s", err, out)
	}

	report := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		if kv := strings.SplitN(line, "=", 2); len(kv) == 2 {
			report[kv[0]] = kv[1]
		}
	}
	return report, dir
}

// assertNoStrayFiles fails if the bring cycle created any file beyond the fixtures — evidence that
// a payload value was executed rather than treated as inert data.
func assertNoStrayFiles(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		switch e.Name() {
		case "bin", "init.zsh", "runner.zsh":
		default:
			t.Errorf("bring created unexpected file %q — a payload value executed", e.Name())
		}
	}
}

// TestZshBringAppliesContext is the happy path: a benign agent context is exported, the prompt gains
// the agent segment, `aimsi` is bound to the agent, and `leave` restores the shell.
func TestZshBringAppliesContext(t *testing.T) {
	payload := payloadLine(KeyID, "testid") +
		payloadLine(KeyName, "web01") +
		payloadLine(KeyTool, "sliver") +
		payloadLine(KeyCWD, "/root")

	r, dir := runZshBring(t, payload)

	if r["ID"] != "testid" {
		t.Errorf("AIMS_AGENT_ID = %q, want testid", r["ID"])
	}
	if r["NAME"] != "web01" {
		t.Errorf("AIMS_AGENT_NAME = %q, want web01", r["NAME"])
	}
	if !strings.Contains(r["PROMPT"], "[web01]") {
		t.Errorf("PROMPT = %q, want it to contain [web01]", r["PROMPT"])
	}
	if !strings.Contains(r["AIMSI"], "aims c2 task") {
		t.Errorf("aimsi alias = %q, want it to invoke `aims c2 task`", r["AIMSI"])
	}
	if r["AFTER_ID"] != "" {
		t.Errorf("after leave, AIMS_AGENT_ID = %q, want empty", r["AFTER_ID"])
	}
	assertNoStrayFiles(t, dir)
}

// TestZshBringDoesNotExecuteHostileValues feeds attacker-controlled agent strings and asserts they
// are handled as inert data: a command-substitution name is defeated by sanitization, and a
// quote/semicolon break-out is defeated by capture-as-data (read -r never evals). Nothing runs.
func TestZshBringDoesNotExecuteHostileValues(t *testing.T) {
	payload := payloadLine(KeyID, "testid") +
		payloadLine(KeyName, "$(touch PWNED)") + // sanitized to (touch PWNED)
		payloadLine(KeyTool, "x'; touch PWNED2; #") + // survives sanitize; must stay inert data
		payloadLine(KeyCWD, "/root")

	r, dir := runZshBring(t, payload)

	if strings.Contains(r["NAME"], "$(") {
		t.Errorf("hostile name reached the shell with substitution intact: %q", r["NAME"])
	}
	if r["ID"] != "testid" {
		t.Errorf("AIMS_AGENT_ID = %q, want testid (context still applied)", r["ID"])
	}
	assertNoStrayFiles(t, dir)
}
