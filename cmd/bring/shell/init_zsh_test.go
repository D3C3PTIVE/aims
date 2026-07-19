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

// fakeAims stands in for the real `aims` binary on PATH: `aims bring <id>` prints the payload file
// named <id> under $AIMS_TEST_PAYLOAD_DIR. This drives the generated zsh integration end to end,
// with distinct payloads per agent id, without a teamserver or the c2 data model.
const fakeAims = `#!/bin/sh
if [ "$1" = bring ]; then
  cat "$AIMS_TEST_PAYLOAD_DIR/$2" 2>/dev/null || { echo "fake aims: no payload for '$2'" >&2; exit 1; }
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

// runZshScript generates the zsh integration, writes the given per-id payload files and the given
// runner body, then runs them under a clean `zsh -f`. It returns the printed KEY=VALUE report and
// the working directory (so callers can assert nothing executed).
func runZshScript(t *testing.T, payloads map[string]string, body string) (map[string]string, string) {
	t.Helper()
	zsh, err := exec.LookPath("zsh")
	if err != nil {
		t.Skip("no zsh on PATH")
	}

	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	pdir := filepath.Join(dir, "payloads")
	for _, d := range []string{bin, pdir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(bin, "aims"), []byte(fakeAims), 0o755); err != nil {
		t.Fatal(err)
	}
	for id, p := range payloads {
		if err := os.WriteFile(filepath.Join(pdir, id), []byte(p), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	var initBuf bytes.Buffer
	if err := Init(&initBuf, Zsh); err != nil {
		t.Fatalf("Init(zsh): %v", err)
	}
	initPath := filepath.Join(dir, "init.zsh")
	if err := os.WriteFile(initPath, initBuf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	runnerPath := filepath.Join(dir, "runner.zsh")
	if err := os.WriteFile(runnerPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(zsh, "-f", runnerPath, initPath)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"AIMS_TEST_PAYLOAD_DIR="+pdir,
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

// assertNoStrayFiles fails if the run created any file beyond the fixtures — evidence that a
// payload value was executed rather than treated as inert data.
func assertNoStrayFiles(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		switch e.Name() {
		case "bin", "payloads", "init.zsh", "runner.zsh":
		default:
			t.Errorf("run created unexpected file %q — a payload value executed", e.Name())
		}
	}
}

// singleBringRunner drives one bring/leave cycle and reports the resulting shell state. `setopt
// prompt_subst` + `${(%)PROMPT}` forces a full prompt expansion — the exact place a hostile agent
// name would execute if it were not sanitized.
const singleBringRunner = `
source "$1"
bring agent
print -r -- "ID=$AIMS_AGENT_ID"
print -r -- "NAME=$AIMS_AGENT_NAME"
print -r -- "TOOL=$AIMS_AGENT_TOOL"
print -r -- "CWD=$AIMS_AGENT_CWD"
print -r -- "PENDING=$AIMS_AGENT_PENDING"
print -r -- "DEPTH=$AIMS_CONTEXT_DEPTH"
print -r -- "PROMPT=$PROMPT"
print -r -- "AIMSI=${functions[aimsi]}"
setopt prompt_subst
: "${(%)PROMPT}"
leave
print -r -- "AFTER_ID=$AIMS_AGENT_ID"
`

// TestZshBringAppliesContext is the happy path: a benign agent context is exported, the prompt gains
// the agent segment, `aimsi` is bound to `aims c2 task`, and `leave` restores the shell.
func TestZshBringAppliesContext(t *testing.T) {
	payload := payloadLine(KeyID, "testid") +
		payloadLine(KeyName, "web01") +
		payloadLine(KeyTool, "sliver") +
		payloadLine(KeyCWD, "/root") +
		payloadLine(KeyPending, "0")

	r, dir := runZshScript(t, map[string]string{"agent": payload}, singleBringRunner)

	if r["ID"] != "testid" {
		t.Errorf("AIMS_AGENT_ID = %q, want testid", r["ID"])
	}
	if r["NAME"] != "web01" {
		t.Errorf("AIMS_AGENT_NAME = %q, want web01", r["NAME"])
	}
	if r["DEPTH"] != "1" {
		t.Errorf("AIMS_CONTEXT_DEPTH = %q, want 1", r["DEPTH"])
	}
	if !strings.Contains(r["PROMPT"], "[web01") {
		t.Errorf("PROMPT = %q, want it to contain [web01", r["PROMPT"])
	}
	if !strings.Contains(r["AIMSI"], "aims c2 task") {
		t.Errorf("aimsi function = %q, want it to invoke `aims c2 task`", r["AIMSI"])
	}
	if r["AFTER_ID"] != "" {
		t.Errorf("after leave, AIMS_AGENT_ID = %q, want empty", r["AFTER_ID"])
	}
	assertNoStrayFiles(t, dir)
}

// TestZshBringShowsPendingTasks checks the pending-task prompt element appears when there are
// pending tasks.
func TestZshBringShowsPendingTasks(t *testing.T) {
	payload := payloadLine(KeyID, "testid") +
		payloadLine(KeyName, "web01") +
		payloadLine(KeyPending, "3")

	r, _ := runZshScript(t, map[string]string{"agent": payload}, singleBringRunner)

	if r["PENDING"] != "3" {
		t.Errorf("AIMS_AGENT_PENDING = %q, want 3", r["PENDING"])
	}
	if !strings.Contains(r["PROMPT"], "3") {
		t.Errorf("PROMPT = %q, want it to surface the pending count", r["PROMPT"])
	}
}

// TestZshBringDoesNotExecuteHostileValues feeds attacker-controlled agent strings and asserts they
// are handled as inert data: a command-substitution name is defeated by sanitization, and a
// quote/semicolon break-out is defeated by capture-as-data (read -r never evals). Nothing runs.
func TestZshBringDoesNotExecuteHostileValues(t *testing.T) {
	payload := payloadLine(KeyID, "testid") +
		payloadLine(KeyName, "$(touch PWNED)") + // sanitized to (touch PWNED)
		payloadLine(KeyTool, "x'; touch PWNED2; #") + // survives sanitize; must stay inert data
		payloadLine(KeyCWD, "/root") +
		payloadLine(KeyPending, "0")

	r, dir := runZshScript(t, map[string]string{"agent": payload}, singleBringRunner)

	if strings.Contains(r["NAME"], "$(") {
		t.Errorf("hostile name reached the shell with substitution intact: %q", r["NAME"])
	}
	if r["ID"] != "testid" {
		t.Errorf("AIMS_AGENT_ID = %q, want testid (context still applied)", r["ID"])
	}
	assertNoStrayFiles(t, dir)
}

// nestingRunner brings two agents (stacking the first), then leaves twice, reporting the state at
// each step.
const nestingRunner = `
source "$1"
print -r -- "BASE_PROMPT=$PROMPT"
bring one
print -r -- "D1_ID=$AIMS_AGENT_ID"
print -r -- "D1_DEPTH=$AIMS_CONTEXT_DEPTH"
bring two
print -r -- "D2_ID=$AIMS_AGENT_ID"
print -r -- "D2_NAME=$AIMS_AGENT_NAME"
print -r -- "D2_DEPTH=$AIMS_CONTEXT_DEPTH"
print -r -- "D2_PROMPT=$PROMPT"
leave
print -r -- "P1_ID=$AIMS_AGENT_ID"
print -r -- "P1_NAME=$AIMS_AGENT_NAME"
print -r -- "P1_DEPTH=$AIMS_CONTEXT_DEPTH"
leave
print -r -- "P0_ID=$AIMS_AGENT_ID"
print -r -- "P0_DEPTH=$AIMS_CONTEXT_DEPTH"
print -r -- "P0_PROMPT=$PROMPT"
`

// TestZshBringNesting verifies the P2 context stack: a second bring stacks the first, the depth
// tracks, and each leave pops back — the last one fully restoring the original prompt.
func TestZshBringNesting(t *testing.T) {
	one := payloadLine(KeyID, "one-id") + payloadLine(KeyName, "alpha") + payloadLine(KeyPending, "0")
	two := payloadLine(KeyID, "two-id") + payloadLine(KeyName, "beta") + payloadLine(KeyPending, "0")

	r, dir := runZshScript(t, map[string]string{"one": one, "two": two}, nestingRunner)

	// After bringing 'one'.
	if r["D1_ID"] != "one-id" || r["D1_DEPTH"] != "1" {
		t.Errorf("after bring one: id=%q depth=%q, want one-id / 1", r["D1_ID"], r["D1_DEPTH"])
	}
	// After nesting 'two'.
	if r["D2_ID"] != "two-id" || r["D2_NAME"] != "beta" || r["D2_DEPTH"] != "2" {
		t.Errorf("after bring two: id=%q name=%q depth=%q, want two-id / beta / 2", r["D2_ID"], r["D2_NAME"], r["D2_DEPTH"])
	}
	if !strings.Contains(r["D2_PROMPT"], "beta") {
		t.Errorf("nested prompt = %q, want it to show the current agent beta", r["D2_PROMPT"])
	}
	// First leave pops back to 'one'.
	if r["P1_ID"] != "one-id" || r["P1_NAME"] != "alpha" || r["P1_DEPTH"] != "1" {
		t.Errorf("after first leave: id=%q name=%q depth=%q, want one-id / alpha / 1", r["P1_ID"], r["P1_NAME"], r["P1_DEPTH"])
	}
	// Second leave fully tears down and restores the base prompt.
	if r["P0_ID"] != "" || r["P0_DEPTH"] != "" {
		t.Errorf("after second leave: id=%q depth=%q, want both empty", r["P0_ID"], r["P0_DEPTH"])
	}
	if r["P0_PROMPT"] != r["BASE_PROMPT"] {
		t.Errorf("after full teardown, PROMPT = %q, want the base %q", r["P0_PROMPT"], r["BASE_PROMPT"])
	}
	assertNoStrayFiles(t, dir)
}
