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
if [ "$1" = prompt ]; then
  # --terse mode for the shell prompt integration: emit the test-provided fields as one
  # scans<TAB>version<TAB>connected line. Any var left unset yields an empty field, which the poll
  # treats as "no update".
  printf '%s\t%s\t%s\n' "${AIMS_TEST_SCAN_COUNT}" "${AIMS_TEST_SERVER_VERSION}" "${AIMS_TEST_SERVER_CONN}"
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
print -r -- "ROUTE=$AIMS_AGENT_ROUTE"
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

// TestZshBringShowsRoute checks the network-path prompt element appears when the agent context
// carries a route summary.
func TestZshBringShowsRoute(t *testing.T) {
	payload := payloadLine(KeyID, "testid") +
		payloadLine(KeyName, "web01") +
		payloadLine(KeyRoute, "3h·gw01") +
		payloadLine(KeyPending, "0")

	r, _ := runZshScript(t, map[string]string{"agent": payload}, singleBringRunner)

	if r["ROUTE"] != "3h·gw01" {
		t.Errorf("AIMS_AGENT_ROUTE = %q, want 3h·gw01", r["ROUTE"])
	}
	if !strings.Contains(r["PROMPT"], "⤳3h·gw01") {
		t.Errorf("PROMPT = %q, want it to surface the route ⤳3h·gw01", r["PROMPT"])
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
print -r -- "D2_ROUTE=$AIMS_AGENT_ROUTE"
print -r -- "D2_DEPTH=$AIMS_CONTEXT_DEPTH"
print -r -- "D2_PROMPT=$PROMPT"
leave
print -r -- "P1_ID=$AIMS_AGENT_ID"
print -r -- "P1_NAME=$AIMS_AGENT_NAME"
print -r -- "P1_ROUTE=$AIMS_AGENT_ROUTE"
print -r -- "P1_DEPTH=$AIMS_CONTEXT_DEPTH"
leave
print -r -- "P0_ID=$AIMS_AGENT_ID"
print -r -- "P0_DEPTH=$AIMS_CONTEXT_DEPTH"
print -r -- "P0_PROMPT=$PROMPT"
`

// TestZshBringNesting verifies the P2 context stack: a second bring stacks the first, the depth
// tracks, and each leave pops back — the last one fully restoring the original prompt.
func TestZshBringNesting(t *testing.T) {
	one := payloadLine(KeyID, "one-id") + payloadLine(KeyName, "alpha") + payloadLine(KeyRoute, "2h·gwA") + payloadLine(KeyPending, "0")
	two := payloadLine(KeyID, "two-id") + payloadLine(KeyName, "beta") + payloadLine(KeyRoute, "5h·gwB") + payloadLine(KeyPending, "0")

	r, dir := runZshScript(t, map[string]string{"one": one, "two": two}, nestingRunner)

	// After bringing 'one'.
	if r["D1_ID"] != "one-id" || r["D1_DEPTH"] != "1" {
		t.Errorf("after bring one: id=%q depth=%q, want one-id / 1", r["D1_ID"], r["D1_DEPTH"])
	}
	// After nesting 'two'.
	if r["D2_ID"] != "two-id" || r["D2_NAME"] != "beta" || r["D2_DEPTH"] != "2" {
		t.Errorf("after bring two: id=%q name=%q depth=%q, want two-id / beta / 2", r["D2_ID"], r["D2_NAME"], r["D2_DEPTH"])
	}
	if r["D2_ROUTE"] != "5h·gwB" {
		t.Errorf("after bring two: route=%q, want 5h·gwB", r["D2_ROUTE"])
	}
	if !strings.Contains(r["D2_PROMPT"], "beta") {
		t.Errorf("nested prompt = %q, want it to show the current agent beta", r["D2_PROMPT"])
	}
	// First leave pops back to 'one' — including its route, restored from the stack.
	if r["P1_ID"] != "one-id" || r["P1_NAME"] != "alpha" || r["P1_DEPTH"] != "1" {
		t.Errorf("after first leave: id=%q name=%q depth=%q, want one-id / alpha / 1", r["P1_ID"], r["P1_NAME"], r["P1_DEPTH"])
	}
	if r["P1_ROUTE"] != "2h·gwA" {
		t.Errorf("after first leave: route=%q, want 2h·gwA (restored from stack)", r["P1_ROUTE"])
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

// promptPollRunner sources the integration and invokes the precmd poll once directly (a script has no
// prompt, so the registered precmd hook never fires on its own), then reports the resulting RPROMPT.
// The single poll fetches every right-prompt field (scans + server version + operators) at once.
const promptPollRunner = `
source "$1"
print -r -- "BASE_RPROMPT=$RPROMPT"
_aims_prompt_poll
print -r -- "RPROMPT=$RPROMPT"
`

// TestZshScanIndicatorShowsRunningCount checks the right-prompt running-scan indicator surfaces the
// scan field of `aims prompt --terse`, and composes with the operator's own RPROMPT.
func TestZshScanIndicatorShowsRunningCount(t *testing.T) {
	t.Setenv("AIMS_TEST_SCAN_COUNT", "2")

	r, dir := runZshScript(t, nil, `RPROMPT='%~'`+"\n"+promptPollRunner)

	// The count carries a "scans" label so the glyph alone never has to convey the meaning.
	if !strings.Contains(r["RPROMPT"], "⟳2 scans") {
		t.Errorf("RPROMPT = %q, want it to contain the labelled running-scan indicator ⟳2 scans", r["RPROMPT"])
	}
	// The indicator prefixes, not replaces, the pre-existing right prompt.
	if !strings.Contains(r["RPROMPT"], "%~") {
		t.Errorf("RPROMPT = %q, want it to preserve the operator's own right prompt %%~", r["RPROMPT"])
	}
	assertNoStrayFiles(t, dir)
}

// TestZshScanIndicatorSingularLabel checks the label is singular for a single running scan.
func TestZshScanIndicatorSingularLabel(t *testing.T) {
	t.Setenv("AIMS_TEST_SCAN_COUNT", "1")

	r, _ := runZshScript(t, nil, `RPROMPT='%~'`+"\n"+promptPollRunner)

	if !strings.Contains(r["RPROMPT"], "⟳1 scan") || strings.Contains(r["RPROMPT"], "⟳1 scans") {
		t.Errorf("RPROMPT = %q, want the singular label ⟳1 scan", r["RPROMPT"])
	}
}

// TestZshScanIndicatorHiddenWhenIdle checks that with no running scans (and no server version) the
// indicator adds nothing — the right prompt is exactly what the operator had.
func TestZshScanIndicatorHiddenWhenIdle(t *testing.T) {
	t.Setenv("AIMS_TEST_SCAN_COUNT", "0")

	r, _ := runZshScript(t, nil, `RPROMPT='%~'`+"\n"+promptPollRunner)

	if strings.Contains(r["RPROMPT"], "⟳") {
		t.Errorf("RPROMPT = %q, want no scan indicator when the count is 0", r["RPROMPT"])
	}
	if r["RPROMPT"] != "%~" {
		t.Errorf("RPROMPT = %q, want the untouched operator prompt %%~", r["RPROMPT"])
	}
}

// TestZshScanIndicatorDisabled checks the AIMS_SCAN_PROMPT=0 opt-out fully suppresses the scan
// segment even while scans are running.
func TestZshScanIndicatorDisabled(t *testing.T) {
	t.Setenv("AIMS_TEST_SCAN_COUNT", "5")
	t.Setenv("AIMS_SCAN_PROMPT", "0")

	r, _ := runZshScript(t, nil, `RPROMPT='%~'`+"\n"+promptPollRunner)

	if strings.Contains(r["RPROMPT"], "⟳") {
		t.Errorf("RPROMPT = %q, want no scan indicator when AIMS_SCAN_PROMPT=0", r["RPROMPT"])
	}
}

// TestZshServerIndicatorShowsVersionAndOperators checks the right-prompt server segment surfaces the
// version and connected-operator fields of `aims prompt --terse`, labelled and composing with the
// operator's own RPROMPT.
func TestZshServerIndicatorShowsVersionAndOperators(t *testing.T) {
	t.Setenv("AIMS_TEST_SCAN_COUNT", "0")
	t.Setenv("AIMS_TEST_SERVER_VERSION", "0.4.0")
	t.Setenv("AIMS_TEST_SERVER_CONN", "2")

	r, dir := runZshScript(t, nil, `RPROMPT='%~'`+"\n"+promptPollRunner)

	if !strings.Contains(r["RPROMPT"], "aims v0.4.0") {
		t.Errorf("RPROMPT = %q, want it to contain the server version aims v0.4.0", r["RPROMPT"])
	}
	// The operator count carries an "ops" label so a bare number never floats unexplained.
	if !strings.Contains(r["RPROMPT"], "·2 ops") {
		t.Errorf("RPROMPT = %q, want it to contain the labelled operator count ·2 ops", r["RPROMPT"])
	}
	// No scans running: the server segment shows but the scan glyph must not.
	if strings.Contains(r["RPROMPT"], "⟳") {
		t.Errorf("RPROMPT = %q, want no scan indicator when the count is 0", r["RPROMPT"])
	}
	if !strings.Contains(r["RPROMPT"], "%~") {
		t.Errorf("RPROMPT = %q, want it to preserve the operator's own right prompt %%~", r["RPROMPT"])
	}
	assertNoStrayFiles(t, dir)
}

// TestZshServerIndicatorSingularOperator checks the operator label is singular for a single connected
// operator.
func TestZshServerIndicatorSingularOperator(t *testing.T) {
	t.Setenv("AIMS_TEST_SERVER_VERSION", "1.2.3")
	t.Setenv("AIMS_TEST_SERVER_CONN", "1")

	r, _ := runZshScript(t, nil, `RPROMPT='%~'`+"\n"+promptPollRunner)

	if !strings.Contains(r["RPROMPT"], "·1 op") || strings.Contains(r["RPROMPT"], "·1 ops") {
		t.Errorf("RPROMPT = %q, want the singular label ·1 op", r["RPROMPT"])
	}
}

// TestZshServerIndicatorDisabled checks AIMS_SERVER_PROMPT=0 suppresses the server segment even when
// the server reports a version, while the scan segment is unaffected.
func TestZshServerIndicatorDisabled(t *testing.T) {
	t.Setenv("AIMS_TEST_SCAN_COUNT", "3")
	t.Setenv("AIMS_TEST_SERVER_VERSION", "0.4.0")
	t.Setenv("AIMS_TEST_SERVER_CONN", "2")
	t.Setenv("AIMS_SERVER_PROMPT", "0")

	r, _ := runZshScript(t, nil, `RPROMPT='%~'`+"\n"+promptPollRunner)

	if strings.Contains(r["RPROMPT"], "aims v") {
		t.Errorf("RPROMPT = %q, want no server segment when AIMS_SERVER_PROMPT=0", r["RPROMPT"])
	}
	// The scan segment still renders — the toggles are independent.
	if !strings.Contains(r["RPROMPT"], "⟳3 scans") {
		t.Errorf("RPROMPT = %q, want the scan segment unaffected by AIMS_SERVER_PROMPT", r["RPROMPT"])
	}
}

// serverColor extracts the `%F{...}` color token immediately preceding the "aims v" server segment,
// so a test can assert how that segment is tinted without hardcoding the palette.
func serverColor(rprompt string) string {
	i := strings.Index(rprompt, "aims v")
	if i < 0 {
		return ""
	}
	prefix := rprompt[:i]
	j := strings.LastIndex(prefix, "%F{")
	if j < 0 {
		return ""
	}
	end := strings.Index(prefix[j:], "}")
	if end < 0 {
		return ""
	}
	return prefix[j : j+end+1]
}

// TestZshServerColorVariesByVersion checks the server segment is tinted with a color derived from the
// version, so two different versions render in different colors (stable per version).
func TestZshServerColorVariesByVersion(t *testing.T) {
	color := func(ver string) string {
		t.Setenv("AIMS_TEST_SERVER_VERSION", ver)
		t.Setenv("AIMS_TEST_SERVER_CONN", "1")
		r, _ := runZshScript(t, nil, `RPROMPT='%~'`+"\n"+promptPollRunner)
		c := serverColor(r["RPROMPT"])
		if c == "" {
			t.Fatalf("version %s: no %%F{...} color found before 'aims v' in RPROMPT %q", ver, r["RPROMPT"])
		}
		return c
	}

	// Two versions whose character sums land on different palette slots.
	if a, b := color("0.4.0"), color("0.5.1"); a == b {
		t.Errorf("server color did not vary by version: both %q rendered as %q", "0.4.0/0.5.1", a)
	}
}

// TestZshPromptCombined checks both right-prompt segments render together from a single poll: the
// server identity + operators followed by the running-scan indicator.
func TestZshPromptCombined(t *testing.T) {
	t.Setenv("AIMS_TEST_SCAN_COUNT", "2")
	t.Setenv("AIMS_TEST_SERVER_VERSION", "0.4.0")
	t.Setenv("AIMS_TEST_SERVER_CONN", "3")

	r, _ := runZshScript(t, nil, `RPROMPT='%~'`+"\n"+promptPollRunner)

	for _, want := range []string{"aims v0.4.0", "·3 ops", "⟳2 scans", "%~"} {
		if !strings.Contains(r["RPROMPT"], want) {
			t.Errorf("RPROMPT = %q, want it to contain %q", r["RPROMPT"], want)
		}
	}
}
