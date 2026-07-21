package scan

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
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/carapace-sh/carapace"
)

// actionValues invokes an Action and extracts its candidate values, for tests that need to assert
// on what a completer actually offers rather than just its side effects. It goes through JSON
// (InvokedAction has no exported value accessor) — good enough for a test helper.
func actionValues(t *testing.T, a carapace.Action) []string {
	t.Helper()
	raw, err := a.Invoke(carapace.NewContext()).MarshalJSON()
	if err != nil {
		t.Fatalf("marshal invoked action: %v", err)
	}
	var exported struct {
		Values []struct {
			Value string `json:"value"`
		} `json:"values"`
	}
	if err := json.Unmarshal(raw, &exported); err != nil {
		t.Fatalf("unmarshal invoked action: %v", err)
	}
	values := make([]string, 0, len(exported.Values))
	for _, v := range exported.Values {
		values = append(values, v.Value)
	}
	return values
}

// A faithful slice of nmap's real script.db format.
const scriptDBSample = `Entry { filename = "acarsd-info.nse", categories = { "discovery", "safe", } }
Entry { filename = "afp-brute.nse", categories = { "brute", "intrusive", } }
Entry { filename = "http-title.nse", categories = { "default", "discovery", "safe", } }
# a comment line that must be ignored
Entry { filename = "smb-os-discovery.nse", categories = { "default", "discovery", "safe", } }`

func TestParseScriptDB(t *testing.T) {
	scripts, categories := parseScriptDB(strings.NewReader(scriptDBSample))

	if len(scripts) != 4 {
		t.Fatalf("want 4 scripts parsed, got %d (%v)", len(scripts), scripts)
	}

	// Scripts are sorted by name; names carry the .nse stripped, and each keeps its own category
	// slice (the grouping axis) rather than a joined string.
	want := map[string]string{
		"acarsd-info":      "discovery,safe",
		"afp-brute":        "brute,intrusive",
		"http-title":       "default,discovery,safe",
		"smb-os-discovery": "default,discovery,safe",
	}
	for _, s := range scripts {
		cats, ok := want[s.name]
		if !ok {
			t.Errorf("unexpected script %q", s.name)
			continue
		}
		if got := strings.Join(s.cats, ","); got != cats {
			t.Errorf("script %q: want categories %q, got %q", s.name, cats, got)
		}
	}

	// Categories are the sorted union plus the synthetic "all".
	catSet := map[string]bool{}
	for _, c := range categories {
		catSet[c] = true
	}
	for _, must := range []string{"all", "brute", "default", "discovery", "intrusive", "safe"} {
		if !catSet[must] {
			t.Errorf("missing category %q in %v", must, categories)
		}
	}

	// Sorted ascending.
	for i := 1; i < len(categories); i++ {
		if categories[i-1] > categories[i] {
			t.Errorf("categories not sorted: %v", categories)
			break
		}
	}
}

func TestParseScriptDBEmpty(t *testing.T) {
	scripts, categories := parseScriptDB(strings.NewReader("garbage\nno entries here\n"))
	if len(scripts) != 0 {
		t.Errorf("want no scripts, got %v", scripts)
	}
	// Even with no entries, the synthetic "all" selector is present.
	if len(categories) != 1 || categories[0] != "all" {
		t.Errorf("want just [all], got %v", categories)
	}
}

// TestClassifyNmapFlag pins the flag grouping. AIMS no longer defines nmap flags (the bridge
// supplies value + description); it only assigns each a group tag, so this guards the classifier
// that turns the bridge's flat list into nmap --help-style sections. The tricky cases are the ones
// that share a prefix with a broader bucket: -sV/-sC/-sn must not fall into the generic "-s" scan
// techniques group.
func TestClassifyNmapFlag(t *testing.T) {
	cases := map[string]string{
		"-sS":           "scan techniques",
		"-sU":           "scan techniques",
		"-sV":           "service / OS detection",
		"-O":            "service / OS detection",
		"-A":            "service / OS detection",
		"-sC":           "scripts (NSE)",
		"--script":      "scripts (NSE)",
		"--script-help": "scripts (NSE)",
		"--script-args": "scripts (NSE)",
		"-T4":           "timing & performance",
		"--min-rate":    "timing & performance",
		"--max-retries": "timing & performance",
		"-p":            "port specification",
		"-F":            "port specification",
		"--top-ports":   "port specification",
		"-Pn":           "host discovery",
		"-sn":           "host discovery",
		"-PS":           "host discovery",
		"--dns-servers": "host discovery",
		"--traceroute":  "host discovery",
		"-oX":           "output",
		"-oA":           "output",
		"-v":            "output",
		"-f":            "firewall / IDS evasion",
		"--spoof-mac":   "firewall / IDS evasion",
		"--data-length": "firewall / IDS evasion",
		"-iL":           "target specification",
		"--exclude":     "target specification",
		"--excludefile": "target specification",
		"-6":            "other nmap flags",
		"--datadir":     "other nmap flags",
	}
	for flag, want := range cases {
		if got := classifyNmapFlag(flag); got != want {
			t.Errorf("classifyNmapFlag(%q) = %q, want %q", flag, got, want)
		}
	}
}

// TestCuratedNmapFlags guards the AIMS-owned flag set: it must be well-formed (flag, description)
// pairs with no empties and no leading-dash-less tokens, no duplicate flags, and it must carry the
// high-value modern flags a stale system `_nmap` tends to drop — above all --script, the flag AIMS
// integrates NSE completion for.
func TestCuratedNmapFlags(t *testing.T) {
	pairs := curatedNmapFlags()
	if len(pairs)%2 != 0 {
		t.Fatalf("curatedNmapFlags must be (flag, description) pairs, got odd length %d", len(pairs))
	}

	seen := map[string]bool{}
	for i := 0; i < len(pairs); i += 2 {
		flag, desc := pairs[i], pairs[i+1]
		if !strings.HasPrefix(flag, "-") {
			t.Errorf("%q is not a flag (want a leading -)", flag)
		}
		if strings.TrimSpace(desc) == "" {
			t.Errorf("flag %q has an empty description", flag)
		}
		if seen[flag] {
			t.Errorf("flag %q listed more than once", flag)
		}
		seen[flag] = true
	}

	for _, must := range []string{"--script", "-sC", "-sV", "-sn", "-Pn", "-oA", "-T4", "--min-rate", "-A", "-O"} {
		if !seen[must] {
			t.Errorf("curated flag set is missing %q", must)
		}
	}

	// curatedFlagNames must be the flags (the even indices) plus one name per nmapFlagFamilies
	// placeholder, so the bridge filter dedups both the curated flags and the family placeholders.
	want := len(pairs)/2 + len(nmapFlagFamilies)
	if got := len(curatedFlagNames()); got != want {
		t.Errorf("curatedFlagNames returned %d names, want %d", got, want)
	}
}

// TestCollapsedNmapFlags guards the bare-`-` declutter: every nmapFlagFamilies variant collapses to
// exactly one placeholder entry per family, everything else passes through untouched, and the
// placeholder is keyed by the family prefix itself so classifyNmapFlag still buckets it sensibly.
func TestCollapsedNmapFlags(t *testing.T) {
	pairs := curatedNmapFlags()
	collapsed := collapsedNmapFlags(pairs)

	if len(collapsed)%2 != 0 {
		t.Fatalf("collapsedNmapFlags must be (flag, description) pairs, got odd length %d", len(collapsed))
	}

	seenFam := map[string]int{}
	seenFlag := map[string]bool{}
	for i := 0; i < len(collapsed); i += 2 {
		flag := collapsed[i]
		seenFlag[flag] = true
		if _, ok := nmapFlagFamilies[flag]; ok {
			seenFam[flag]++
		}
	}

	for fam := range nmapFlagFamilies {
		if seenFam[fam] != 1 {
			t.Errorf("family placeholder %q appears %d times in collapsedNmapFlags, want 1", fam, seenFam[fam])
		}
	}

	// Every original variant (-sS, -Pn, -oA, -T4, -iL, …) must be gone, replaced by its family.
	for i := 0; i < len(pairs); i += 2 {
		flag := pairs[i]
		if fam, isVariant := nmapFlagFamilyOf(flag); isVariant {
			if seenFlag[flag] {
				t.Errorf("variant %q (family %q) still present in collapsedNmapFlags, want collapsed", flag, fam)
			}
		} else if !seenFlag[flag] {
			t.Errorf("non-variant flag %q dropped by collapsedNmapFlags", flag)
		}
	}

	// A flag not owned by any curated pair (e.g. plain "-p") is not a family variant.
	if fam, isVariant := nmapFlagFamilyOf("-p"); isVariant {
		t.Errorf("-p misclassified as a variant of family %q", fam)
	}
}

// TestNmapFlagCompletionsBareDash checks the dispatch nmapFlagCompletions is built for: at a bare
// `-` it must use the collapsed set (no -sS/-sT/… individually), and once a family prefix has been
// typed (e.g. "-s") it must fall back to the full curated set so the variants are reachable.
func TestNmapFlagCompletionsBareDash(t *testing.T) {
	has := func(vs []string, want string) bool {
		return slices.Contains(vs, want)
	}

	bareValues := actionValues(t, nmapFlagCompletions("-"))
	if !has(bareValues, "-s") {
		t.Errorf("bare `-` completion missing the collapsed \"-s\" placeholder: %v", bareValues)
	}
	if has(bareValues, "-sS") {
		t.Errorf("bare `-` completion still lists a scan-technique variant \"-sS\" instead of collapsing it: %v", bareValues)
	}

	expandedValues := actionValues(t, nmapFlagCompletions("-s"))
	if !has(expandedValues, "-sS") {
		t.Errorf("`-s`-prefixed completion should expose the \"-sS\" variant, got: %v", expandedValues)
	}
}

// A faithful slice of an NSE header: a name-only arg, and a description that wraps across comment
// lines and is terminated by the next @tag.
const nseArgsSample = `local shortport = require "shortport"

---
-- Does a thing to a host.
--
-- @usage nmap --script foo --script-args foo.timeout=5
-- @args foo.timeout  Timeout in seconds. Defaults
--       to 10 seconds.
-- @args foo.retries Number of retries
-- @args foo.host
-- @output
-- | foo: bar
--
author = "someone"
`

// TestParseNSEArgs pins the @args extraction: multi-line descriptions are folded, a name-only arg
// keeps an empty description, and neither the code lines nor the other @tags leak in.
func TestParseNSEArgs(t *testing.T) {
	args := parseNSEArgs(strings.NewReader(nseArgsSample))

	want := map[string]string{
		"foo.timeout": "Timeout in seconds. Defaults to 10 seconds.",
		"foo.retries": "Number of retries",
		"foo.host":    "",
	}
	if len(args) != len(want) {
		t.Fatalf("want %d args, got %d (%v)", len(want), len(args), args)
	}
	for _, a := range args {
		w, ok := want[a[0]]
		if !ok {
			t.Errorf("unexpected arg %q", a[0])
			continue
		}
		if a[1] != w {
			t.Errorf("arg %q: want description %q, got %q", a[0], w, a[1])
		}
	}
}

// TestNSEArgValueKind guards the value-side dispatch: which NSE args borrow an existing AIMS
// completer. The subtle cases are the ones that share a substring with another kind — userdb/passdb
// are wordlist files, not usernames; passvar/passlimit/useragent are free-form, not files or creds.
func TestNSEArgValueKind(t *testing.T) {
	cases := map[string]string{
		"http-enum.host":            "host",
		"ssl.host":                  "host",
		"target":                    "host",
		"mssql.username":            "username",
		"smbusername":               "username",
		"userdb":                    "file",
		"passdb":                    "file",
		"brute.outputfile":          "file",
		"smtp.domain":               "domain",
		"http-enum.basepath":        "",
		"http-form-brute.passvar":   "",
		"unpwdb.passlimit":          "",
		"http.useragent":            "",
		"creds.global":              "",
		"broadcast-*.interface":     "interface",
		"snmp.interface":            "interface",
		"smtp.port":                 "port",
		"port":                      "port",
		"smbpassword":               "secret",
		"mssql.password":            "secret",
		"ssh.passphrase":            "secret",
		"http-enum.url":             "url",
		"spider.uri":                "url",
		"dns-brute.domain":          "domain",
		"ldap.domains":              "domain",
		"smbdomain":                 "domain",
		"http-domino.withindomain":  "domain",
		"broadcast-wake-on-lan.MAC": "mac",
		"targets-mac.mac":           "mac",
	}
	for k, want := range cases {
		if got := nseArgValueKind(k); got != want {
			t.Errorf("nseArgValueKind(%q) = %q, want %q", k, got, want)
		}
	}
}

// TestCuratedMasscanFlags guards the second scanner's AIMS-owned flag set: well-formed
// (flag, description) pairs, no empties, no dashless tokens, no duplicates, and the high-value flags
// an operator reaches for (-p, --rate, --banners, -oX for the XML the driver folds).
func TestCuratedMasscanFlags(t *testing.T) {
	pairs := curatedMasscanFlags()
	if len(pairs)%2 != 0 {
		t.Fatalf("curatedMasscanFlags must be (flag, description) pairs, got odd length %d", len(pairs))
	}
	seen := map[string]bool{}
	for i := 0; i < len(pairs); i += 2 {
		flag, desc := pairs[i], pairs[i+1]
		if !strings.HasPrefix(flag, "-") {
			t.Errorf("%q is not a flag (want a leading -)", flag)
		}
		if strings.TrimSpace(desc) == "" {
			t.Errorf("flag %q has an empty description", flag)
		}
		if seen[flag] {
			t.Errorf("flag %q listed more than once", flag)
		}
		seen[flag] = true
	}
	for _, must := range []string{"-p", "--rate", "--banners", "-oX", "--exclude"} {
		if !seen[must] {
			t.Errorf("curated masscan flag set is missing %q", must)
		}
	}
}

// TestClassifyMasscanFlag pins the masscan flag grouping.
func TestClassifyMasscanFlag(t *testing.T) {
	cases := map[string]string{
		"-p":           "ports & targets",
		"--ports":      "ports & targets",
		"--exclude":    "ports & targets",
		"--rate":       "rate & performance",
		"--retries":    "rate & performance",
		"--banners":    "probes & detail",
		"--open":       "probes & detail",
		"-e":           "interface / link layer",
		"--router-mac": "interface / link layer",
		"-oX":          "output",
		"-oJ":          "output",
		"--resume":     "other masscan flags",
	}
	for flag, want := range cases {
		if got := classifyMasscanFlag(flag); got != want {
			t.Errorf("classifyMasscanFlag(%q) = %q, want %q", flag, got, want)
		}
	}
}

// TestScriptSelectorsFromArgs checks we recover the --script selection from the raw token stream in
// both `--script v` and `--script=v` forms, split on commas, without mistaking --script-args or
// --script-help for --script.
func TestScriptSelectorsFromArgs(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want []string
	}{
		{"spaced", []string{"10.0.0.1", "--script", "http-title,safe", "--script-args"}, []string{"http-title", "safe"}},
		{"equals", []string{"--script=http-*", "--script-args"}, []string{"http-*"}},
		{"none", []string{"10.0.0.1", "--script-args"}, nil},
		{"not-confused-by-siblings", []string{"--script-help", "--script-args", "--script-updatedb"}, nil},
		{"trims-and-drops-empty", []string{"--script", "a, ,b,"}, []string{"a", "b"}},
		{"multiple-flags", []string{"--script", "vuln", "--script=auth"}, []string{"vuln", "auth"}},
	}
	for _, c := range cases {
		got := scriptSelectorsFromArgs(c.args)
		if strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Errorf("%s: scriptSelectorsFromArgs(%v) = %v, want %v", c.name, c.args, got, c.want)
		}
	}
}

// TestUsedNSEArgKeys pins the key extraction completeNSEScriptArgs uses to dedup: each already-typed
// `--script-args` comma segment contributes its key (up to "="), blank/empty segments are dropped,
// and a bare key with no "=" yet (still mid-typing) still counts as used.
func TestUsedNSEArgKeys(t *testing.T) {
	cases := []struct {
		name  string
		parts []string
		want  []string
	}{
		{"empty", nil, nil},
		{"single", []string{"http.useragent=Mozilla"}, []string{"http.useragent"}},
		{"multiple", []string{"http.useragent=Mozilla", "smbdomain=WORKGROUP"}, []string{"http.useragent", "smbdomain"}},
		{"bare-key-no-value-yet", []string{"http.useragent"}, []string{"http.useragent"}},
		{"drops-blank-segments", []string{"a=1", "", "  ", "b=2"}, []string{"a", "b"}},
		{"value-containing-equals", []string{"userdb=admin=root"}, []string{"userdb"}},
	}
	for _, c := range cases {
		got := usedNSEArgKeys(c.parts)
		if strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Errorf("%s: usedNSEArgKeys(%v) = %v, want %v", c.name, c.parts, got, c.want)
		}
	}
}

// TestSelectScriptRefs pins selector resolution: exact name, category, wildcard, `all`, a script
// path, a miss, and de-duplicated unions — all name-sorted.
func TestSelectScriptRefs(t *testing.T) {
	refs := []nseScriptRef{
		{name: "ftp-brute", cats: []string{"brute", "intrusive"}},
		{name: "http-enum", cats: []string{"discovery", "intrusive"}},
		{name: "http-title", cats: []string{"default", "discovery", "safe"}},
		{name: "smb-os-discovery", cats: []string{"default", "safe"}},
	}
	names := func(rs []nseScriptRef) string {
		var ns []string
		for _, r := range rs {
			ns = append(ns, r.name)
		}
		return strings.Join(ns, ",")
	}

	cases := []struct {
		name string
		sels []string
		want string
	}{
		{"exact", []string{"http-title"}, "http-title"},
		{"category", []string{"safe"}, "http-title,smb-os-discovery"},
		{"wildcard", []string{"http-*"}, "http-enum,http-title"},
		{"all", []string{"all"}, "ftp-brute,http-enum,http-title,smb-os-discovery"},
		{"category-intrusive", []string{"intrusive"}, "ftp-brute,http-enum"},
		{"path-form", []string{"scripts/http-title.nse"}, "http-title"},
		{"miss", []string{"nope"}, ""},
		{"union-dedup", []string{"safe", "http-title"}, "http-title,smb-os-discovery"},
		{"empty", nil, ""},
	}
	for _, c := range cases {
		if got := names(selectScriptRefs(refs, c.sels)); got != c.want {
			t.Errorf("%s: selectScriptRefs(%v) = %q, want %q", c.name, c.sels, got, c.want)
		}
	}
}
