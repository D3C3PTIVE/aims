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
	"strings"
	"testing"

	pb "github.com/d3c3ptive/aims/host/pb"
	network "github.com/d3c3ptive/aims/network/pb"
)

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

// TestLocalityOf pins the target sub-grouping classifier: loopback, the private estate (RFC1918,
// ULA, link-local, in both address families), routable public space, and non-IP tokens.
func TestLocalityOf(t *testing.T) {
	cases := map[string]string{
		"127.0.0.1":       "loopback",
		"127.5.6.7":       "loopback",
		"::1":             "loopback",
		"10.0.0.5":        "private",
		"192.168.1.10":    "private",
		"172.16.0.1":      "private",
		"169.254.1.1":     "private", // link-local
		"fe80::1":         "private", // IPv6 link-local
		"fc00::1":         "private", // IPv6 ULA
		"8.8.8.8":         "routable",
		"1.1.1.1":         "routable",
		"2606:4700::1111": "routable",
		"  10.0.0.9  ":    "private", // surrounding whitespace tolerated
		"scanme.nmap.org": "",        // a hostname is not an IP literal
		"":                "",
		"not-an-ip":       "",
	}
	for addr, want := range cases {
		if got := localityOf(addr); got != want {
			t.Errorf("localityOf(%q) = %q, want %q", addr, got, want)
		}
	}
}

// TestHostLocality checks a host is bucketed by its first parseable address, and that a host known
// only by hostname (no parseable address) lands in the "no address" group.
func TestHostLocality(t *testing.T) {
	host := func(addrs ...string) *pb.Host {
		h := &pb.Host{}
		for _, a := range addrs {
			h.Addresses = append(h.Addresses, &network.Address{Addr: a})
		}
		return h
	}

	cases := []struct {
		name string
		host *pb.Host
		want string
	}{
		{"routable", host("8.8.8.8"), tagRoutable},
		{"private", host("192.168.0.1"), tagPrivate},
		{"loopback", host("127.0.0.1"), tagLoopback},
		{"first-parseable-wins", host("", "10.0.0.1", "8.8.8.8"), tagPrivate},
		{"no-parseable-address", host("", "web.example.com"), tagNoAddr},
		{"no-address-at-all", host(), tagNoAddr},
	}
	for _, c := range cases {
		if got := hostLocality(c.host); got != c.want {
			t.Errorf("%s: hostLocality = %q, want %q", c.name, got, c.want)
		}
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
		"-sC":            "scripts (NSE)",
		"--script":       "scripts (NSE)",
		"--script-help":  "scripts (NSE)",
		"--script-args":  "scripts (NSE)",
		"-T4":            "timing & performance",
		"--min-rate":     "timing & performance",
		"--max-retries":  "timing & performance",
		"-p":             "port specification",
		"-F":             "port specification",
		"--top-ports":    "port specification",
		"-Pn":            "host discovery",
		"-sn":            "host discovery",
		"-PS":            "host discovery",
		"--dns-servers":  "host discovery",
		"--traceroute":   "host discovery",
		"-oX":            "output",
		"-oA":            "output",
		"-v":             "output",
		"-f":             "firewall / IDS evasion",
		"--spoof-mac":    "firewall / IDS evasion",
		"--data-length":  "firewall / IDS evasion",
		"-iL":            "target specification",
		"--exclude":      "target specification",
		"--excludefile":  "target specification",
		"-6":             "other nmap flags",
		"--datadir":      "other nmap flags",
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

	// curatedFlagNames must be exactly the flags (the even indices), so the bridge filter dedups.
	if got := len(curatedFlagNames()); got != len(pairs)/2 {
		t.Errorf("curatedFlagNames returned %d names, want %d", got, len(pairs)/2)
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
		"http-enum.host":          "host",
		"ssl.host":                "host",
		"target":                  "host",
		"mssql.username":          "username",
		"smbusername":             "username",
		"userdb":                  "file",
		"passdb":                  "file",
		"brute.outputfile":        "file",
		"smtp.domain":             "",
		"http-enum.basepath":      "",
		"http-form-brute.passvar": "",
		"unpwdb.passlimit":        "",
		"http.useragent":          "",
		"creds.global":            "",
	}
	for k, want := range cases {
		if got := nseArgValueKind(k); got != want {
			t.Errorf("nseArgValueKind(%q) = %q, want %q", k, got, want)
		}
	}
}
