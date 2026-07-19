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

	// Scripts are sorted by name; names carry the .nse stripped.
	want := map[string]string{
		"acarsd-info":      "discovery, safe",
		"afp-brute":        "brute, intrusive",
		"http-title":       "default, discovery, safe",
		"smb-os-discovery": "default, discovery, safe",
	}
	for _, s := range scripts {
		desc, ok := want[s[0]]
		if !ok {
			t.Errorf("unexpected script %q", s[0])
			continue
		}
		if s[1] != desc {
			t.Errorf("script %q: want categories %q, got %q", s[0], desc, s[1])
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

// TestNmapFlagGroups guards the curated flag set: every group is a well-formed described list
// (even length, no empty flag or description), tags are unique, and the highest-value flags the
// design contract calls out are actually present.
func TestNmapFlagGroups(t *testing.T) {
	groups := nmapFlagGroups()
	if len(groups) == 0 {
		t.Fatal("no flag groups defined")
	}

	seenTag := map[string]bool{}
	seenFlag := map[string]bool{}
	for _, g := range groups {
		if g.tag == "" {
			t.Error("group with empty tag")
		}
		if seenTag[g.tag] {
			t.Errorf("duplicate group tag %q", g.tag)
		}
		seenTag[g.tag] = true

		if len(g.flags)%2 != 0 {
			t.Errorf("group %q: flags must be (value, description) pairs, got odd length %d", g.tag, len(g.flags))
		}
		for i := 0; i+1 < len(g.flags); i += 2 {
			flag, desc := g.flags[i], g.flags[i+1]
			if !strings.HasPrefix(flag, "-") {
				t.Errorf("group %q: %q is not a flag (want a leading -)", g.tag, flag)
			}
			if strings.TrimSpace(desc) == "" {
				t.Errorf("group %q: flag %q has an empty description", g.tag, flag)
			}
			if seenFlag[flag] {
				t.Errorf("flag %q listed in more than one group", flag)
			}
			seenFlag[flag] = true
		}
	}

	for _, must := range []string{"-sS", "-sV", "-sC", "-O", "-A", "-p", "--script", "-Pn", "-T4", "-oX"} {
		if !seenFlag[must] {
			t.Errorf("curated flag set is missing %q", must)
		}
	}
}
