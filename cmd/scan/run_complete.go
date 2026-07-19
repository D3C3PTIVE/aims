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
	"bufio"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/rsteube/carapace"

	"github.com/d3c3ptive/aims/client"
	"github.com/d3c3ptive/aims/cmd/hosts"
)

// completeRunNmap is the single positional-tail completer for `scan run nmap`. Because the
// command uses DisableFlagParsing, cobra does no flag parsing and every token is a positional,
// so completion is dispatched here by inspecting the preceding token:
//
//   - after `--script`       → NSE script & category names
//   - a flag being typed (-…) → nothing (let the operator type nmap flags freely)
//   - otherwise (target slot) → hosts/addresses from the database
//
// It never touches the DB directly: targets come through hosts.CompleteByHostnameOrIP, which
// queries the teamserver over RPC — correct whether the CLI is the in-process teamserver or a
// remote teamclient. (NSE names are read from the local nmap script.db; see completeNSEScripts.)
func completeRunNmap(con *client.Client) carapace.Action {
	return carapace.ActionCallback(func(c carapace.Context) carapace.Action {
		if n := len(c.Args); n > 0 && c.Args[n-1] == "--script" {
			return completeNSEScripts()
		}
		if strings.HasPrefix(c.Value, "-") {
			// The operator is typing an nmap flag; stay out of the way.
			return carapace.ActionValues()
		}
		return hosts.CompleteByHostnameOrIP(con)
	})
}

// completeNSEScripts completes the `--script` argument with nmap's NSE script names and
// category selectors, parsed from the local script.db. `--script` takes a comma-separated
// list (names, categories, wildcards), so completion is per comma-separated segment.
//
// Caveat: script.db is read from the *local* machine — the one running the CLI/completion —
// while scans execute server-side (SCAN.md). The authoritative list is the server's; a
// server-side NSE-list RPC is the correct long-term source. This local read is a good-enough
// first cut (script names are stable across nmap installs) and degrades to a message if absent.
func completeNSEScripts() carapace.Action {
	scripts, categories := loadNSEScripts()
	if len(scripts) == 0 && len(categories) == 0 {
		return carapace.ActionMessage("no nmap script.db found (is nmap installed locally?)")
	}

	described := make([]string, 0, (len(categories)+len(scripts))*2)
	for _, cat := range categories { // categories first — coarse selectors
		described = append(described, cat, "category")
	}
	for _, s := range scripts {
		described = append(described, s[0], s[1])
	}

	return carapace.ActionMultiParts(",", func(c carapace.Context) carapace.Action {
		return carapace.ActionValuesDescribed(described...)
	})
}

var nseEntryRE = regexp.MustCompile(`filename\s*=\s*"([^"]+)\.nse".*categories\s*=\s*\{([^}]*)\}`)
var nseCatRE = regexp.MustCompile(`"([^"]+)"`)

// loadNSEScripts parses nmap's script.db into (script{name, "cat, cat"}, sorted categories).
func loadNSEScripts() (scripts [][2]string, categories []string) {
	path := findScriptDB()
	if path == "" {
		return nil, nil
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, nil
	}
	defer f.Close()

	return parseScriptDB(f)
}

// parseScriptDB parses the `Entry { filename = "x.nse", categories = { "a", "b", } }` lines of
// nmap's script.db into sorted (script{name, joined-categories}, categories) — including the
// synthetic `all` selector nmap accepts but script.db does not list.
func parseScriptDB(r io.Reader) (scripts [][2]string, categories []string) {
	catSet := map[string]bool{"all": true} // `all` is a valid selector but not a script.db category
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		m := nseEntryRE.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		var cats []string
		for _, cm := range nseCatRE.FindAllStringSubmatch(m[2], -1) {
			cats = append(cats, cm[1])
			catSet[cm[1]] = true
		}
		scripts = append(scripts, [2]string{m[1], strings.Join(cats, ", ")})
	}

	for cat := range catSet {
		categories = append(categories, cat)
	}
	sort.Strings(categories)
	sort.Slice(scripts, func(i, j int) bool { return scripts[i][0] < scripts[j][0] })

	return scripts, categories
}

// findScriptDB locates nmap's script index across the common install prefixes.
func findScriptDB() string {
	for _, p := range []string{
		"/usr/share/nmap/scripts/script.db",
		"/usr/local/share/nmap/scripts/script.db",
		"/opt/homebrew/share/nmap/scripts/script.db",
		"/opt/local/share/nmap/scripts/script.db",
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}
