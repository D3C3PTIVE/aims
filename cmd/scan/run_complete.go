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
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/carapace-sh/carapace"
	"github.com/carapace-sh/carapace-bridge/pkg/actions/bridge"

	"github.com/d3c3ptive/aims/client"
	aims "github.com/d3c3ptive/aims/cmd"
	"github.com/d3c3ptive/aims/cmd/display"
	"github.com/d3c3ptive/aims/host"
	pb "github.com/d3c3ptive/aims/host/pb"
	hostrpc "github.com/d3c3ptive/aims/host/pb/rpc"
)

// completeRunNmap is the single positional-tail completer for `scan run nmap`. Because the
// command uses DisableFlagParsing, cobra does no flag parsing and every token is a positional,
// so completion is dispatched here by inspecting the preceding token:
//
//   - after `--script`       → NSE script & category names (local script.db)
//   - a flag being typed (-…) → a curated, described set of high-value nmap flags
//   - otherwise (target slot) → hosts/addresses from the database, sub-grouped by locality
//
// It never touches the DB directly: targets come through completeTargets, which queries the
// teamserver over RPC — correct whether the CLI is the in-process teamserver or a remote
// teamclient. (NSE names are read from the local nmap script.db; see completeNSEScripts.)
//
// SCAN.md's contract is "raw passthrough, complete only where AIMS adds value": we deliberately
// do NOT mirror nmap's hundreds of flags as typed cobra flags. The flag completion below stacks a
// small curated set (AIMS attaches descriptions and grouping) on top of nmap's full flag long-tail,
// which is bridged from the system's zsh `_nmap` completer via carapace-bridge (see
// nmapFlagCompletions) — so passthrough stays complete without ever declaring the flags ourselves.
func completeRunNmap(con *client.Client) carapace.Action {
	return carapace.ActionCallback(func(c carapace.Context) carapace.Action {
		if n := len(c.Args); n > 0 && c.Args[n-1] == "--script" {
			return completeNSEScripts(con)
		}
		if strings.HasPrefix(c.Value, "-") {
			return nmapFlagCompletions()
		}
		return completeTargets(con)
	})
}

//
// [ Targets — DB hosts, sub-grouped by locality ] -----------------------------------------------
//

// Target sub-group tags, listed in deliberate display order: externally routable targets first
// (the scans that matter most), then the private/loopback estate, then hosts we only know by name.
// The standing project preference is that candidates convey sub-categories (see CLAUDE.md
// "sub-categorized completions"); locality is the axis that costs the operator most to eyeball
// in a flat list.
const (
	tagRoutable = "routable targets"
	tagPrivate  = "private targets"
	tagLoopback = "loopback targets"
	tagNoAddr   = "targets (no address)"
)

// targetGroupOrder fixes the order sub-groups are presented in.
var targetGroupOrder = []string{tagRoutable, tagPrivate, tagLoopback, tagNoAddr}

// completeTargets completes the nmap target slot with known hosts, sub-grouped by address
// locality. It is a scan-local completion (not a call into cmd/hosts) precisely because the
// shared hosts.CompleteByHostnameOrIP flattens the address away, and locality grouping needs it;
// the read still goes through the teamclient RPC, never the DB directly. Wrapped in the shared
// on-disk completion cache so a burst of Tabs doesn't re-fetch the whole host set each keystroke.
func completeTargets(con *client.Client) carapace.Action {
	return aims.CacheCompletion(con, "scan:nmap:targets", carapace.ActionCallback(func(_ carapace.Context) carapace.Action {
		if msg, err := con.ConnectComplete(); err != nil {
			return msg
		}

		res, err := con.Hosts.Read(context.Background(), &hostrpc.ReadHostRequest{Host: &pb.Host{}})
		if err = aims.CheckError(err); err != nil {
			return carapace.ActionMessage("Error: %s", err)
		}
		if len(res.GetHosts()) == 0 {
			return carapace.ActionMessage("no hosts in database")
		}

		return groupedTargets(res.GetHosts())
	}))
}

// groupedTargets partitions hosts into locality sub-groups and renders each as its own tagged
// carapace group, reusing the shared display engine for the (candidate, description) rows exactly
// as hosts.CompleteByHostnameOrIP does — the hostname is the inserted value, the address the
// fallback for hosts with no name.
func groupedTargets(all []*pb.Host) carapace.Action {
	buckets := make(map[string][]*pb.Host, len(targetGroupOrder))
	for _, h := range all {
		tag := hostLocality(h)
		buckets[tag] = append(buckets[tag], h)
	}

	actions := make([]carapace.Action, 0, len(targetGroupOrder))
	for _, tag := range targetGroupOrder {
		group := buckets[tag]
		if len(group) == 0 {
			continue
		}

		options := host.Completions()
		options = append(options, display.WithCandidateValue("Hostnames", "Addresses"))
		options = append(options, display.WithSplitCandidate(","))

		pairs := display.Completions(group, host.DisplayFields, options...)
		actions = append(actions, carapace.ActionValuesDescribed(pairs...).Tag(tag))
	}

	return carapace.Batch(actions...).ToA()
}

// hostLocality classifies a host by the locality of its first parseable address; a host with no
// parseable address (known only by hostname) falls into the "no address" group.
func hostLocality(h *pb.Host) string {
	for _, a := range h.GetAddresses() {
		switch localityOf(a.GetAddr()) {
		case "routable":
			return tagRoutable
		case "private":
			return tagPrivate
		case "loopback":
			return tagLoopback
		}
	}
	return tagNoAddr
}

// localityOf classifies a single IP string as "loopback", "private" (RFC1918 / ULA / link-local),
// or "routable" (globally reachable unicast). It returns "" for anything that is not an IP literal
// (e.g. a bare hostname), so callers can treat that as "unknown locality".
func localityOf(addr string) string {
	ip := net.ParseIP(strings.TrimSpace(addr))
	if ip == nil {
		return ""
	}
	switch {
	case ip.IsLoopback():
		return "loopback"
	case ip.IsPrivate(), ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		return "private"
	default:
		return "routable"
	}
}

//
// [ Flags — curated, described, sub-grouped ] ---------------------------------------------------
//

// flagGroup is a named sub-group of curated nmap flags rendered as one carapace tag group.
// flags is a flat (flag, description, …) list for carapace.ActionValuesDescribed.
type flagGroup struct {
	tag   string
	flags []string
}

// nmapFlagGroups is the curated, described flag set offered on top while the operator is typing a
// `-flag`. It is intentionally small: AIMS mirrors none of nmap's flags as typed cobra flags
// (SCAN.md), so this is only the highest-value handful, grouped so the operator sees scan types
// apart from timing apart from output — with AIMS-authored descriptions the bridge can't guarantee.
// The exhaustive long-tail is supplied by carapace-bridge underneath (see nmapFlagCompletions), so
// this curated set is a hand-tuned "most useful first" layer, not the whole surface.
func nmapFlagGroups() []flagGroup {
	return []flagGroup{
		{tag: "scan type", flags: []string{
			"-sS", "TCP SYN (half-open) scan — the default, stealthy",
			"-sT", "TCP connect scan (no raw-socket privilege needed)",
			"-sU", "UDP scan",
			"-sV", "Probe open ports for service/version info",
			"-sC", "Run the default NSE script set (= --script=default)",
			"-O", "Enable OS detection",
			"-A", "Aggressive: OS detection, version, script scan, traceroute",
		}},
		{tag: "selection", flags: []string{
			"-p", "Port ranges to scan (e.g. -p22,80,443 or -p1-65535)",
			"--script", "Run NSE scripts by name, category, or wildcard",
		}},
		{tag: "timing", flags: []string{
			"-T0", "paranoid — serial, slowest, IDS-evasive",
			"-T1", "sneaky — serial, slow",
			"-T2", "polite — less bandwidth/target load",
			"-T3", "normal — the default timing",
			"-T4", "aggressive — fast, assumes a reliable network",
			"-T5", "insane — fastest, may sacrifice accuracy",
		}},
		{tag: "host discovery", flags: []string{
			"-Pn", "Treat all hosts as online — skip host discovery",
		}},
		{tag: "output", flags: []string{
			"-oX", "Write XML output to a file",
			"-oN", "Write normal (human-readable) output to a file",
			"-oG", "Write grepable output to a file",
		}},
	}
}

// nmapFlagCompletions renders the flag completion offered while typing a `-flag`: the curated,
// sub-grouped, described set on top, then nmap's full flag long-tail underneath.
//
// The long-tail is bridged to the system's zsh `_nmap` completer (carapace-bridge). It is filtered
// to drop the flags we already curate, so our authored descriptions and grouping win over the
// bridge's plainer entries, and tagged as its own group so it sits below the curated set. The
// bridge is best-effort: it spawns `zsh` per completion and needs nmap's `_nmap` zsh completion
// present; if either is missing it yields nothing (or an error line) and the curated set still
// stands. zsh is the chosen shell because nmap ships a rich `_nmap` (with descriptions, which
// ActionZsh forwards) and this project's operators run zsh; ActionBash/ActionFish exist for other
// shells if that assumption ever changes.
func nmapFlagCompletions() carapace.Action {
	groups := nmapFlagGroups()
	actions := make([]carapace.Action, 0, len(groups)+1)

	curated := make([]string, 0)
	for _, g := range groups {
		actions = append(actions, carapace.ActionValuesDescribed(g.flags...).Tag(g.tag))
		for i := 0; i+1 < len(g.flags); i += 2 {
			curated = append(curated, g.flags[i])
		}
	}

	longTail := bridge.ActionZsh("nmap").
		Filter(curated...).
		Tag("nmap (full flag set)")
	actions = append(actions, longTail)

	return carapace.Batch(actions...).ToA()
}

// completeNSEScripts completes the `--script` argument with nmap's NSE script names and
// category selectors, parsed from the local script.db. `--script` takes a comma-separated
// list (names, categories, wildcards), so completion is per comma-separated segment.
//
// The parse (findScriptDB + a regex over ~600 script.db lines) is wrapped in the shared
// on-disk completion cache. This matters most in exec-once CLI mode, where every Tab is a
// fresh process: an in-process memo would never hit, so only the on-disk cache collapses the
// re-parse-per-keystroke storm. The ActionMultiParts shell stays *outside* the cache so the
// per-segment comma handling is always recomputed against what was typed; the cached candidate
// set is identical for every segment, so one cache entry (keyed by the Cache call site) serves
// them all. A "no script.db" result is an ActionMessage, which carapace never caches, so
// installing nmap later is picked up on the next Tab.
//
// The cache lives under the "local" scope — script.db is a local-machine resource, independent
// of any teamserver, and CompletionScope() returns "local" without a connection. The teamserver
// scope and DB-mutation epoch keys carapace mixes in are spurious for a local file (a remote
// switch or a DB add/import needlessly drops this entry) but only ever cost a harmless re-parse,
// and the short TTL bounds staleness against an nmap upgrade.
//
// Caveat: script.db is read from the *local* machine — the one running the CLI/completion —
// while scans execute server-side (SCAN.md). The authoritative list is the server's; a
// server-side NSE-list RPC is the correct long-term source. This local read is a good-enough
// first cut (script names are stable across nmap installs) and degrades to a message if absent.
func completeNSEScripts(con *client.Client) carapace.Action {
	return carapace.ActionMultiParts(",", func(carapace.Context) carapace.Action {
		return aims.CacheCompletion(con, "scan:nmap:nse", carapace.ActionCallback(func(carapace.Context) carapace.Action {
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

			return carapace.ActionValuesDescribed(described...)
		}))
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

// findScriptDB locates nmap's script index. It honours $NMAPDIR (nmap's own data-dir override)
// first, then falls back to the common install prefixes. A `nmap --datadir <dir>` invocation
// resolves to the same $NMAPDIR path, so respecting the env var covers the custom-datadir case
// without shelling out to nmap.
func findScriptDB() string {
	candidates := make([]string, 0, 6)
	if dir := os.Getenv("NMAPDIR"); dir != "" {
		candidates = append(candidates,
			filepath.Join(dir, "scripts", "script.db"),
			filepath.Join(dir, "script.db"),
		)
	}
	candidates = append(candidates,
		"/usr/share/nmap/scripts/script.db",
		"/usr/local/share/nmap/scripts/script.db",
		"/opt/homebrew/share/nmap/scripts/script.db",
		"/opt/local/share/nmap/scripts/script.db",
	)

	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}
