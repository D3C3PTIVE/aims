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
	"github.com/d3c3ptive/aims/cmd/credentials"
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
// SCAN.md's contract is "raw passthrough, complete only where AIMS adds value": we still add no
// typed cobra flags. Flag completion (see nmapFlagCompletions) is a curated, described, tagged set
// of the high-value flags AIMS owns — because the system's zsh `_nmap` completer is often a stale,
// pre-NSE stub that drops --script and friends — supplemented, deduped, by the carapace-bridge
// long-tail for whatever extra the local `_nmap` knows.
func completeRunNmap(con *client.Client) carapace.Action {
	return carapace.ActionCallback(func(c carapace.Context) carapace.Action {
		if n := len(c.Args); n > 0 {
			switch c.Args[n-1] {
			case "--script":
				return completeNSEScripts(con)
			case "--script-args":
				return completeNSEScriptArgs(con)
			case "-e":
				return completeInterface()
			}
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

// completeTargets completes a target slot with known hosts, sub-grouped by address locality, and
// drops any target already present on the command line. It is the shared target completer — the
// nmap positional target slot and NSE host-valued script args both use it — so excluding
// already-chosen targets happens here, once, for every reuse site.
//
// The exclusion (Filter against c.Args) is applied *outside* the cache: cachedTargets stores the
// whole host set once, and each keystroke filters that set against the live arguments. Filtering by
// exact token is safe against the DisableFlagParsing arg stream — flags and flag-values (-sS, a
// --script value) never equal a host candidate.
func completeTargets(con *client.Client) carapace.Action {
	return carapace.ActionCallback(func(c carapace.Context) carapace.Action {
		return cachedTargets(con).Filter(c.Args...)
	})
}

// cachedTargets is the cached whole-host-set candidate action behind completeTargets. It is a
// scan-local completion (not a call into cmd/hosts) precisely because the shared
// hosts.CompleteByHostnameOrIP flattens the address away, and locality grouping needs it; the read
// still goes through the teamclient RPC, never the DB directly. Wrapped in the shared on-disk
// completion cache so a burst of Tabs doesn't re-fetch the whole host set each keystroke.
func cachedTargets(con *client.Client) carapace.Action {
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
// [ Flags — bridged from zsh _nmap, tagged by AIMS ] --------------------------------------------
//

// nmapFlagCompletions completes an nmap `-flag`. It merges two sources, both grouped through the
// same classifyNmapFlag so the sections are one source of truth:
//
//   - curatedNmapFlags — an AIMS-owned set of the high-value modern flags, with AIMS-authored
//     descriptions. This is authoritative, not decoration: the system's zsh `_nmap` completion is
//     frequently a stale, pre-NSE stub (the one on this dev box has no --script, -sV, -sC, -sn or
//     -Pn and exposes scan types as a `-s-` argument), so leaning on the bridge alone silently
//     drops exactly the flags that matter. --script especially must always be here — it is the
//     one flag AIMS deeply integrates (completeNSEScripts).
//   - the carapace-bridge zsh `_nmap` long-tail, Filter'd to drop anything already curated, as a
//     best-effort supplement: on a box with a richer `_nmap` it adds whatever extra flags exist;
//     on a stale one it simply adds little. Both are tagged by the same classifier.
//
// carapace-bin has no nmap spec (checked), so the zsh bridge is the only external source; it spawns
// `zsh` per completion and needs `_nmap` present, contributing nothing if either is absent — which
// is exactly why the curated set carries the essentials on its own.
func nmapFlagCompletions() carapace.Action {
	curated := carapace.ActionValuesDescribed(curatedNmapFlags()...).TagF(classifyNmapFlag)
	longTail := bridge.ActionZsh("nmap").Filter(curatedFlagNames()...).TagF(classifyNmapFlag)
	return carapace.Batch(curated, longTail).ToA()
}

// curatedNmapFlags is the AIMS-owned (flag, description, …) set of high-value nmap flags, flat for
// carapace.ActionValuesDescribed and grouped at render time by classifyNmapFlag. It targets the
// modern surface an operator actually reaches for — the NSE, service/version, host-discovery and
// timing flags a stale system `_nmap` tends to lack — rather than mirroring nmap's whole flag list.
func curatedNmapFlags() []string {
	return []string{
		// scan techniques
		"-sS", "TCP SYN (half-open) scan — default, fast, stealthy",
		"-sT", "TCP connect scan (no raw-socket privilege needed)",
		"-sU", "UDP scan",
		"-sA", "TCP ACK scan (map firewall rulesets)",
		"-sN", "TCP null scan",
		"-sF", "TCP FIN scan",
		"-sX", "TCP Xmas scan",
		"-sO", "IP protocol scan",
		// service / OS detection
		"-sV", "Probe open ports for service/version info",
		"--version-intensity", "Set version-scan intensity (0–9)",
		"-O", "Enable OS detection",
		"--osscan-guess", "Guess OS more aggressively",
		"-A", "Aggressive: OS detection, version, default scripts, traceroute",
		// scripts (NSE)
		"-sC", "Run the default NSE script set (= --script=default)",
		"--script", "Run NSE scripts by name, category, dir, or wildcard",
		"--script-args", "Provide arguments to NSE scripts",
		"--script-help", "Show help for the given NSE scripts",
		"--script-updatedb", "Update the NSE script database",
		// host discovery
		"-sn", "Ping scan — host discovery only, no port scan",
		"-Pn", "Treat all hosts as online — skip host discovery",
		"-PS", "TCP SYN ping to the given ports",
		"-PA", "TCP ACK ping to the given ports",
		"-PU", "UDP ping to the given ports",
		"-PE", "ICMP echo ping",
		"-n", "Never do DNS resolution",
		"-R", "Always resolve DNS",
		"--traceroute", "Trace the network path to each host",
		"--dns-servers", "Use the given DNS servers",
		// port specification
		"-p", "Port ranges to scan (e.g. -p22,80,443 or -p1-65535)",
		"-F", "Fast scan — fewer ports than the default",
		"-r", "Scan ports in order (don't randomize)",
		"--top-ports", "Scan the N most common ports",
		"--exclude-ports", "Exclude the given ports from scanning",
		// timing & performance
		"-T0", "paranoid — serial, slowest, IDS-evasive",
		"-T1", "sneaky — serial, slow",
		"-T2", "polite — less bandwidth/target load",
		"-T3", "normal — the default timing",
		"-T4", "aggressive — fast, assumes a reliable network",
		"-T5", "insane — fastest, may sacrifice accuracy",
		"--min-rate", "Send at least N packets per second",
		"--max-rate", "Send at most N packets per second",
		"--max-retries", "Cap probe retransmissions",
		"--host-timeout", "Give up on a host after this long",
		"--scan-delay", "Wait at least this long between probes",
		// firewall / IDS evasion
		"-f", "Fragment packets",
		"-D", "Decoy scan — cloak the real source among decoys",
		"-S", "Spoof the source address",
		"-e", "Use the given network interface",
		"-g", "Spoof the source port",
		"--source-port", "Spoof the source port",
		"--data-length", "Append random data to packets",
		"--spoof-mac", "Spoof the MAC address",
		"--mtu", "Set a custom fragmentation MTU",
		"--proxies", "Relay connections through the given proxies",
		"--badsum", "Send packets with a bogus checksum",
		// output
		"-oN", "Write normal (human-readable) output to a file",
		"-oX", "Write XML output to a file",
		"-oG", "Write grepable output to a file",
		"-oA", "Write output in all major formats (given a base name)",
		"-v", "Verbose (repeat for more)",
		"-d", "Debugging (repeat for more)",
		"--reason", "Explain why a port is in a given state",
		"--open", "Show only open (or possibly-open) ports",
		"--packet-trace", "Show every packet sent and received",
		"--resume", "Resume an aborted scan from its output file",
		// target specification
		"-iL", "Read target specifications from a file",
		"-iR", "Choose random targets",
		"--exclude", "Exclude the given hosts/networks",
		"--excludefile", "Exclude hosts/networks listed in a file",
		// other
		"-6", "Enable IPv6 scanning",
		"--datadir", "Use a custom nmap data directory",
		"--privileged", "Assume the user is fully privileged",
		"-V", "Print the nmap version",
	}
}

// curatedFlagNames returns just the flag names from curatedNmapFlags (the even indices), used to
// Filter the bridge long-tail so a curated flag is never listed twice.
func curatedFlagNames() []string {
	pairs := curatedNmapFlags()
	names := make([]string, 0, len(pairs)/2)
	for i := 0; i < len(pairs); i += 2 {
		names = append(names, pairs[i])
	}
	return names
}

// classifyNmapFlag buckets an nmap flag into the group nmap's own `--help` uses, matching on the
// stable flag-name prefixes. It only ever returns a tag — never a description or value — so the
// bridge's authoritative value+description is preserved untouched. It is deliberately heuristic:
// an unrecognised token lands in a generic group rather than being dropped.
func classifyNmapFlag(flag string) string {
	switch {
	case flag == "-sC" || strings.HasPrefix(flag, "--script"):
		return "scripts (NSE)"
	case flag == "-sn" || flag == "-sL":
		return "host discovery"
	case strings.HasPrefix(flag, "-sV") || flag == "-O" || flag == "-A" ||
		strings.HasPrefix(flag, "--version") || strings.HasPrefix(flag, "--osscan"):
		return "service / OS detection"
	case strings.HasPrefix(flag, "-s"):
		return "scan techniques"
	case strings.HasPrefix(flag, "-T") || strings.HasPrefix(flag, "--min-") ||
		strings.HasPrefix(flag, "--max-") || strings.HasPrefix(flag, "--host-timeout") ||
		strings.HasPrefix(flag, "--scan-delay") || strings.HasSuffix(flag, "-rate"):
		return "timing & performance"
	case flag == "-p" || flag == "-F" || flag == "-r" ||
		strings.HasPrefix(flag, "--top-ports") || strings.HasPrefix(flag, "--port-ratio") ||
		strings.HasPrefix(flag, "--exclude-ports"):
		return "port specification"
	case strings.HasPrefix(flag, "-P") || flag == "-n" || flag == "-R" ||
		strings.HasPrefix(flag, "--dns") || flag == "--system-dns" || flag == "--traceroute":
		return "host discovery"
	case strings.HasPrefix(flag, "-o") || flag == "-v" || flag == "-d" ||
		strings.HasPrefix(flag, "--reason") || strings.HasPrefix(flag, "--open") ||
		strings.HasPrefix(flag, "--packet-trace") || strings.HasPrefix(flag, "--stylesheet") ||
		strings.HasPrefix(flag, "--append-output") || strings.HasPrefix(flag, "--resume"):
		return "output"
	case flag == "-f" || flag == "-D" || flag == "-S" || flag == "-e" || flag == "-g" ||
		strings.HasPrefix(flag, "--source-port") || flag == "--data" || strings.HasPrefix(flag, "--data-") ||
		strings.HasPrefix(flag, "--spoof-mac") || flag == "--badsum" ||
		strings.HasPrefix(flag, "--mtu") || strings.HasPrefix(flag, "--proxies") ||
		strings.HasPrefix(flag, "--ttl"):
		return "firewall / IDS evasion"
	case strings.HasPrefix(flag, "-i") || strings.HasPrefix(flag, "--exclude"):
		return "target specification"
	default:
		return "other nmap flags"
	}
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
			return groupedNSE(scripts, categories)
		}))
	})
}

// groupedNSE renders NSE completion as tag groups rather than descriptions. The category is NSE's
// only real sub-structure, so it is the grouping axis: the coarse category *selectors* sit under a
// "categories" tag, then every script is listed under each category it declares. A script is
// genuinely in all of its categories, so e.g. http-title appears under safe, default and discovery
// — carapace shows the same candidate in each group it belongs to. Descriptions are dropped on
// purpose: they only ever repeated the category list, which the tag header now conveys.
func groupedNSE(scripts []nseScript, categories []string) carapace.Action {
	byCat := make(map[string][]string, len(categories))
	for _, s := range scripts {
		for _, c := range s.cats {
			byCat[c] = append(byCat[c], s.name)
		}
	}

	actions := make([]carapace.Action, 0, len(byCat)+1)
	actions = append(actions, carapace.ActionValues(categories...).Tag("categories"))

	cats := make([]string, 0, len(byCat))
	for c := range byCat {
		cats = append(cats, c)
	}
	sort.Strings(cats)
	for _, c := range cats {
		actions = append(actions, carapace.ActionValues(byCat[c]...).Tag(c))
	}

	return carapace.Batch(actions...).ToA()
}

//
// [ NSE script args — parsed from every .nse @args tag ] ----------------------------------------
//

// completeNSEScriptArgs completes nmap's `--script-args`, whose value is a comma-separated list of
// `key=value` pairs. Completion is two-level: the key side offers every NSE argument declared by an
// installed script (parsed from `@args` header tags, cached), and the value side dispatches to an
// existing AIMS completer when the key's shape says what the value is — a target host, a known
// credential username, or a wordlist/data file. Anything else is left free-form.
func completeNSEScriptArgs(con *client.Client) carapace.Action {
	return carapace.ActionCallback(func(c carapace.Context) carapace.Action {
		// Scope the offered args to whatever `--script` already selects on this command line.
		selectors := scriptSelectorsFromArgs(c.Args)
		return carapace.ActionMultiParts(",", func(carapace.Context) carapace.Action {
			return carapace.ActionMultiParts("=", func(mc carapace.Context) carapace.Action {
				if len(mc.Parts) > 0 { // past the '=', completing the value of Parts[0]
					return completeNSEArgValue(con, mc.Parts[0])
				}
				return nseArgNames(con, selectors)
			})
		})
	})
}

// scriptSelectorsFromArgs pulls the `--script` value(s) out of the raw positional token stream
// (DisableFlagParsing hands us everything as args). It handles both `--script foo,bar` and
// `--script=foo,bar`, splits on commas, and never mistakes `--script-args`/`--script-help` for
// `--script`. The returned selectors are script names, categories, wildcards, `all`, or paths —
// resolved later against the installed set.
func scriptSelectorsFromArgs(args []string) []string {
	var sels []string
	for i := 0; i < len(args); i++ {
		var val string
		switch a := args[i]; {
		case a == "--script" && i+1 < len(args):
			val = args[i+1]
			i++
		case strings.HasPrefix(a, "--script="):
			val = strings.TrimPrefix(a, "--script=")
		default:
			continue
		}
		for _, s := range strings.Split(val, ",") {
			if s = strings.TrimSpace(s); s != "" {
				sels = append(sels, s)
			}
		}
	}
	return sels
}

// nseArgNames offers the NSE argument names, described from their `@args` text and scoped to the
// scripts `--script` selects. With no selection it falls back to the full deduped set under one
// "script args" tag; with a selection it groups the args by the script that declares them, so an
// operator running several scripts sees whose arg is whose. Parsing the `.nse` files is the
// expensive part, so it is wrapped in the shared on-disk completion cache — keyed by the (sorted)
// selectors so distinct `--script` values don't share a cache entry, while repeated Tabs at the
// same selection stay a cache hit.
func nseArgNames(con *client.Client, selectors []string) carapace.Action {
	name := "scan:nmap:nse-args"
	if len(selectors) > 0 {
		sorted := append([]string(nil), selectors...)
		sort.Strings(sorted)
		name += ":" + strings.Join(sorted, ",")
	}

	return aims.CacheCompletion(con, name, carapace.ActionCallback(func(carapace.Context) carapace.Action {
		refs := nseScriptIndex()
		if len(refs) == 0 {
			return carapace.ActionMessage("no NSE scripts found (is nmap installed locally?)")
		}

		selected := selectScriptRefs(refs, selectors)
		if len(selected) == 0 {
			// No --script scope yet (or nothing matched): the whole deduped set, one group.
			return allArgsAction(refs)
		}

		// Scoped: one tag group per selected script, so multi-script selections stay legible.
		actions := make([]carapace.Action, 0, len(selected))
		for _, ref := range selected {
			args := parseArgsForFile(ref.path)
			if len(args) == 0 {
				continue
			}
			described := make([]string, 0, len(args)*2)
			for _, a := range args {
				described = append(described, a[0], a[1])
			}
			actions = append(actions, carapace.ActionValuesDescribed(described...).Tag(ref.name))
		}
		if len(actions) == 0 {
			return carapace.ActionMessage("selected script(s) declare no @args")
		}
		return carapace.Batch(actions...).ToA()
	}))
}

// completeNSEArgValue dispatches the value side of an NSE `key=value` arg to an existing AIMS
// completer, chosen from the key's shape (see nseArgValueKind). Reusing completeTargets and the
// credentials completer means these values flow through the same cached teamclient RPC path as the
// rest of AIMS completion — never the DB directly.
func completeNSEArgValue(con *client.Client, key string) carapace.Action {
	switch nseArgValueKind(key) {
	case "host":
		return completeTargets(con)
	case "username":
		return credentials.CompleteByUsername(con)
	case "file":
		return carapace.ActionFiles()
	case "interface":
		return completeInterface()
	default:
		return carapace.ActionValues() // free-form value, nothing to offer
	}
}

// nseArgValueKind classifies what an NSE argument's value is, from the argument name, so its value
// can borrow an existing completer. It keys off the last dotted/dashed segment (NSE args are
// namespaced, e.g. http-enum.host, mssql.username) with a few whole-key signals. Heuristic by
// nature: an unrecognised arg returns "" (free-form). Order matters — the file signals are checked
// before "username" so that userdb/passdb (wordlist files) don't read as usernames.
func nseArgValueKind(key string) string {
	k := strings.ToLower(key)
	base := k
	if i := strings.LastIndexAny(k, ".-"); i >= 0 {
		base = k[i+1:]
	}

	switch {
	case strings.Contains(k, "userdb"), strings.Contains(k, "passdb"),
		strings.Contains(k, "wordlist"), strings.Contains(k, "dict"),
		strings.HasSuffix(base, "file"):
		return "file"
	case base == "host" || base == "target" || base == "targets" ||
		base == "rhost" || strings.HasSuffix(base, "host"):
		return "host"
	case strings.Contains(base, "username") || base == "user" || strings.HasSuffix(base, "user"):
		return "username"
	case strings.Contains(base, "interface"):
		return "interface"
	default:
		return ""
	}
}

// completeInterface completes a network-interface value — nmap's `-e`, an NSE `*.interface` arg,
// and any other scanner's interface flag — from the LOCAL machine's interfaces (the box the
// completion process runs on). It is deliberately not agent-context aware: interfaces belong to the
// operator's host, not the possibly-remote loaded agent. Purely local and cheap, so it is not
// cached. Interfaces are grouped up vs down (you scan from an up interface), each described by its
// addresses.
func completeInterface() carapace.Action {
	ifaces, err := net.Interfaces()
	if err != nil {
		return carapace.ActionMessage("cannot list interfaces: %s", err)
	}

	var up, down []string
	for _, ic := range ifaces {
		addrs, _ := ic.Addrs()
		desc := interfaceLabel(ic.Flags&net.FlagLoopback != 0, addrs)
		if ic.Flags&net.FlagUp != 0 {
			up = append(up, ic.Name, desc)
		} else {
			down = append(down, ic.Name, desc)
		}
	}

	actions := make([]carapace.Action, 0, 2)
	if len(up) > 0 {
		actions = append(actions, carapace.ActionValuesDescribed(up...).Tag("up interfaces"))
	}
	if len(down) > 0 {
		actions = append(actions, carapace.ActionValuesDescribed(down...).Tag("down interfaces"))
	}
	if len(actions) == 0 {
		return carapace.ActionMessage("no network interfaces found")
	}
	return carapace.Batch(actions...).ToA()
}

// interfaceLabel describes an interface for its completion candidate: its addresses (IPs, mask
// stripped) and a loopback marker, or "no address". Split from completeInterface so it can be
// tested without the machine's real interfaces.
func interfaceLabel(loopback bool, addrs []net.Addr) string {
	var ips []string
	for _, a := range addrs {
		ip := a.String()
		if ipn, ok := a.(*net.IPNet); ok {
			ip = ipn.IP.String()
		}
		ips = append(ips, ip)
	}

	label := strings.Join(ips, ", ")
	if loopback {
		if label != "" {
			label += " "
		}
		label += "(loopback)"
	}
	if label == "" {
		label = "no address"
	}
	return label
}

// nseArgsRE captures `@args <name> <description…>` from an NSE header comment (the leading comment
// dashes are already stripped by parseNSEArgs). The description may continue on following comment
// lines; parseNSEArgs folds those in.
var nseArgsRE = regexp.MustCompile(`^@args\s+(\S+)\s*(.*)$`)

// findNSEScriptsDir returns the directory holding the installed `.nse` files. They sit alongside
// script.db, so the script.db locator already found the right place; fall back to a `scripts`
// subdirectory for the rare layout where script.db is one level up.
func findNSEScriptsDir() string {
	db := findScriptDB()
	if db == "" {
		return ""
	}
	dir := filepath.Dir(db)
	if matches, _ := filepath.Glob(filepath.Join(dir, "*.nse")); len(matches) > 0 {
		return dir
	}
	if sub := filepath.Join(dir, "scripts"); dirHasNSE(sub) {
		return sub
	}
	return ""
}

func dirHasNSE(dir string) bool {
	matches, _ := filepath.Glob(filepath.Join(dir, "*.nse"))
	return len(matches) > 0
}

// nseScriptRef locates one installed script and its categories without parsing its @args — enough
// to resolve a --script selector. Building the whole index is cheap (script.db + a glob); the
// expensive per-file @args parse is deferred to only the scripts that actually match.
type nseScriptRef struct {
	name string
	cats []string
	path string
}

// nseScriptIndex lists every installed script with its categories (from script.db) and file path
// (from the scripts dir glob), name-sorted. No @args parsing happens here.
func nseScriptIndex() []nseScriptRef {
	dir := findNSEScriptsDir()
	if dir == "" {
		return nil
	}

	scripts, _ := loadNSEScripts() // name → categories, from script.db
	catByName := make(map[string][]string, len(scripts))
	for _, s := range scripts {
		catByName[s.name] = s.cats
	}

	files, _ := filepath.Glob(filepath.Join(dir, "*.nse"))
	refs := make([]nseScriptRef, 0, len(files))
	for _, path := range files {
		name := strings.TrimSuffix(filepath.Base(path), ".nse")
		refs = append(refs, nseScriptRef{name: name, cats: catByName[name], path: path})
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].name < refs[j].name })
	return refs
}

// selectScriptRefs resolves --script selectors against the index the way nmap does: `all`, an exact
// script name, a category, a `name*`/`?`/`[` wildcard, or a script path (dir and `.nse` stripped).
// Matches are unioned and de-duplicated, name-sorted. Empty selectors resolve to nothing (the
// caller then falls back to the full arg set).
func selectScriptRefs(refs []nseScriptRef, selectors []string) []nseScriptRef {
	if len(selectors) == 0 {
		return nil
	}

	byName := make(map[string]nseScriptRef, len(refs))
	for _, r := range refs {
		byName[r.name] = r
	}

	seen := make(map[string]bool)
	var out []nseScriptRef
	add := func(r nseScriptRef) {
		if !seen[r.name] {
			seen[r.name] = true
			out = append(out, r)
		}
	}

	for _, sel := range selectors {
		s := strings.TrimSpace(sel)
		if s == "" {
			continue
		}
		if strings.Contains(s, "/") || strings.HasSuffix(s, ".nse") { // a script path
			s = strings.TrimSuffix(filepath.Base(s), ".nse")
		}

		switch {
		case s == "all":
			for _, r := range refs {
				add(r)
			}
		case strings.ContainsAny(s, "*?["): // a wildcard
			for _, r := range refs {
				if ok, _ := filepath.Match(s, r.name); ok {
					add(r)
				}
			}
		default: // an exact name and/or a category
			if r, ok := byName[s]; ok {
				add(r)
			}
			for _, r := range refs {
				for _, c := range r.cats {
					if c == s {
						add(r)
						break
					}
				}
			}
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

// parseArgsForFile parses the @args of a single script file, or nil if it can't be opened.
func parseArgsForFile(path string) [][2]string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	return parseNSEArgs(f)
}

// allArgsAction is the unscoped fallback: the @args of every installed script, deduplicated by name
// (many scripts declare the same library arg, e.g. http.useragent, smbdomain) keeping the first
// non-empty description, under a single "script args" tag.
func allArgsAction(refs []nseScriptRef) carapace.Action {
	byName := make(map[string]string)
	var order []string
	for _, ref := range refs {
		for _, a := range parseArgsForFile(ref.path) {
			if _, ok := byName[a[0]]; !ok {
				order = append(order, a[0])
			}
			if byName[a[0]] == "" {
				byName[a[0]] = a[1]
			}
		}
	}
	if len(order) == 0 {
		return carapace.ActionMessage("no NSE script args found (is nmap installed locally?)")
	}

	sort.Strings(order)
	described := make([]string, 0, len(order)*2)
	for _, n := range order {
		described = append(described, n, byName[n])
	}
	return carapace.ActionValuesDescribed(described...).Tag("script args")
}

// parseNSEArgs extracts the `@args name description` declarations from a single `.nse` file. NSE
// headers are Lua block comments (`-- …`); a description often wraps onto following comment lines,
// which are folded into it until the next `@tag`, a blank comment line, or the end of the header.
func parseNSEArgs(r io.Reader) [][2]string {
	var out [][2]string
	var name, desc string

	flush := func() {
		if name != "" {
			out = append(out, [2]string{name, strings.TrimSpace(desc)})
		}
		name, desc = "", ""
	}

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024) // some .nse lines are long
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "--") { // left the comment header / hit code
			flush()
			continue
		}
		content := strings.TrimSpace(strings.TrimLeft(line, "-"))

		switch {
		case strings.HasPrefix(content, "@args ") || content == "@args":
			flush()
			if m := nseArgsRE.FindStringSubmatch(content); m != nil {
				name, desc = m[1], m[2]
			}
		case strings.HasPrefix(content, "@"): // a different header tag ends this arg
			flush()
		case content == "": // blank comment line ends this arg
			flush()
		default:
			if name != "" { // a wrapped description line
				desc += " " + content
			}
		}
	}
	flush()

	return out
}

var nseEntryRE = regexp.MustCompile(`filename\s*=\s*"([^"]+)\.nse".*categories\s*=\s*\{([^}]*)\}`)
var nseCatRE = regexp.MustCompile(`"([^"]+)"`)

// nseScript is one NSE script: its bare name (the `.nse` suffix stripped) and the categories it
// declares in script.db. The categories are the grouping axis for completion (see groupedNSE).
type nseScript struct {
	name string
	cats []string
}

// loadNSEScripts parses nmap's script.db into (scripts, sorted category selectors).
func loadNSEScripts() (scripts []nseScript, categories []string) {
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
// nmap's script.db into name-sorted scripts (each carrying its declared categories) and the sorted
// union of category selectors — including the synthetic `all` selector nmap accepts but script.db
// does not list.
func parseScriptDB(r io.Reader) (scripts []nseScript, categories []string) {
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
		scripts = append(scripts, nseScript{name: m[1], cats: cats})
	}

	for cat := range catSet {
		categories = append(categories, cat)
	}
	sort.Strings(categories)
	sort.Slice(scripts, func(i, j int) bool { return scripts[i].name < scripts[j].name })

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
