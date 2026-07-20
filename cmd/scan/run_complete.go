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
	"strconv"
	"strings"

	"github.com/carapace-sh/carapace"
	"github.com/carapace-sh/carapace-bridge/pkg/actions/bridge"

	"github.com/d3c3ptive/aims/client"
	aims "github.com/d3c3ptive/aims/cmd"
	"github.com/d3c3ptive/aims/cmd/agentctx"
	"github.com/d3c3ptive/aims/cmd/credentials"
	"github.com/d3c3ptive/aims/cmd/display"
	credential "github.com/d3c3ptive/aims/credential/pb"
	credrpc "github.com/d3c3ptive/aims/credential/pb/rpc"
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
			case "-p":
				return completePortValue(con)
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

// targetGroupOrder fixes the order sub-groups are presented in: the shared agent-context relevance
// groups first (agentctx.PromotedOrder), then the intrinsic locality groups.
var targetGroupOrder = agentctx.PromotedOrder(tagRoutable, tagPrivate, tagLoopback, tagNoAddr)

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
//
// When an agent context is loaded, the grouping is relative to that agent's host, so the cache name
// carries the agent id — a different loaded agent gets a distinct entry, and repeated Tabs at the
// same context stay a hit. The agent id comes from the cheap env read (agentctx.Current); the full
// agent host is resolved once per cache-miss inside the callback.
func cachedTargets(con *client.Client) carapace.Action {
	name := "scan:nmap:targets"
	if ctx, ok := agentctx.Current(); ok {
		name += ":" + ctx.ID
	}

	return aims.CacheCompletion(con, name, carapace.ActionCallback(func(_ carapace.Context) carapace.Action {
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

		// The agent's host is the base for context-aware grouping; nil when no context is loaded.
		agentHost, _ := agentctx.CurrentHost(con)

		// A CIDR is a valid nmap target, so the target slot offers individual hosts *and* the
		// subnets clustered from them (both promoted by agent context).
		return carapace.Batch(
			groupedTargets(res.GetHosts(), agentHost),
			groupedSubnets(res.GetHosts(), agentHost),
		).ToA()
	}))
}

// groupedTargets partitions hosts into sub-groups and renders each as its own tagged carapace
// group, reusing the shared display engine for the (candidate, description) rows exactly as
// hosts.CompleteByHostnameOrIP does — the hostname is the inserted value, the address the fallback
// for hosts with no name. When agentHost is non-nil (a context is loaded), the agent's own host and
// its subnet neighbours are promoted into their own groups ahead of the locality groups; otherwise
// hosts fall into their locality group as before.
func groupedTargets(all []*pb.Host, agentHost *pb.Host) carapace.Action {
	buckets := make(map[string][]*pb.Host, len(targetGroupOrder))
	for _, h := range all {
		tag := targetTag(h, agentHost)
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

// targetTag chooses a host's completion group. With an agent context loaded (agentHost non-nil),
// the shared classifier promotes the agent's own host and its subnet neighbours into dedicated
// relevance groups; every other host — and every host when no context is loaded — falls into its
// intrinsic locality group.
func targetTag(h, agentHost *pb.Host) string {
	if tag := agentctx.RelevanceOfHost(h, agentHost).Tag(); tag != "" {
		return tag
	}
	return hostLocality(h)
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
	case "port":
		return completePortValue(con)
	case "secret":
		return completeSecret(con)
	case "url":
		return completeWebURL(con)
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
	case base == "port":
		return "port"
	case strings.Contains(base, "password") || strings.Contains(base, "passphrase"):
		return "secret"
	case base == "url" || base == "uri":
		return "url"
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

//
// [ Port values — DB open ports + common services, agent-promoted ] -----------------------------
//

const (
	tagPortsDB     = "open ports (database)"
	tagPortsCommon = "common ports"
)

// portGroupOrder: agent-context relevance groups first (agentctx.PromotedOrder), then the other DB
// ports, then the curated well-known ports.
var portGroupOrder = agentctx.PromotedOrder(tagPortsDB, tagPortsCommon)

// completePortValue completes a port value — nmap's `-p` (comma-separated) and NSE `*.port` — from
// the DB's known open ports plus a curated set of well-known ports. Ports open on the current
// agent's host, then on its subnet neighbours, are promoted via the shared relevance layer, so the
// operator sees "what's open around here" first. Cached; the cache key carries the agent id.
func completePortValue(con *client.Client) carapace.Action {
	return carapace.ActionMultiParts(",", func(carapace.Context) carapace.Action {
		return cachedPorts(con)
	})
}

func cachedPorts(con *client.Client) carapace.Action {
	name := "scan:nmap:ports"
	if ctx, ok := agentctx.Current(); ok {
		name += ":" + ctx.ID
	}

	return aims.CacheCompletion(con, name, carapace.ActionCallback(func(_ carapace.Context) carapace.Action {
		if msg, err := con.ConnectComplete(); err != nil {
			return msg
		}

		res, err := con.Hosts.Read(context.Background(), &hostrpc.ReadHostRequest{
			Host:    &pb.Host{},
			Filters: &hostrpc.HostFilters{Ports: true},
		})
		if err = aims.CheckError(err); err != nil {
			return carapace.ActionMessage("Error: %s", err)
		}

		agentHost, _ := agentctx.CurrentHost(con)
		return groupedPorts(res.GetHosts(), agentHost)
	}))
}

// portInfo aggregates one open port number across the host set: its service name and protocol
// (first seen), how many hosts have it open, and the closest agent-context relevance of any host
// that exposes it.
type portInfo struct {
	number  uint32
	proto   string
	service string
	rel     agentctx.Relevance
	hosts   int
}

// collectOpenPorts aggregates every host's open ports by number, keeping the highest agent-context
// relevance of any host exposing each port — so a port open on the agent host outranks the same port
// number seen only on a distant host. Sorted by number.
func collectOpenPorts(all []*pb.Host, agentHost *pb.Host) []*portInfo {
	byNum := make(map[uint32]*portInfo)
	for _, h := range all {
		rel := agentctx.RelevanceOfHost(h, agentHost)
		for _, p := range h.GetPorts() {
			if p.GetState().GetState() != "open" {
				continue
			}
			pi := byNum[p.GetNumber()]
			if pi == nil {
				pi = &portInfo{number: p.GetNumber(), proto: p.GetProtocol()}
				byNum[p.GetNumber()] = pi
			}
			if pi.service == "" {
				pi.service = p.GetService().GetName()
			}
			if rel > pi.rel {
				pi.rel = rel
			}
			pi.hosts++
		}
	}

	out := make([]*portInfo, 0, len(byNum))
	for _, pi := range byNum {
		out = append(out, pi)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].number < out[j].number })
	return out
}

// groupedPorts renders the aggregated open ports as promoted, described carapace groups, then adds
// the curated well-known ports not already present under a "common ports" group — so completion is
// useful even against an empty database.
func groupedPorts(all []*pb.Host, agentHost *pb.Host) carapace.Action {
	buckets := make(map[string][]string)
	seen := make(map[uint32]bool)

	for _, pi := range collectOpenPorts(all, agentHost) {
		tag := pi.rel.Tag()
		if tag == "" {
			tag = tagPortsDB
		}
		buckets[tag] = append(buckets[tag], strconv.Itoa(int(pi.number)), portDesc(pi))
		seen[pi.number] = true
	}

	for _, cp := range commonPorts() {
		if seen[cp.number] {
			continue
		}
		buckets[tagPortsCommon] = append(buckets[tagPortsCommon], strconv.Itoa(int(cp.number)), cp.name+" (well-known)")
	}

	actions := make([]carapace.Action, 0, len(portGroupOrder))
	for _, tag := range portGroupOrder {
		if pairs := buckets[tag]; len(pairs) > 0 {
			actions = append(actions, carapace.ActionValuesDescribed(pairs...).Tag(tag))
		}
	}
	if len(actions) == 0 {
		return carapace.ActionMessage("no ports known")
	}
	return carapace.Batch(actions...).ToA()
}

// portDesc describes a DB port: its service (or protocol), and how many hosts have it open.
func portDesc(pi *portInfo) string {
	label := pi.service
	if label == "" {
		label = pi.proto
	}
	if label == "" {
		label = "open"
	}
	unit := " hosts"
	if pi.hosts == 1 {
		unit = " host"
	}
	return label + " · " + strconv.Itoa(pi.hosts) + unit
}

// namedPort is a well-known (port, service) pair for the curated fallback set.
type namedPort struct {
	number uint32
	name   string
}

// commonPorts is a small curated set of well-known ports, offered so port completion is useful even
// with an empty database. Deduplicated against the DB ports at render time.
func commonPorts() []namedPort {
	return []namedPort{
		{21, "ftp"}, {22, "ssh"}, {23, "telnet"}, {25, "smtp"}, {53, "dns"},
		{80, "http"}, {110, "pop3"}, {135, "msrpc"}, {139, "netbios-ssn"},
		{143, "imap"}, {443, "https"}, {445, "microsoft-ds"}, {993, "imaps"},
		{995, "pop3s"}, {1433, "mssql"}, {1521, "oracle"}, {3306, "mysql"},
		{3389, "rdp"}, {5432, "postgresql"}, {5900, "vnc"}, {6379, "redis"},
		{8080, "http-proxy"}, {8443, "https-alt"}, {27017, "mongodb"},
	}
}

//
// [ Secrets — known credentials, typed and agent-promoted ] -------------------------------------
//

// completeSecret completes a secret value — an NSE `*.password`/`*.passphrase` arg, and any
// brute/auth tool's secret flag later — from the credential store, so known passwords/hashes can be
// reused (AIMS's whole point). Secrets are grouped by credential type (the PrivateType axis), and
// the credentials used on the current agent's host are promoted to the top via the relevance layer
// (RelevanceOfHostID over the Logins that attach a credential to a host). Cached; key carries the
// agent id.
//
// Note: this deliberately surfaces plaintext secrets as completion values — that is the point of
// credential reuse, and the operator owns the store (cf. Sliver's GetPlaintextCredsByHashType).
func completeSecret(con *client.Client) carapace.Action {
	name := "scan:secret"
	if ctx, ok := agentctx.Current(); ok {
		name += ":" + ctx.ID
	}

	return aims.CacheCompletion(con, name, carapace.ActionCallback(func(_ carapace.Context) carapace.Action {
		if msg, err := con.ConnectComplete(); err != nil {
			return msg
		}

		res, err := con.Creds.List(context.Background(), &credrpc.ReadCredentialRequest{Credential: &credential.Core{}})
		if err = aims.CheckError(err); err != nil {
			return carapace.ActionMessage("Error: %s", err)
		}
		if len(res.GetCredentials()) == 0 {
			return carapace.ActionMessage("no credentials in database")
		}

		agentHost, _ := agentctx.CurrentHost(con)
		return groupedSecrets(res.GetCredentials(), agentHostCredIDs(con, agentHost))
	}))
}

// agentHostCredIDs returns the set of credential ids that have a login on the current agent's host —
// the credentials to promote. It reads the Logins service filtered by the agent host id and keeps
// those the relevance layer marks AgentHost. Empty (nil) when no context is loaded.
func agentHostCredIDs(con *client.Client, agentHost *pb.Host) map[string]bool {
	if agentHost == nil {
		return nil
	}
	res, err := con.Logins.List(context.Background(), &credrpc.ReadLoginRequest{
		Login: &credential.Login{HostId: agentHost.GetId()},
	})
	if err != nil {
		return nil
	}

	ids := make(map[string]bool)
	for _, l := range res.GetLogins() {
		if agentctx.RelevanceOfHostID(l.GetHostId(), agentHost) != agentctx.AgentHost {
			continue
		}
		if id := l.GetCore().GetId(); id != "" {
			ids[id] = true
		}
	}
	return ids
}

// groupedSecrets renders credentials that carry a usable secret as tagged, described carapace
// groups: those used on the agent host are promoted to the context group, the rest grouped by
// credential type. The candidate is the secret itself; the description carries who it belongs to.
func groupedSecrets(creds []*credential.Core, agentCreds map[string]bool) carapace.Action {
	buckets := make(map[string][]string)
	for _, c := range creds {
		data := c.GetPrivate().GetData()
		if data == "" {
			continue // no usable secret (bare username / blank)
		}
		tag := secretTypeGroup(c.GetPrivate().GetType())
		if agentCreds[c.GetId()] {
			tag = agentctx.TagContext
		}
		buckets[tag] = append(buckets[tag], data, secretDesc(c))
	}

	actions := make([]carapace.Action, 0, len(secretGroupOrder)+1)
	for _, tag := range secretGroupOrder {
		if pairs := buckets[tag]; len(pairs) > 0 {
			actions = append(actions, carapace.ActionValuesDescribed(pairs...).Tag(tag))
		}
	}
	if len(actions) == 0 {
		return carapace.ActionMessage("no reusable secrets in database")
	}
	return carapace.Batch(actions...).ToA()
}

// secretGroupOrder: the agent-context group first (PromotedOrder), then the credential-type groups.
var secretGroupOrder = agentctx.PromotedOrder(
	"passwords", "NTLM hashes", "replayable hashes",
	"non-replayable hashes", "PostgreSQL hashes", "keys", "JWTs",
)

// secretTypeGroup maps a credential's private type to its group tag. AIMS's PrivateType is the
// coarse axis available here; a finer hash vocabulary (e.g. hashcat modes) would be a type-list
// completer of its own — see COMPLETERS.md.
func secretTypeGroup(t credential.PrivateType) string {
	switch t {
	case credential.PrivateType_NTLMHash:
		return "NTLM hashes"
	case credential.PrivateType_PostgresMD5:
		return "PostgreSQL hashes"
	case credential.PrivateType_ReplayableHash:
		return "replayable hashes"
	case credential.PrivateType_NonReplayableHash:
		return "non-replayable hashes"
	case credential.PrivateType_Key:
		return "keys"
	case credential.PrivateType_JWT:
		return "JWTs"
	default:
		return "passwords"
	}
}

// secretDesc describes a secret candidate by who it belongs to (username @ realm) and its type, so
// the operator picks the right one without reading the secret itself.
func secretDesc(c *credential.Core) string {
	who := c.GetPublic().GetUsername()
	if r := c.GetRealm().GetValue(); r != "" {
		if who != "" {
			who += " @ " + r
		} else {
			who = "@" + r
		}
	}

	label := secretTypeLabel(c.GetPrivate().GetType())
	if who != "" {
		return who + " · " + label
	}
	return label
}

// secretTypeLabel is the singular per-credential type label used in a secret's description.
func secretTypeLabel(t credential.PrivateType) string {
	switch t {
	case credential.PrivateType_NTLMHash:
		return "NTLM hash"
	case credential.PrivateType_PostgresMD5:
		return "PostgreSQL hash"
	case credential.PrivateType_ReplayableHash:
		return "replayable hash"
	case credential.PrivateType_NonReplayableHash:
		return "non-replayable hash"
	case credential.PrivateType_Key:
		return "key"
	case credential.PrivateType_JWT:
		return "JWT"
	default:
		return "password"
	}
}

//
// [ Web URLs — synthesized from DB web services, agent-promoted ] -------------------------------
//

const (
	tagURLHTTPS   = "https endpoints"
	tagURLHTTP    = "http endpoints"
	tagURLGuessed = "web (guessed ports)"
)

// urlGroupOrder: agent-context relevance groups first, then https, http, and guessed-port endpoints.
var urlGroupOrder = agentctx.PromotedOrder(tagURLHTTPS, tagURLHTTP, tagURLGuessed)

// webPorts are ports treated as web endpoints even without a named http service (the "guessed" tier).
var webPorts = map[uint32]bool{
	80: true, 443: true, 3000: true, 5000: true, 8000: true, 8008: true,
	8080: true, 8081: true, 8443: true, 8888: true, 4443: true, 9443: true,
}

// completeWebURL completes a URL value — an NSE `*.url`/`*.uri` arg, and any web scanner's
// `-u`/`--url` later — by synthesizing `scheme://host[:port]/` from the DB's web services rather
// than completing free text. Endpoints on the current agent's host, then its subnet, are promoted
// via the relevance layer; the rest are grouped by scheme (with un-fingerprinted web ports flagged
// as guesses). Cached; the cache key carries the agent id.
func completeWebURL(con *client.Client) carapace.Action {
	name := "scan:nmap:urls"
	if ctx, ok := agentctx.Current(); ok {
		name += ":" + ctx.ID
	}

	return aims.CacheCompletion(con, name, carapace.ActionCallback(func(_ carapace.Context) carapace.Action {
		if msg, err := con.ConnectComplete(); err != nil {
			return msg
		}

		res, err := con.Hosts.Read(context.Background(), &hostrpc.ReadHostRequest{
			Host:    &pb.Host{},
			Filters: &hostrpc.HostFilters{Ports: true},
		})
		if err = aims.CheckError(err); err != nil {
			return carapace.ActionMessage("Error: %s", err)
		}

		agentHost, _ := agentctx.CurrentHost(con)
		return groupedURLs(res.GetHosts(), agentHost)
	}))
}

// groupedURLs synthesizes a URL per open web port and renders them as promoted, described groups.
// A named http/https service is authoritative; an open web-ish port without one is offered as a
// guess. Duplicate URLs are dropped. Each group is NoSpace('/') so the operator can extend the path.
func groupedURLs(all []*pb.Host, agentHost *pb.Host) carapace.Action {
	buckets := make(map[string][]string)
	seen := make(map[string]bool)

	for _, h := range all {
		rel := agentctx.RelevanceOfHost(h, agentHost)
		for _, p := range h.GetPorts() {
			if p.GetState().GetState() != "open" {
				continue
			}
			named := isNamedWeb(p)
			guessed := !named && webPorts[p.GetNumber()]
			if !named && !guessed {
				continue
			}

			host := urlHost(h, p)
			if host == "" {
				continue
			}
			scheme := schemeOf(p)
			url := buildURL(scheme, host, p.GetNumber())
			if seen[url] {
				continue
			}
			seen[url] = true

			tag := rel.Tag()
			if tag == "" {
				switch {
				case guessed:
					tag = tagURLGuessed
				case scheme == "https":
					tag = tagURLHTTPS
				default:
					tag = tagURLHTTP
				}
			}
			buckets[tag] = append(buckets[tag], url, urlDesc(h, p))
		}
	}

	actions := make([]carapace.Action, 0, len(urlGroupOrder))
	for _, tag := range urlGroupOrder {
		if pairs := buckets[tag]; len(pairs) > 0 {
			actions = append(actions, carapace.ActionValuesDescribed(pairs...).Tag(tag).NoSpace('/'))
		}
	}
	if len(actions) == 0 {
		return carapace.ActionMessage("no web services in database")
	}
	return carapace.Batch(actions...).ToA()
}

// isNamedWeb reports whether a port carries a named http/https service (any service name containing
// "http", including nmap's "ssl/http").
func isNamedWeb(p *pb.Port) bool {
	return strings.Contains(strings.ToLower(p.GetService().GetName()), "http")
}

// schemeOf picks the URL scheme: nmap's ssl/tls tunnel or an https-ish service name wins, then the
// well-known TLS ports, else http.
func schemeOf(p *pb.Port) string {
	svc := p.GetService()
	tunnel := strings.ToLower(svc.GetTunnel())
	name := strings.ToLower(svc.GetName())
	if tunnel == "ssl" || tunnel == "tls" || strings.Contains(name, "https") || strings.Contains(name, "ssl") {
		return "https"
	}
	switch p.GetNumber() {
	case 443, 8443, 4443, 9443:
		return "https"
	}
	return "http"
}

// urlHost picks the host part of the URL: the service's own hostname (a vhost from the cert/HTTP
// host) first, then one of the host's hostnames, then an address.
func urlHost(h *pb.Host, p *pb.Port) string {
	if hn := p.GetService().GetHostname(); hn != "" {
		return hn
	}
	for _, hn := range h.GetHostnames() {
		if hn.GetName() != "" {
			return hn.GetName()
		}
	}
	for _, a := range h.GetAddresses() {
		if a.GetAddr() != "" {
			return a.GetAddr()
		}
	}
	return ""
}

// buildURL assembles scheme://host[:port]/ — the default port for the scheme is omitted, an IPv6
// literal is bracketed.
func buildURL(scheme, host string, port uint32) string {
	if strings.Contains(host, ":") && net.ParseIP(host) != nil {
		host = "[" + host + "]"
	}

	def := uint32(80)
	if scheme == "https" {
		def = 443
	}
	if port != 0 && port != def {
		host += ":" + strconv.Itoa(int(port))
	}
	return scheme + "://" + host + "/"
}

// urlDesc describes a synthesized URL by the service product/version and the owning host.
func urlDesc(h *pb.Host, p *pb.Port) string {
	var parts []string
	if prod := p.GetService().GetProduct(); prod != "" {
		if ver := p.GetService().GetVersion(); ver != "" {
			prod += " " + ver
		}
		parts = append(parts, prod)
	}

	label := ""
	for _, hn := range h.GetHostnames() {
		if hn.GetName() != "" {
			label = hn.GetName()
			break
		}
	}
	if label == "" {
		for _, a := range h.GetAddresses() {
			if a.GetAddr() != "" {
				label = a.GetAddr()
				break
			}
		}
	}
	if label != "" {
		parts = append(parts, label)
	}

	return strings.Join(parts, " · ")
}

//
// [ Subnets — clustered from DB addresses + agent seeds ] ---------------------------------------
//

const (
	tagSubnetAgent    = "agent subnets"
	tagSubnetDense    = "private subnets (dense)"
	tagSubnetPrivate  = "private subnets"
	tagSubnetRoutable = "routable subnets"

	// subnetDenseThreshold is the known-host count at which a private subnet is promoted from the
	// "private" group to the "dense" one.
	subnetDenseThreshold = 4
)

// subnetGroupOrder ranks the subnet groups: the agent's own subnets first, then private subnets by
// density, then routable last.
var subnetGroupOrder = []string{tagSubnetAgent, tagSubnetDense, tagSubnetPrivate, tagSubnetRoutable}

// subnetInfo aggregates one candidate subnet: its CIDR, how many known hosts fall in it, its
// locality, whether the agent belongs to it (an agent address or gateway sits inside), and an
// optional gateway annotation.
type subnetInfo struct {
	cidr     string
	hosts    int
	locality string
	isAgent  bool
	gateway  string
	v6       bool
}

// collectSubnets clusters the DB's host addresses into /24 (v4) and /64 (v6) prefixes, then seeds
// the agent host's own subnets and its last-hop gateway — marked as the agent's, and offered even
// when no other host is known there ("sweep to discover"). Sorted by host density (desc) then CIDR.
func collectSubnets(all []*pb.Host, agentHost *pb.Host) []*subnetInfo {
	byNet := make(map[string]*subnetInfo)

	touch := func(addr string) *subnetInfo {
		ip := net.ParseIP(strings.TrimSpace(addr))
		if ip == nil || ip.IsLoopback() {
			return nil
		}
		cidr, ok := agentctx.SubnetOf(ip)
		if !ok {
			return nil
		}
		si := byNet[cidr]
		if si == nil {
			si = &subnetInfo{cidr: cidr, locality: localityOf(addr), v6: ip.To4() == nil}
			byNet[cidr] = si
		}
		return si
	}

	for _, h := range all {
		for _, a := range h.GetAddresses() {
			if si := touch(a.GetAddr()); si != nil {
				si.hosts++
			}
		}
	}

	if agentHost != nil {
		for _, a := range agentHost.GetAddresses() {
			if si := touch(a.GetAddr()); si != nil {
				si.isAgent = true
			}
		}
		if gw := lastGateway(agentHost); gw != "" {
			if si := touch(gw); si != nil {
				si.isAgent = true
				si.gateway = gw
			}
		}
	}

	out := make([]*subnetInfo, 0, len(byNet))
	for _, si := range byNet {
		out = append(out, si)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].hosts != out[j].hosts {
			return out[i].hosts > out[j].hosts
		}
		return out[i].cidr < out[j].cidr
	})
	return out
}

// groupedSubnets renders the clustered subnets as ranked, described carapace groups. Prefixes are
// capped at /24 and /64 (SubnetOf), so clustering never rolls scattered addresses up into a wider
// sweep. Returns an empty action (contributing nothing to the target slot) when there are none.
func groupedSubnets(all []*pb.Host, agentHost *pb.Host) carapace.Action {
	buckets := make(map[string][]string)
	for _, si := range collectSubnets(all, agentHost) {
		tag := subnetTag(si)
		buckets[tag] = append(buckets[tag], si.cidr, subnetDesc(si))
	}

	actions := make([]carapace.Action, 0, len(subnetGroupOrder))
	for _, tag := range subnetGroupOrder {
		if pairs := buckets[tag]; len(pairs) > 0 {
			actions = append(actions, carapace.ActionValuesDescribed(pairs...).Tag(tag))
		}
	}
	if len(actions) == 0 {
		return carapace.ActionValues()
	}
	return carapace.Batch(actions...).ToA()
}

// subnetTag ranks a subnet: the agent's own subnets first, then routable last, else private split by
// density.
func subnetTag(si *subnetInfo) string {
	if si.isAgent {
		return tagSubnetAgent
	}
	if si.locality == "routable" {
		return tagSubnetRoutable
	}
	if si.hosts >= subnetDenseThreshold {
		return tagSubnetDense
	}
	return tagSubnetPrivate
}

// subnetDesc describes a subnet by its gateway (when it's the agent's), host count (or "sweep to
// discover" when none known yet), a public marker, and an IPv6 marker.
func subnetDesc(si *subnetInfo) string {
	var parts []string
	if si.gateway != "" {
		parts = append(parts, "gateway "+si.gateway)
	}
	if si.hosts == 0 {
		parts = append(parts, "sweep to discover")
	} else {
		unit := "hosts"
		if si.hosts == 1 {
			unit = "host"
		}
		parts = append(parts, strconv.Itoa(si.hosts)+" "+unit)
	}
	if si.locality == "routable" {
		parts = append(parts, "public")
	}
	if si.v6 {
		parts = append(parts, "IPv6")
	}
	return strings.Join(parts, " · ")
}

// lastGateway returns the IP of the hop adjacent to the agent host — its gateway — from the host's
// traceroute (the second-to-last hop), or "" when the trace is too short to tell.
func lastGateway(h *pb.Host) string {
	hops := h.GetTrace().GetHops()
	if len(hops) < 2 {
		return ""
	}
	return hops[len(hops)-2].GetIPAddr()
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
