package completers

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

// This file holds the value-typed completers — the command-agnostic completions a caller borrows by
// classifying a slot to a type (a scanner's nmap/masscan dispatch, `credentials add --realm`, …).
// The shared substrate they stand on (Guard, cachedCompleter, cachedHostCompleter, renderGroups)
// lives in plumbing.go; each scanner's own glue (dispatchers, flag sets, NSE machinery) stays in
// cmd/scan/run_complete.go.

import (
	"context"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/carapace-sh/carapace"

	"github.com/d3c3ptive/aims/client"
	aims "github.com/d3c3ptive/aims/cmd"
	"github.com/d3c3ptive/aims/cmd/agentctx"
	"github.com/d3c3ptive/aims/cmd/display"
	credential "github.com/d3c3ptive/aims/credential/pb"
	credrpc "github.com/d3c3ptive/aims/credential/pb/rpc"
	"github.com/d3c3ptive/aims/host"
	pb "github.com/d3c3ptive/aims/host/pb"
	hostrpc "github.com/d3c3ptive/aims/host/pb/rpc"
	"github.com/d3c3ptive/aims/network"
)

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

// Targets completes a target slot with known hosts, sub-grouped by address locality, and
// drops any target already present on the command line. It is the shared target completer — the
// nmap positional target slot and NSE host-valued script args both use it — so excluding
// already-chosen targets happens here, once, for every reuse site.
//
// The exclusion (Filter against c.Args) is applied *outside* the cache: cachedTargets stores the
// whole host set once, and each keystroke filters that set against the live arguments. Filtering by
// exact token is safe against the DisableFlagParsing arg stream — flags and flag-values (-sS, a
// --script value) never equal a host candidate.
func Targets(con *client.Client) carapace.Action {
	return carapace.ActionCallback(func(c carapace.Context) carapace.Action {
		return cachedTargets(con).Filter(c.Args...)
	})
}

// cachedTargets is the cached whole-host-set candidate action behind Targets. It is a
// scan-local completion (not a call into cmd/hosts) precisely because the shared
// hosts.CompleteByHostnameOrIP flattens the address away, and locality grouping needs it. The
// caching, agent-scoping and teamclient read are the shared cachedHostCompleter shell.
func cachedTargets(con *client.Client) carapace.Action {
	// A CIDR is a valid nmap target, so the target slot offers individual hosts *and* the subnets
	// clustered from them (both promoted by agent context). The agent host is nil with no context.
	return cachedHostCompleter(con, "scan:nmap:targets", "targets", nil, "no hosts in database",
		func(hosts []*pb.Host, agentHost *pb.Host) carapace.Action {
			return carapace.Batch(
				groupedTargets(hosts, agentHost),
				groupedSubnets(hosts, agentHost),
			).ToA()
		})
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

	// Convert each host group to (candidate, description) pairs through the shared display engine —
	// the hostname is the inserted value, the address the fallback — then render the tagged groups.
	described := make(map[string][]string, len(buckets))
	for tag, group := range buckets {
		options := host.Completions()
		options = append(options, display.WithCandidateValue("Hostnames", "Addresses"))
		options = append(options, display.WithSplitCandidate(","))
		described[tag] = display.Completions(group, host.DisplayFields, options...)
	}

	return renderGroups(targetGroupOrder, described, "")
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

// Interface completes a network-interface value — nmap's `-e`, an NSE `*.interface` arg,
// and any other scanner's interface flag — from the LOCAL machine's interfaces (the box the
// completion process runs on). It is deliberately not agent-context aware: interfaces belong to the
// operator's host, not the possibly-remote loaded agent. Purely local and cheap, so it is not
// cached. Interfaces are grouped up vs down (you scan from an up interface), each described by its
// addresses.
func Interface() carapace.Action {
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
// stripped) and a loopback marker, or "no address". Split from Interface so it can be
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

// SourceAddr completes a source-address value — nmap's `-S`, masscan's `--source-ip`/
// `--adapter-ip` — from the LOCAL machine's interface addresses: the legitimate source IPs a scan can
// send from. Like Interface it is deliberately local, not agent-context (the source belongs
// to the box running the scan tooling, not the possibly-remote loaded agent). Free-form is still
// accepted — spoofing an arbitrary address — this only offers the real local addresses as a shortcut.
func SourceAddr() carapace.Action {
	ifaces, err := net.Interfaces()
	if err != nil {
		return carapace.ActionMessage("cannot list interfaces: %s", err)
	}
	var pairs []string
	for _, ic := range ifaces {
		addrs, _ := ic.Addrs()
		pairs = append(pairs, localAddrLabels(ic.Name, ic.Flags&net.FlagUp != 0, ic.Flags&net.FlagLoopback != 0, addrs)...)
	}
	if len(pairs) == 0 {
		return carapace.ActionMessage("no local source addresses found")
	}
	return carapace.ActionValuesDescribed(pairs...).Tag("local addresses")
}

// localAddrLabels returns (address, "on <iface>") pairs for one interface's addresses, or nil when the
// interface is down or loopback — you cannot legitimately source a scan from either. Split out so it
// is testable without the machine's real interfaces.
func localAddrLabels(name string, up, loopback bool, addrs []net.Addr) []string {
	if !up || loopback {
		return nil
	}
	var out []string
	for _, a := range addrs {
		ip := a.String()
		if ipn, ok := a.(*net.IPNet); ok {
			ip = ipn.IP.String()
		}
		if ip == "" {
			continue
		}
		out = append(out, ip, "on "+name)
	}
	return out
}

//
// [ Port values — DB open ports + common services, agent-promoted ] -----------------------------
//

const (
	tagPortsDB      = "open ports (database)"
	tagPortsCommon  = "common ports"
	tagPortsService = "service names"
)

// portGroupOrder: agent-context relevance groups first (agentctx.PromotedOrder), then the other DB
// ports, then the curated well-known ports, then the named-service tokens (nmap `-p http` — the
// "service names" group is only ever populated for nmap; masscan/NSE port slots keep it empty).
var portGroupOrder = agentctx.PromotedOrder(tagPortsDB, tagPortsCommon, tagPortsService)

// PortValue completes a numeric port value — masscan's `-p`/`--ports` and NSE `*.port` — from
// the DB's known open ports plus a curated set of well-known ports. Ports open on the current agent's
// host, then on its subnet neighbours, are promoted via the shared relevance layer, so the operator
// sees "what's open around here" first. Cached; the cache key carries the agent id.
func PortValue(con *client.Client) carapace.Action {
	return completePortValueMode(con, false)
}

// PortSpec is PortValue plus named-service tokens (ssh, http, …), for nmap's `-p`,
// which — unlike masscan — accepts a service name and expands it via nmap-services. The service group
// renders last, after the numeric ports.
func PortSpec(con *client.Client) carapace.Action {
	return completePortValueMode(con, true)
}

func completePortValueMode(con *client.Client, withServices bool) carapace.Action {
	return carapace.ActionMultiParts(",", func(carapace.Context) carapace.Action {
		return cachedPorts(con, withServices)
	})
}

func cachedPorts(con *client.Client, withServices bool) carapace.Action {
	name := "scan:nmap:ports"
	if withServices {
		name += ":svc"
	}
	return cachedHostCompleter(con, name, "ports", &hostrpc.HostFilters{Ports: true}, "",
		func(hosts []*pb.Host, agentHost *pb.Host) carapace.Action {
			return groupedPorts(hosts, agentHost, withServices)
		})
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
			if p.GetState().GetState() != host.PortOpen {
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
func groupedPorts(all []*pb.Host, agentHost *pb.Host, withServices bool) carapace.Action {
	buckets := make(map[string][]string)
	seen := make(map[uint32]bool)

	ports := collectOpenPorts(all, agentHost)
	for _, pi := range ports {
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

	// nmap `-p` also accepts service names (expanded via nmap-services); offer the names known from
	// the DB's open ports and the curated set as their own group. masscan/NSE pass withServices=false.
	if withServices {
		buckets[tagPortsService] = serviceNameGroup(ports)
	}

	return renderGroups(portGroupOrder, buckets, "no ports known")
}

// serviceNameGroup builds the (name, description) pairs for the "service names" group of nmap's `-p`:
// the distinct service names seen on the DB's open ports (described by their port), then the curated
// well-known names not already present. Deduplicated by name, first-seen order preserved.
func serviceNameGroup(ports []*portInfo) []string {
	seen := make(map[string]bool)
	var out []string
	for _, pi := range ports {
		if pi.service != "" && !seen[pi.service] {
			seen[pi.service] = true
			out = append(out, pi.service, strconv.Itoa(int(pi.number))+"/"+pi.proto)
		}
	}
	for _, cp := range commonPorts() {
		if !seen[cp.name] {
			seen[cp.name] = true
			out = append(out, cp.name, strconv.Itoa(int(cp.number))+" (well-known)")
		}
	}
	return out
}

// portDesc describes a DB port: its service (or protocol), and how many hosts have it open.
func portDesc(pi *portInfo) string {
	label := pi.service
	if label == "" {
		label = pi.proto
	}
	if label == "" {
		label = host.PortOpen
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

// Secret completes a secret value — an NSE `*.password`/`*.passphrase` arg, and any
// brute/auth tool's secret flag later — from the credential store, so known passwords/hashes can be
// reused (AIMS's whole point). Secrets are grouped by credential type (the PrivateType axis), and
// the credentials used on the current agent's host are promoted to the top via the relevance layer
// (RelevanceOfHostID over the Logins that attach a credential to a host). Cached; key carries the
// agent id.
//
// Note: this deliberately surfaces plaintext secrets as completion values — that is the point of
// credential reuse, and the operator owns the store (cf. Sliver's GetPlaintextCredsByHashType).
func Secret(con *client.Client) carapace.Action {
	return cachedCompleter(con, "scan:secret", "secret", func() carapace.Action {
		creds, agentCreds, err := credsWithAgentPromotion(con)
		if err = aims.CheckError(err); err != nil {
			return carapace.ActionMessage("Error: %s", err)
		}
		if len(creds) == 0 {
			return carapace.ActionMessage("no credentials in database")
		}
		return groupedSecrets(creds, agentCreds)
	})
}

// credsWithAgentPromotion runs the two independent legs of an agent-context credential completer
// concurrently: the full credential list, and the agent-host credential-id promote-set (itself a
// CurrentHost resolve → Logins.List chain). The legs share no data until the render, so overlapping
// them removes the serial wait that dominated Secret/Username on a cache miss (the Creds.List no
// longer blocks in front of the 2-RPC host resolve). Only the credential-list error is returned; the
// promotion leg degrades to an empty (nil) set on error rather than failing the whole completion.
// gRPC clients are safe for concurrent use and the legs write disjoint variables, so no lock is
// needed beyond the WaitGroup join.
func credsWithAgentPromotion(con *client.Client) (creds []*credential.Core, agentCreds map[string]bool, err error) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		res, listErr := con.Creds.List(context.Background(), &credrpc.ReadCredentialRequest{Credential: &credential.Core{}})
		creds, err = res.GetCredentials(), listErr
	}()

	go func() {
		defer wg.Done()
		agentHost, _ := currentHost(con)
		agentCreds = agentHostCredIDs(con, agentHost)
	}()

	wg.Wait()
	return creds, agentCreds, err
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
// [ Usernames — credential logins, paired with their secret, agent-promoted ] -------------------
//

const (
	tagUserWithSecret = "with known secret"
	tagUserNoSecret   = "username only"
)

// usernameGroupOrder: the agent-context group first (PromotedOrder), then usernames whose password/
// hash we hold, then the bare usernames.
var usernameGroupOrder = agentctx.PromotedOrder(tagUserWithSecret, tagUserNoSecret)

// Username completes a username value — an NSE `*.username`/`*.user` arg, and any auth tool's
// user flag later — from the credential store, and is the username half of the credential pair: each
// candidate is described by the secret it is paired with (its type and realm), so the operator picks
// a username *knowing* whether its password is on hand. It mirrors Secret's agent-context
// promotion on the username axis — usernames whose login is on the agent's host lead. This replaces
// the flat credentials.CompleteByUsername for scan slots. Cached; the key carries the agent id.
func Username(con *client.Client) carapace.Action {
	return cachedCompleter(con, "scan:username", "username", func() carapace.Action {
		creds, agentCreds, err := credsWithAgentPromotion(con)
		if err = aims.CheckError(err); err != nil {
			return carapace.ActionMessage("Error: %s", err)
		}
		if len(creds) == 0 {
			return carapace.ActionMessage("no credentials in database")
		}
		return groupedUsernames(creds, agentCreds)
	})
}

// groupedUsernames renders distinct usernames as tagged, described groups. A username can appear on
// several credentials; the one kept per username is the most useful — an agent-host login outranks a
// login with a secret outranks a bare one (usernameScore) — and its group and description come from
// that credential. The username is the inserted value; the description names the paired secret.
func groupedUsernames(creds []*credential.Core, agentCreds map[string]bool) carapace.Action {
	best := make(map[string]*credential.Core)
	for _, c := range creds {
		u := c.GetPublic().GetUsername()
		if u == "" {
			continue
		}
		if cur, ok := best[u]; !ok || usernameScore(c, agentCreds) > usernameScore(cur, agentCreds) {
			best[u] = c
		}
	}
	if len(best) == 0 {
		return carapace.ActionMessage("no usernames in database")
	}

	users := make([]string, 0, len(best))
	for u := range best {
		users = append(users, u)
	}
	sort.Strings(users)

	buckets := make(map[string][]string)
	for _, u := range users {
		c := best[u]
		tag := usernameTag(c, agentCreds[c.GetId()])
		buckets[tag] = append(buckets[tag], u, usernameDesc(c))
	}
	return renderGroups(usernameGroupOrder, buckets, "no usernames in database")
}

// usernameScore ranks the candidates for one username so the most useful wins the dedup: an agent-host
// login (+2) over a login carrying a secret (+1) over a bare username.
func usernameScore(c *credential.Core, agentCreds map[string]bool) int {
	score := 0
	if agentCreds[c.GetId()] {
		score += 2
	}
	if c.GetPrivate().GetData() != "" {
		score++
	}
	return score
}

// usernameTag groups a username: promoted to the agent-context group when its login is on the agent's
// host, else split by whether a usable secret is on hand for it.
func usernameTag(c *credential.Core, isAgent bool) string {
	if isAgent {
		return agentctx.TagContext
	}
	if c.GetPrivate().GetData() != "" {
		return tagUserWithSecret
	}
	return tagUserNoSecret
}

// usernameDesc describes a username by the secret it is paired with (type, "known"/"no secret") and
// its realm — the other half of the credential pair.
func usernameDesc(c *credential.Core) string {
	var parts []string
	if c.GetPrivate().GetData() != "" {
		parts = append(parts, secretTypeLabel(c.GetPrivate().GetType())+" known")
	} else {
		parts = append(parts, "no secret")
	}
	if r := c.GetRealm().GetValue(); r != "" {
		parts = append(parts, "@ "+r)
	}
	return strings.Join(parts, " ")
}

//
// [ MAC addresses — from DB hosts, vendor-described, agent-promoted ] ---------------------------
//

const tagMACKnown = "known MAC addresses"

// macGroupOrder: agent-context relevance groups first, then all other known MACs.
var macGroupOrder = agentctx.PromotedOrder(tagMACKnown)

// MAC completes a MAC-address value — nmap's `--spoof-mac`, masscan's `--router-mac`/
// `--adapter-mac`/`--spoof-mac`, and an NSE `*.mac` arg — from the MACs already in the database (the
// `Host.MAC` field and any address of type "mac", which carries an OUI vendor). MACs on the agent's
// host, then its subnet, are promoted via the relevance layer. Cached; the key carries the agent id.
func MAC(con *client.Client) carapace.Action {
	return cachedHostCompleter(con, "scan:macs", "mac", nil, "no hosts in database", groupedMACs)
}

// macInfo aggregates one MAC across the host set: its vendor (first seen), an owning-host label, and
// the closest agent-context relevance of any host that carries it.
type macInfo struct {
	mac    string
	vendor string
	host   string
	rel    agentctx.Relevance
}

// collectMACs gathers every host's MACs — the Host.MAC field plus any address of type "mac" (which
// also carries a vendor) — deduplicated by normalised MAC, keeping the highest agent-context
// relevance of any host that has it. Sorted by MAC.
func collectMACs(all []*pb.Host, agentHost *pb.Host) []*macInfo {
	byMAC := make(map[string]*macInfo)
	add := func(mac, vendor string, rel agentctx.Relevance, host string) {
		mac = strings.ToLower(strings.TrimSpace(mac))
		if mac == "" {
			return
		}
		mi := byMAC[mac]
		if mi == nil {
			mi = &macInfo{mac: mac}
			byMAC[mac] = mi
		}
		if mi.vendor == "" {
			mi.vendor = vendor
		}
		if mi.host == "" || rel > mi.rel {
			mi.host = host // first seen, or a higher-relevance host takes over the label
		}
		if rel > mi.rel {
			mi.rel = rel
		}
	}

	for _, h := range all {
		rel := agentctx.RelevanceOfHost(h, agentHost)
		label := hostShortLabel(h)
		add(h.GetMAC(), "", rel, label)
		for _, a := range h.GetAddresses() {
			if strings.EqualFold(a.GetType(), network.AddrTypeMAC) {
				add(a.GetAddr(), a.GetVendor(), rel, label)
			}
		}
	}

	out := make([]*macInfo, 0, len(byMAC))
	for _, mi := range byMAC {
		out = append(out, mi)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].mac < out[j].mac })
	return out
}

// groupedMACs renders the known MACs as promoted, described groups: the MAC is the inserted value,
// the description its vendor and owning host.
func groupedMACs(all []*pb.Host, agentHost *pb.Host) carapace.Action {
	buckets := make(map[string][]string)
	for _, mi := range collectMACs(all, agentHost) {
		tag := mi.rel.Tag()
		if tag == "" {
			tag = tagMACKnown
		}
		buckets[tag] = append(buckets[tag], mi.mac, macDesc(mi))
	}
	return renderGroups(macGroupOrder, buckets, "no MAC addresses in database")
}

// macDesc describes a MAC by its vendor (when known) and the host it belongs to.
func macDesc(mi *macInfo) string {
	var parts []string
	if mi.vendor != "" {
		parts = append(parts, mi.vendor)
	}
	if mi.host != "" {
		parts = append(parts, mi.host)
	}
	if len(parts) == 0 {
		return "known MAC"
	}
	return strings.Join(parts, " · ")
}

// hostShortLabel is a compact host identifier for a description: its first hostname, else its first
// address, else "?".
func hostShortLabel(h *pb.Host) string {
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
	return "?"
}

//
// [ Web URLs — synthesized from DB web services, agent-promoted ] -------------------------------
//

const (
	tagURLHTTPS   = "https endpoints"
	tagURLHTTP    = "http endpoints"
	tagURLGuessed = "web (guessed ports)"
	tagURLPaths   = "discovered paths"

	// maxDiscoveredPaths caps the http-enum-derived path URLs offered, so a large enumeration can't
	// flood the completion.
	maxDiscoveredPaths = 40
)

// urlGroupOrder: agent-context relevance groups first, then the paths NSE actually discovered, then
// the synthesized https/http/guessed roots.
var urlGroupOrder = agentctx.PromotedOrder(tagURLPaths, tagURLHTTPS, tagURLHTTP, tagURLGuessed)

// webPorts are ports treated as web endpoints even without a named http service (the "guessed" tier).
var webPorts = map[uint32]bool{
	80: true, 443: true, 3000: true, 5000: true, 8000: true, 8008: true,
	8080: true, 8081: true, 8443: true, 8888: true, 4443: true, 9443: true,
}

// WebURL completes a URL value — an NSE `*.url`/`*.uri` arg, and any web scanner's
// `-u`/`--url` later — by synthesizing `scheme://host[:port]/` from the DB's web services rather
// than completing free text. Endpoints on the current agent's host, then its subnet, are promoted
// via the relevance layer; the rest are grouped by scheme (with un-fingerprinted web ports flagged
// as guesses). Cached; the cache key carries the agent id.
func WebURL(con *client.Client) carapace.Action {
	return cachedHostCompleter(con, "scan:nmap:urls", "web-url",
		&hostrpc.HostFilters{Ports: true}, "", groupedURLs)
}

// groupedURLs synthesizes a URL per open web port and renders them as promoted, described groups.
// A named http/https service is authoritative; an open web-ish port without one is offered as a
// guess. Duplicate URLs are dropped. Each group is NoSpace('/') so the operator can extend the path.
func groupedURLs(all []*pb.Host, agentHost *pb.Host) carapace.Action {
	buckets := make(map[string][]string)
	seen := make(map[string]bool)
	pathCount := 0

	for _, h := range all {
		rel := agentctx.RelevanceOfHost(h, agentHost)
		for _, p := range h.GetPorts() {
			if p.GetState().GetState() != host.PortOpen {
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
			base := urlBase(scheme, host, p.GetNumber())

			if root := base + "/"; !seen[root] {
				seen[root] = true
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
				buckets[tag] = append(buckets[tag], root, urlDesc(h, p))
			}

			// T3: real paths NSE discovered on this port (http-enum), appended to the base.
			for _, pd := range pathsFromPort(p) {
				if pathCount >= maxDiscoveredPaths {
					break
				}
				pu := base + pd[0]
				if seen[pu] {
					continue
				}
				seen[pu] = true
				pathCount++
				desc := pd[1]
				if desc == "" {
					desc = "discovered path"
				}
				buckets[tagURLPaths] = append(buckets[tagURLPaths], pu, desc)
			}
		}
	}

	return renderGroups(urlGroupOrder, buckets, "no web services in database",
		func(a carapace.Action) carapace.Action { return a.NoSpace('/') })
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

// urlBase assembles scheme://host[:port] with no trailing path — the default port for the scheme is
// omitted, an IPv6 literal bracketed. A discovered path (which starts with "/") is appended directly.
func urlBase(scheme, host string, port uint32) string {
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
	return scheme + "://" + host
}

// buildURL is urlBase with the root path "/".
func buildURL(scheme, host string, port uint32) string {
	return urlBase(scheme, host, port) + "/"
}

// nsePathRE extracts a discovered path and its label from an http-* NSE script's output line, e.g.
//
//	|   /admin/: Possible admin folder
var nsePathRE = regexp.MustCompile(`(?m)^[\s|_]*(/[^\s:]+)\s*:[ \t]*(.*)$`)

// pathsFromPort collects the (path, label) pairs an http-* script discovered on this port — mainly
// http-enum. Deduplicated by path; a script that lists no paths (http-title, …) simply yields
// nothing, so restricting to http-* Ids plus the path shape avoids false positives.
func pathsFromPort(p *pb.Port) [][2]string {
	var out [][2]string
	seen := make(map[string]bool)
	for _, s := range p.GetScripts() {
		if !strings.HasPrefix(s.GetId(), "http") {
			continue
		}
		for _, m := range nsePathRE.FindAllStringSubmatch(s.GetOutput(), -1) {
			path := m[1]
			if seen[path] {
				continue
			}
			seen[path] = true
			out = append(out, [2]string{path, strings.TrimSpace(m[2])})
		}
	}
	return out
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

	return renderGroups(subnetGroupOrder, buckets, "")
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

//
// [ Domains — parent zones of DB hostnames, agent-promoted ] ------------------------------------
//

const (
	tagDomainRegistered = "registered domains"
	tagDomainSub        = "subdomains"
)

// domainGroupOrder: agent-context relevance groups first, then the apex/registered domains (the
// natural zone to enumerate), then the deeper subdomains.
var domainGroupOrder = agentctx.PromotedOrder(tagDomainRegistered, tagDomainSub)

// Domain completes a domain value — an NSE `dns-*` arg (dns-brute.domain, …), and any
// DNS/recon tool's domain flag later — from the DNS names already in the database. Each known
// hostname contributes its parent zones (every suffix of ≥2 labels, minus the host name itself),
// aggregated by how many known hosts fall under each; zones under the current agent's host are
// promoted via the relevance layer. Cached; the cache key carries the agent id.
//
// The value is intentionally *not* a full host FQDN (that is the target completer's job) — it is the
// zone an operator hands to a brute/transfer tool to enumerate.
func Domain(con *client.Client) carapace.Action {
	return cachedHostCompleter(con, "scan:domains", "domain", nil, "no hosts in database", groupedDomains)
}

// domainInfo aggregates one candidate zone: its name, how many known hosts have a name under it, and
// the closest agent-context relevance of any of those hosts.
type domainInfo struct {
	name  string
	hosts int
	rel   agentctx.Relevance
}

// domainsFromName returns the parent zones of a DNS name: every suffix of ≥2 labels, excluding the
// full name itself (that is a host, not a zone) — except a bare 2-label name, which *is* its own
// registered domain. A bare IP or single-label name yields nothing. So www.corp.example.com →
// {corp.example.com, example.com} and example.com → {example.com}.
func domainsFromName(name string) []string {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if name == "" || net.ParseIP(name) != nil {
		return nil
	}
	labels := strings.Split(name, ".")
	n := len(labels)
	if n < 2 {
		return nil
	}

	max := n - 1 // deeper names: drop at least the leftmost (host) label
	if n == 2 {
		max = 2 // a bare apex is its own registered domain
	}
	out := make([]string, 0, max-1)
	for size := max; size >= 2; size-- { // most-specific zone first, down to the apex
		out = append(out, strings.Join(labels[n-size:], "."))
	}
	return out
}

// collectDomains aggregates the parent zones of every host's hostnames, counting each host once per
// zone and keeping the highest agent-context relevance of any host under it. Sorted by host density
// (desc) then name.
func collectDomains(all []*pb.Host, agentHost *pb.Host) []*domainInfo {
	byName := make(map[string]*domainInfo)
	for _, h := range all {
		rel := agentctx.RelevanceOfHost(h, agentHost)
		counted := make(map[string]bool) // a host counts once per zone, however many names it has there
		for _, hn := range h.GetHostnames() {
			for _, d := range domainsFromName(hn.GetName()) {
				di := byName[d]
				if di == nil {
					di = &domainInfo{name: d}
					byName[d] = di
				}
				if rel > di.rel {
					di.rel = rel
				}
				if !counted[d] {
					counted[d] = true
					di.hosts++
				}
			}
		}
	}

	out := make([]*domainInfo, 0, len(byName))
	for _, di := range byName {
		out = append(out, di)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].hosts != out[j].hosts {
			return out[i].hosts > out[j].hosts
		}
		return out[i].name < out[j].name
	})
	return out
}

// groupedDomains renders the aggregated zones as promoted, described carapace groups: zones under the
// agent's host (then its subnet) lead via the relevance layer, then apex/registered domains, then
// deeper subdomains.
func groupedDomains(all []*pb.Host, agentHost *pb.Host) carapace.Action {
	buckets := make(map[string][]string)
	for _, di := range collectDomains(all, agentHost) {
		buckets[domainTag(di)] = append(buckets[domainTag(di)], di.name, domainDesc(di))
	}

	return renderGroups(domainGroupOrder, buckets, "no domains in database")
}

// domainTag groups a zone: the agent-context relevance group if any, else registered (one dot, an
// apex like example.com) vs a deeper subdomain (a heuristic split — no public-suffix list, so a
// multi-label public suffix like co.uk reads as registered, which is harmless here).
func domainTag(di *domainInfo) string {
	if tag := di.rel.Tag(); tag != "" {
		return tag
	}
	if strings.Count(di.name, ".") == 1 {
		return tagDomainRegistered
	}
	return tagDomainSub
}

// domainDesc describes a zone by how many known hosts fall under it.
func domainDesc(di *domainInfo) string {
	unit := "hosts"
	if di.hosts == 1 {
		unit = "host"
	}
	return strconv.Itoa(di.hosts) + " known " + unit
}
