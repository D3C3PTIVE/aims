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
	"net"
	"strings"
	"testing"

	"github.com/d3c3ptive/aims/cmd/agentctx"
	credential "github.com/d3c3ptive/aims/credential/pb"
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
		"broadcast-*.interface":   "interface",
		"snmp.interface":          "interface",
		"smtp.port":               "port",
		"port":                    "port",
		"smbpassword":             "secret",
		"mssql.password":          "secret",
		"ssh.passphrase":          "secret",
		"http-enum.url":           "url",
		"spider.uri":              "url",
	}
	for k, want := range cases {
		if got := nseArgValueKind(k); got != want {
			t.Errorf("nseArgValueKind(%q) = %q, want %q", k, got, want)
		}
	}
}

// TestTargetTag pins the agent-context promotion: the agent's own host (by id) and its subnet
// neighbours are promoted (via the shared agentctx classifier); every other host — and every host
// when no context is loaded — falls into its locality group.
func TestTargetTag(t *testing.T) {
	host := func(id string, addrs ...string) *pb.Host {
		h := &pb.Host{Id: id}
		for _, a := range addrs {
			h.Addresses = append(h.Addresses, &network.Address{Addr: a})
		}
		return h
	}
	agent := host("agent-1", "10.0.0.10")

	cases := []struct {
		name  string
		h     *pb.Host
		agent *pb.Host
		want  string
	}{
		{"agent-host-by-id", host("agent-1", "10.0.0.10"), agent, agentctx.TagContext},
		{"same-subnet", host("h2", "10.0.0.55"), agent, agentctx.TagNearby},
		{"other-private-subnet", host("h3", "192.168.5.5"), agent, tagPrivate},
		{"routable", host("h4", "8.8.8.8"), agent, tagRoutable},
		{"no-context-falls-to-locality", host("h5", "10.0.0.55"), nil, tagPrivate},
		{"no-address", host("h6"), agent, tagNoAddr},
	}
	for _, c := range cases {
		if got := targetTag(c.h, c.agent); got != c.want {
			t.Errorf("%s: targetTag = %q, want %q", c.name, got, c.want)
		}
	}
}

// TestInterfaceLabel pins the interface description: addresses joined with the mask stripped, a
// loopback marker, and the empty-address fallbacks.
func TestInterfaceLabel(t *testing.T) {
	ipnet := func(cidr string) *net.IPNet {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			t.Fatalf("bad test CIDR %q: %v", cidr, err)
		}
		n.IP = net.ParseIP(strings.SplitN(cidr, "/", 2)[0]) // keep the host IP, not the network addr
		return n
	}

	cases := []struct {
		name     string
		loopback bool
		addrs    []net.Addr
		want     string
	}{
		{"v4+v6", false, []net.Addr{ipnet("192.168.1.10/24"), ipnet("fe80::1/64")}, "192.168.1.10, fe80::1"},
		{"loopback", true, []net.Addr{ipnet("127.0.0.1/8")}, "127.0.0.1 (loopback)"},
		{"no-addr", false, nil, "no address"},
		{"loopback-no-addr", true, nil, "(loopback)"},
	}
	for _, c := range cases {
		if got := interfaceLabel(c.loopback, c.addrs); got != c.want {
			t.Errorf("%s: interfaceLabel = %q, want %q", c.name, got, c.want)
		}
	}
}

// TestCollectOpenPorts pins the port aggregation and its agent-context ranking: only open ports
// count, each number is deduped across hosts with a host count, and a port takes the highest
// relevance of any host exposing it (agent host › subnet neighbour › distant).
func TestCollectOpenPorts(t *testing.T) {
	port := func(num uint32, state, svc string) *pb.Port {
		return &pb.Port{Number: num, Protocol: "tcp", State: &pb.State{State: state}, Service: &network.Service{Name: svc}}
	}
	host := func(id, addr string, ports ...*pb.Port) *pb.Host {
		h := &pb.Host{Id: id}
		if addr != "" {
			h.Addresses = append(h.Addresses, &network.Address{Addr: addr})
		}
		h.Ports = ports
		return h
	}

	agent := host("agent", "10.0.0.10", port(22, "open", "ssh"), port(80, "open", "http"))
	all := []*pb.Host{
		agent,
		host("b", "10.0.0.50", port(22, "open", "ssh"), port(443, "open", "https")), // same /24
		host("c", "8.8.8.8", port(22, "open", "ssh"), port(3389, "open", "rdp"),
			port(9, "closed", "")), // distant, plus a closed port that must be dropped
	}

	byNum := map[uint32]*portInfo{}
	got := collectOpenPorts(all, agent)
	for _, pi := range got {
		byNum[pi.number] = pi
	}

	if _, ok := byNum[9]; ok {
		t.Error("closed port 9 must be excluded")
	}
	if pi := byNum[22]; pi == nil || pi.rel != agentctx.AgentHost || pi.hosts != 3 || pi.service != "ssh" {
		t.Errorf("port 22: got %+v, want rel=AgentHost hosts=3 service=ssh", pi)
	}
	if pi := byNum[80]; pi == nil || pi.rel != agentctx.AgentHost || pi.hosts != 1 {
		t.Errorf("port 80: got %+v, want rel=AgentHost hosts=1", pi)
	}
	if pi := byNum[443]; pi == nil || pi.rel != agentctx.Nearby || pi.hosts != 1 {
		t.Errorf("port 443: got %+v, want rel=Nearby hosts=1", pi)
	}
	if pi := byNum[3389]; pi == nil || pi.rel != agentctx.Normal {
		t.Errorf("port 3389: got %+v, want rel=Normal", pi)
	}
	for i := 1; i < len(got); i++ {
		if got[i-1].number > got[i].number {
			t.Errorf("collectOpenPorts not sorted by number: %v", got)
			break
		}
	}
}

// TestSecretDesc: a secret is described by who owns it (username @ realm) and its type — never by
// the secret value itself.
func TestSecretDesc(t *testing.T) {
	cases := []struct {
		name string
		core *credential.Core
		want string
	}{
		{
			"user-realm-hash",
			&credential.Core{
				Public:  &credential.Public{Username: "administrator"},
				Realm:   &credential.Realm{Value: "CORP"},
				Private: &credential.Private{Type: credential.PrivateType_NTLMHash, Data: "aad3b..."},
			},
			"administrator @ CORP · NTLM hash",
		},
		{
			"user-password",
			&credential.Core{
				Public:  &credential.Public{Username: "root"},
				Private: &credential.Private{Type: credential.PrivateType_Password, Data: "hunter2"},
			},
			"root · password",
		},
		{
			"no-user-jwt",
			&credential.Core{Private: &credential.Private{Type: credential.PrivateType_JWT, Data: "ey..."}},
			"JWT",
		},
	}
	for _, c := range cases {
		if got := secretDesc(c.core); got != c.want {
			t.Errorf("%s: secretDesc = %q, want %q", c.name, got, c.want)
		}
	}
}

// TestSecretTypeGroup: each private type lands in its group, unknown types default to passwords.
func TestSecretTypeGroup(t *testing.T) {
	cases := map[credential.PrivateType]string{
		credential.PrivateType_Password:         "passwords",
		credential.PrivateType_NTLMHash:         "NTLM hashes",
		credential.PrivateType_PostgresMD5:      "PostgreSQL hashes",
		credential.PrivateType_ReplayableHash:   "replayable hashes",
		credential.PrivateType_NonReplayableHash: "non-replayable hashes",
		credential.PrivateType_Key:              "keys",
		credential.PrivateType_JWT:              "JWTs",
	}
	for typ, want := range cases {
		if got := secretTypeGroup(typ); got != want {
			t.Errorf("secretTypeGroup(%v) = %q, want %q", typ, got, want)
		}
	}
}

// TestSchemeOf pins scheme detection: the ssl/tls tunnel or an https-ish service name wins, then
// the well-known TLS ports, else http.
func TestSchemeOf(t *testing.T) {
	port := func(num uint32, name, tunnel string) *pb.Port {
		return &pb.Port{Number: num, Service: &network.Service{Name: name, Tunnel: tunnel}}
	}
	cases := []struct {
		name string
		port *pb.Port
		want string
	}{
		{"named-https-ssl", port(443, "https", "ssl"), "https"},
		{"named-http", port(80, "http", ""), "http"},
		{"http-proxy-8080", port(8080, "http-proxy", ""), "http"},
		{"ssl-http-tunnel", port(8443, "ssl/http", "ssl"), "https"},
		{"tunnel-overrides", port(8080, "http", "ssl"), "https"},
		{"port-443-no-service", port(443, "", ""), "https"},
		{"port-80-no-service", port(80, "", ""), "http"},
	}
	for _, c := range cases {
		if got := schemeOf(c.port); got != c.want {
			t.Errorf("%s: schemeOf = %q, want %q", c.name, got, c.want)
		}
	}
}

// TestBuildURL pins URL assembly: the scheme's default port is omitted, a non-default kept, an IPv6
// literal bracketed.
func TestBuildURL(t *testing.T) {
	cases := []struct {
		scheme, host string
		port         uint32
		want         string
	}{
		{"http", "web01", 80, "http://web01/"},
		{"https", "web01", 443, "https://web01/"},
		{"http", "web01", 8080, "http://web01:8080/"},
		{"https", "10.0.0.5", 8443, "https://10.0.0.5:8443/"},
		{"http", "fe80::1", 80, "http://[fe80::1]/"},
		{"https", "fe80::1", 8443, "https://[fe80::1]:8443/"},
	}
	for _, c := range cases {
		if got := buildURL(c.scheme, c.host, c.port); got != c.want {
			t.Errorf("buildURL(%q,%q,%d) = %q, want %q", c.scheme, c.host, c.port, got, c.want)
		}
	}
}

// TestUrlHost pins host selection: the service vhost wins, then a host hostname, then an address.
func TestUrlHost(t *testing.T) {
	mkHost := func(hostnames, addrs []string) *pb.Host {
		h := &pb.Host{}
		for _, n := range hostnames {
			h.Hostnames = append(h.Hostnames, &pb.Hostname{Name: n})
		}
		for _, a := range addrs {
			h.Addresses = append(h.Addresses, &network.Address{Addr: a})
		}
		return h
	}
	svcPort := func(hostname string) *pb.Port {
		return &pb.Port{Service: &network.Service{Hostname: hostname}}
	}

	if got := urlHost(mkHost([]string{"web01"}, []string{"10.0.0.5"}), svcPort("vhost.example.com")); got != "vhost.example.com" {
		t.Errorf("service vhost should win, got %q", got)
	}
	if got := urlHost(mkHost([]string{"web01"}, []string{"10.0.0.5"}), svcPort("")); got != "web01" {
		t.Errorf("host hostname fallback, got %q", got)
	}
	if got := urlHost(mkHost(nil, []string{"10.0.0.5"}), svcPort("")); got != "10.0.0.5" {
		t.Errorf("address fallback, got %q", got)
	}
}

// TestPortDesc: service (or protocol, or "open") plus a correctly pluralised host count.
func TestPortDesc(t *testing.T) {
	cases := []struct {
		pi   *portInfo
		want string
	}{
		{&portInfo{service: "ssh", proto: "tcp", hosts: 3}, "ssh · 3 hosts"},
		{&portInfo{proto: "tcp", hosts: 1}, "tcp · 1 host"},
		{&portInfo{hosts: 2}, "open · 2 hosts"},
	}
	for _, c := range cases {
		if got := portDesc(c.pi); got != c.want {
			t.Errorf("portDesc(%+v) = %q, want %q", c.pi, got, c.want)
		}
	}
}

// TestCollectSubnets pins the clustering + agent seeding: hosts group into /24s, loopback is
// dropped, the agent's own subnet is marked (host-count includes the agent), and the last-hop
// gateway seeds a subnet marked agent with no known hosts. Sorted by density desc.
func TestCollectSubnets(t *testing.T) {
	host := func(id string, addrs ...string) *pb.Host {
		h := &pb.Host{Id: id}
		for _, a := range addrs {
			h.Addresses = append(h.Addresses, &network.Address{Addr: a})
		}
		return h
	}
	agent := host("agent", "10.0.0.10")
	agent.Trace = &network.Trace{Hops: []*network.Hop{{IPAddr: "10.0.5.1"}, {IPAddr: "10.0.0.10"}}}

	all := []*pb.Host{
		agent,
		host("b", "10.0.0.20"), host("c", "10.0.0.30"), host("d", "10.0.0.40"),
		host("e", "192.168.1.5"), host("f", "192.168.1.6"),
		host("g", "8.8.8.8"),
		host("lo", "127.0.0.1"), // loopback → dropped
	}

	byCidr := map[string]*subnetInfo{}
	subs := collectSubnets(all, agent)
	for _, si := range subs {
		byCidr[si.cidr] = si
	}

	if si := byCidr["10.0.0.0/24"]; si == nil || !si.isAgent || si.hosts != 4 {
		t.Errorf("10.0.0.0/24: got %+v, want isAgent hosts=4", si)
	}
	if si := byCidr["10.0.5.0/24"]; si == nil || !si.isAgent || si.hosts != 0 || si.gateway != "10.0.5.1" {
		t.Errorf("10.0.5.0/24 (gateway seed): got %+v, want isAgent hosts=0 gateway=10.0.5.1", si)
	}
	if si := byCidr["192.168.1.0/24"]; si == nil || si.isAgent || si.hosts != 2 || si.locality != "private" {
		t.Errorf("192.168.1.0/24: got %+v, want private hosts=2 not-agent", si)
	}
	if si := byCidr["8.8.8.0/24"]; si == nil || si.locality != "routable" || si.hosts != 1 {
		t.Errorf("8.8.8.0/24: got %+v, want routable hosts=1", si)
	}
	if _, ok := byCidr["127.0.0.0/24"]; ok {
		t.Error("loopback subnet must be excluded")
	}
	for i := 1; i < len(subs); i++ {
		if subs[i-1].hosts < subs[i].hosts {
			t.Errorf("collectSubnets not sorted by density desc: %v", subs)
			break
		}
	}
}

// TestSubnetTag: agent subnets win, routable is always last-group, private splits on the density
// threshold.
func TestSubnetTag(t *testing.T) {
	cases := []struct {
		si   *subnetInfo
		want string
	}{
		{&subnetInfo{isAgent: true, locality: "private", hosts: 4}, tagSubnetAgent},
		{&subnetInfo{isAgent: true, locality: "routable", hosts: 0}, tagSubnetAgent},
		{&subnetInfo{locality: "private", hosts: 5}, tagSubnetDense},
		{&subnetInfo{locality: "private", hosts: 4}, tagSubnetDense},
		{&subnetInfo{locality: "private", hosts: 3}, tagSubnetPrivate},
		{&subnetInfo{locality: "routable", hosts: 10}, tagSubnetRoutable},
	}
	for _, c := range cases {
		if got := subnetTag(c.si); got != c.want {
			t.Errorf("subnetTag(%+v) = %q, want %q", c.si, got, c.want)
		}
	}
}

// TestSubnetDesc: gateway annotation, host count (or "sweep to discover"), public and IPv6 markers.
func TestSubnetDesc(t *testing.T) {
	cases := []struct {
		si   *subnetInfo
		want string
	}{
		{&subnetInfo{hosts: 12}, "12 hosts"},
		{&subnetInfo{hosts: 1}, "1 host"},
		{&subnetInfo{hosts: 0, isAgent: true, gateway: "10.0.5.1"}, "gateway 10.0.5.1 · sweep to discover"},
		{&subnetInfo{hosts: 2, locality: "routable"}, "2 hosts · public"},
		{&subnetInfo{hosts: 4, v6: true}, "4 hosts · IPv6"},
	}
	for _, c := range cases {
		if got := subnetDesc(c.si); got != c.want {
			t.Errorf("subnetDesc(%+v) = %q, want %q", c.si, got, c.want)
		}
	}
}

// TestLastGateway: the second-to-last traceroute hop, or "" when there aren't two hops.
func TestLastGateway(t *testing.T) {
	mk := func(hops ...string) *pb.Host {
		h := &pb.Host{}
		if len(hops) > 0 {
			tr := &network.Trace{}
			for _, ip := range hops {
				tr.Hops = append(tr.Hops, &network.Hop{IPAddr: ip})
			}
			h.Trace = tr
		}
		return h
	}
	if got := lastGateway(mk("10.0.5.1", "10.0.0.10")); got != "10.0.5.1" {
		t.Errorf("two hops: got %q, want 10.0.5.1", got)
	}
	if got := lastGateway(mk("10.0.0.10")); got != "" {
		t.Errorf("single hop: got %q, want empty", got)
	}
	if got := lastGateway(mk()); got != "" {
		t.Errorf("no trace: got %q, want empty", got)
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
