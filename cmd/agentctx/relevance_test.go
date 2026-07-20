package agentctx

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
	"testing"

	hostpb "github.com/d3c3ptive/aims/host/pb"
	network "github.com/d3c3ptive/aims/network/pb"
)

// TestSameSubnet pins the netmask-free heuristic: shared /24 for IPv4, shared /64 for IPv6, and
// mixed families never in the same subnet.
func TestSameSubnet(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"10.0.0.5", "10.0.0.9", true},
		{"10.0.0.5", "10.0.1.9", false},
		{"192.168.1.1", "192.168.1.254", true},
		{"192.168.1.1", "192.168.2.1", false},
		{"fe80::1", "fe80::abcd", true},               // same /64
		{"2001:db8:0:1::1", "2001:db8:0:1::2", true},  // same /64
		{"2001:db8:0:1::1", "2001:db8:0:2::1", false}, // differ in the 8th byte
		{"10.0.0.1", "::1", false},                    // mixed families
	}
	for _, c := range cases {
		if got := sameSubnet(net.ParseIP(c.a), net.ParseIP(c.b)); got != c.want {
			t.Errorf("sameSubnet(%s, %s) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func host(id string, addrs ...string) *hostpb.Host {
	h := &hostpb.Host{Id: id}
	for _, a := range addrs {
		h.Addresses = append(h.Addresses, &network.Address{Addr: a})
	}
	return h
}

// TestRelevanceOfHost pins the host classifier: the agent host itself is Context, a subnet neighbour
// is Nearby, anything else (and every host with no context) is Normal; loopback never bridges hosts.
func TestRelevanceOfHost(t *testing.T) {
	agent := host("agent-1", "10.0.0.10")
	cases := []struct {
		name     string
		h, agent *hostpb.Host
		want     Relevance
	}{
		{"self-by-id", host("agent-1", "10.0.0.10"), agent, AgentHost},
		{"same-subnet", host("h2", "10.0.0.55"), agent, Nearby},
		{"other-subnet", host("h3", "192.168.5.5"), agent, Normal},
		{"no-context", host("h4", "10.0.0.55"), nil, Normal},
		{"loopback-not-nearby", host("h5", "127.0.0.1"), host("agent-1b", "127.0.0.1"), Normal},
	}
	for _, c := range cases {
		if got := RelevanceOfHost(c.h, c.agent); got != c.want {
			t.Errorf("%s: RelevanceOfHost = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestRelevanceOfHostID pins the id-only classifier (credentials, services): Context when the id is
// the agent host's, else Normal — never Nearby, since an id carries no address.
func TestRelevanceOfHostID(t *testing.T) {
	agent := host("agent-1", "10.0.0.10")
	if got := RelevanceOfHostID("agent-1", agent); got != AgentHost {
		t.Errorf("matching id: got %v, want AgentHost", got)
	}
	if got := RelevanceOfHostID("other", agent); got != Normal {
		t.Errorf("non-matching id: got %v, want Normal", got)
	}
	if got := RelevanceOfHostID("agent-1", nil); got != Normal {
		t.Errorf("no context: got %v, want Normal", got)
	}
	if got := RelevanceOfHostID("", agent); got != Normal {
		t.Errorf("empty id: got %v, want Normal", got)
	}
}

// TestPromotedOrder: relevance groups lead, the completer's own groups follow in order.
func TestPromotedOrder(t *testing.T) {
	got := PromotedOrder("a", "b")
	want := []string{TagContext, TagNearby, "a", "b"}
	if len(got) != len(want) {
		t.Fatalf("PromotedOrder len = %d, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("PromotedOrder[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
