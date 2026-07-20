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

// This file is the shared "Relevance × Group" classification layer. A context-aware completer keeps
// its own intrinsic groups (locality, category, service scheme, …) and, when an agent context is
// loaded, promotes the candidates related to the agent's host into the shared relevance groups —
// which PromotedOrder floats to the top. Each completer only supplies the domain glue (which host a
// candidate belongs to); the vocabulary, tags and ordering live here so every completer promotes
// identically and the operator learns one spatial convention.

import (
	"net"
	"strings"

	hostpb "github.com/d3c3ptive/aims/host/pb"
)

// Relevance ranks a completion candidate by its relationship to the loaded agent context. Higher is
// closer.
type Relevance int

const (
	Normal    Relevance = iota // no special relationship to the loaded agent
	Nearby                     // on the agent host's subnet
	AgentHost                  // the agent host itself (or an entity attached to it)
)

// Relevance group tags, shared so every completer labels the promoted groups identically. Normal
// has no tag — the completer keeps its own intrinsic group (locality, category, …) for those.
const (
	TagContext = "this agent's host"
	TagNearby  = "agent subnet (nearby)"
)

// Tag is the group tag for a relevance, or "" for Normal (the caller then uses its own intrinsic
// group for that candidate).
func (r Relevance) Tag() string {
	switch r {
	case AgentHost:
		return TagContext
	case Nearby:
		return TagNearby
	default:
		return ""
	}
}

// PromotedOrder prepends the relevance group tags, in their canonical order, to a completer's own
// intrinsic group order — so the agent's host and its subnet always render first, and every
// context-aware completer presents the same spatial convention.
func PromotedOrder(intrinsic ...string) []string {
	return append([]string{TagContext, TagNearby}, intrinsic...)
}

// RelevanceOfHost classifies a host relative to the loaded agent host: Context if it IS the agent
// host, Nearby if it shares a subnet, else Normal. A nil agentHost (no context loaded) is always
// Normal, so callers get the context-free behaviour for free.
func RelevanceOfHost(h, agentHost *hostpb.Host) Relevance {
	if agentHost == nil || h == nil {
		return Normal
	}
	if h.GetId() == agentHost.GetId() {
		return AgentHost
	}
	if hostsSameSubnet(h, agentHost) {
		return Nearby
	}
	return Normal
}

// RelevanceOfHostID classifies an entity that references a host only by id — a credential's HostId,
// a service's host — as Context when that is the agent host, else Normal. Subnet proximity needs
// addresses, which a bare id lacks, so Nearby is never returned here.
func RelevanceOfHostID(hostID string, agentHost *hostpb.Host) Relevance {
	if agentHost == nil || hostID == "" {
		return Normal
	}
	if hostID == agentHost.GetId() {
		return AgentHost
	}
	return Normal
}

// hostsSameSubnet reports whether any address of a shares a subnet with any address of b. Loopback
// addresses are ignored so two hosts each carrying 127.0.0.1 aren't read as neighbours.
func hostsSameSubnet(a, b *hostpb.Host) bool {
	for _, aa := range a.GetAddresses() {
		ipA := net.ParseIP(strings.TrimSpace(aa.GetAddr()))
		if ipA == nil || ipA.IsLoopback() {
			continue
		}
		for _, ba := range b.GetAddresses() {
			ipB := net.ParseIP(strings.TrimSpace(ba.GetAddr()))
			if ipB == nil || ipB.IsLoopback() {
				continue
			}
			if sameSubnet(ipA, ipB) {
				return true
			}
		}
	}
	return false
}

// sameSubnet is a heuristic — the model stores bare addresses with no netmask — so "same subnet"
// assumes the common defaults: a shared /24 for IPv4, a shared /64 for IPv6. Mixed address families
// are never in the same subnet.
func sameSubnet(a, b net.IP) bool {
	if a4, b4 := a.To4(), b.To4(); a4 != nil && b4 != nil {
		return a4[0] == b4[0] && a4[1] == b4[1] && a4[2] == b4[2]
	}
	if a.To4() != nil || b.To4() != nil {
		return false // one v4, one v6
	}
	a16, b16 := a.To16(), b.To16()
	if a16 == nil || b16 == nil {
		return false
	}
	for i := 0; i < 8; i++ { // the first 64 bits
		if a16[i] != b16[i] {
			return false
		}
	}
	return true
}
