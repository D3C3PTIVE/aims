package host

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
	"gorm.io/gorm"

	pb "github.com/d3c3ptive/aims/host/pb"
)

// IDsMatching resolves a host *filter value* to the subquery selecting the ids of the hosts it
// denotes. It is the host end of the host/subnet scoping axis: the domain servers pass whatever
// host a caller sent on the wire (usually a bare `&pb.Host{Id: …}` or `&pb.Host{Addresses: …}`)
// and get back something db.ScopeByHost can join against, without any domain having to re-spell
// "how do I turn a host filter into host ids".
//
// Resolution is by identity, most-specific first, and only ONE leg ever runs:
//
//   - Id set          → that host alone (the id is the identity, nothing else can add to it).
//   - else Addresses  → every host carrying one of those addresses (via the host_addresses m2m,
//     index-backed by addresses.addr). This is the leg a CLI user hits when
//     they scope by IP without knowing the UUID.
//   - else Hostnames  → every host answering to one of those names.
//
// A nil host, or one carrying none of the three, returns nil — the caller's "no host scoping"
// signal — so a request's Host field can be threaded through unconditionally and an unset one
// simply widens back to every host. Note this is deliberately *identity* resolution, not the
// full SameHost fold: it answers "which stored hosts is the caller pointing at", which is a
// query concern, whereas SameHost answers "are these two records the same host", an ingest one.
//
// TODO(subnet): the second half of this axis — scoping to a CIDR rather than a single host —
// is NOT implemented. Addresses are stored as free text (addresses.addr), so correct containment
// needs either an inet-typed column (Postgres-only, a schema change) or loading every address to
// test it in Go (defeating the point of pushing the scope down to the DB). Byte-aligned-prefix
// LIKE tricks would only cover /8, /16 and /24 and silently mis-answer everything else, which is
// exactly the half-implementation this axis must not ship. Revisit alongside a typed address
// column; until then callers scope one host at a time.
func IDsMatching(query *gorm.DB, h *pb.Host) *gorm.DB {
	if h == nil || query == nil {
		return nil
	}

	newDB := func() *gorm.DB { return query.Session(&gorm.Session{NewDB: true}) }

	if h.GetId() != "" {
		return newDB().Table("hosts").Select("hosts.id").Where("hosts.id = ?", h.GetId())
	}

	var addrs []string
	for _, a := range h.GetAddresses() {
		if a.GetAddr() != "" {
			addrs = append(addrs, a.GetAddr())
		}
	}
	if len(addrs) > 0 {
		return newDB().
			Table("host_addresses").
			Select("host_addresses.host_id").
			Joins("JOIN addresses ON addresses.id = host_addresses.address_id").
			Where("addresses.addr IN ?", addrs)
	}

	var names []string
	for _, hn := range h.GetHostnames() {
		if hn.GetName() != "" {
			names = append(names, hn.GetName())
		}
	}
	if len(names) > 0 {
		return newDB().
			Table("hostnames").
			Select("hostnames.host_id").
			Where("hostnames.name IN ?", names)
	}

	return nil
}
