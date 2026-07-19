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
	hostmerge "github.com/d3c3ptive/aims/host"
	host "github.com/d3c3ptive/aims/host/pb"
)

// This file is the Run-level ingest fold: it assembles the hosts a scan observed into
// the Run's host tree, deduplicating and merging so several scans (or scanners) can
// contribute to the same objects without duplicating or dropping data. The actual
// host-tree merge and identity live in the host domain (host.MergeHost / host.SameHost,
// see host/merge.go) so this path and the gRPC CRUD servers share one implementation;
// the fold here only owns the Run-scoped orchestration. Contract: DEDUP.md.

// AddHosts folds one or more hosts into this Run, deduplicating and merging by natural
// key. It is the bulk entry point behind the import path: the Hosts of a freshly parsed
// scan.Run (e.g. from nmap.FromXML) are folded in one by one, so an import that overlaps
// hosts already in the Run enriches them instead of duplicating.
func (r *Run) AddHosts(hosts ...*host.Host) {
	for _, h := range hosts {
		r.foldHost(h)
	}
}

// foldHost merges src into the Run's existing host set without ever dropping data:
// a matched host is enriched in place (union of evidence), an unmatched host is
// appended. Returns whether the Run's host tree changed.
func (r *Run) foldHost(src *host.Host) (changed bool) {
	if src == nil {
		return false
	}
	for _, dst := range r.Hosts {
		if hostmerge.SameHost(dst, src) {
			return hostmerge.MergeHost(dst, src)
		}
	}
	r.Hosts = append(r.Hosts, src)
	return true
}
