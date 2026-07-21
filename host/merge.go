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
	"crypto/sha256"
	"encoding/hex"
	"strings"

	host "github.com/d3c3ptive/aims/host/pb"
	"github.com/d3c3ptive/aims/internal/util"
	network "github.com/d3c3ptive/aims/network/pb"
	"github.com/d3c3ptive/aims/provenance"
	"github.com/d3c3ptive/aims/scan/pb/nmap"
)

// This file is the canonical, non-destructive host-tree merge: the primitive that
// lets several scans (or scanners) contribute to the same host/port/service objects
// without either duplicating them or dropping data. It is shared by every ingest
// path — the scan-import fold (scan.Run.AddHosts / AddResult) and the host/scan gRPC
// CRUD servers — so identity and merge semantics never diverge between them.
//
// It is the value-typed (`*pb.Host`) identity+merge primitive, and it follows the
// contract in .claude/DEDUP.md:
//
//   - match ≠ merge: a matched record is merged field-by-field, never discarded
//     whole (a match-then-drop filter would lose data) — .claude/DEDUP.md §1.
//   - keyed-first, always scoped: a port is only matched within its matched host,
//     a script within its matched port — .claude/DEDUP.md §2/§3.
//   - the no-false-merge asymmetry: when identity is uncertain we split (keep both)
//     rather than risk collapsing two distinct objects — .claude/DEDUP.md §0.
//   - field classes: Identity is set once; scalars are fill-only (a known value is
//     never clobbered by an empty one); collections are unioned; contradicting
//     Observations are kept, not overwritten — .claude/DEDUP.md §4/§5.
//
// Every merge returns whether it changed the destination, so callers can skip no-op
// writes (idempotent re-import issues zero updates).

//
// Identity — keyed, PB-level --------
//

// SameHost reports whether two in-memory hosts denote the same machine, using natural
// keys only (.claude/DEDUP.md §2, keyed-first): MAC is definitive, otherwise a shared address
// is decisive. A shared hostname alone is deliberately NOT enough to merge — virtual
// hosts share names — so per the no-false-merge asymmetry we would rather split than
// wrongly collapse two hosts.
func SameHost(a, b *host.Host) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.MAC != "" && b.MAC != "" {
		return strings.EqualFold(a.MAC, b.MAC)
	}
	return sharesAddress(a, b)
}

func sharesAddress(a, b *host.Host) bool {
	for _, aa := range a.Addresses {
		if aa == nil || aa.Addr == "" {
			continue
		}
		for _, bb := range b.Addresses {
			if bb != nil && aa.Addr == bb.Addr {
				return true
			}
		}
	}
	return false
}

// SamePort keys a port by (protocol, number) — its natural key within a host.
func SamePort(a, b *host.Port) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Number == b.Number && strings.EqualFold(a.Protocol, b.Protocol)
}

//
// Host merge -----------------------------------------------------------------
//

// MergeHost folds src into dst in place, by field class, without losing data. It
// assumes the two already match (SameHost); callers do the matching and scoping.
func MergeHost(dst, src *host.Host) (changed bool) {
	if dst == nil || src == nil {
		return false
	}

	// Fill-only scalars: a known value is never clobbered by an empty one.
	changed = util.Fill(&dst.MAC, src.MAC) || changed
	changed = util.Fill(&dst.Comm, src.Comm) || changed
	changed = util.Fill(&dst.OSName, src.OSName) || changed
	changed = util.Fill(&dst.OSFlavor, src.OSFlavor) || changed
	changed = util.Fill(&dst.OSSp, src.OSSp) || changed
	changed = util.Fill(&dst.OSLang, src.OSLang) || changed
	changed = util.Fill(&dst.OSFamily, src.OSFamily) || changed
	changed = util.Fill(&dst.Arch, src.Arch) || changed
	changed = util.Fill(&dst.Purpose, src.Purpose) || changed
	changed = util.Fill(&dst.Info, src.Info) || changed
	changed = util.Fill(&dst.Comment, src.Comment) || changed

	// First-wins scan window: keep the earliest observed start time.
	if src.StartTime != 0 && (dst.StartTime == 0 || src.StartTime < dst.StartTime) {
		dst.StartTime = src.StartTime
		changed = true
	}

	// belongs_to messages: fill-only (deeper OSMatch-rank merge is future work).
	if dst.OS == nil && src.OS != nil {
		dst.OS = src.OS
		changed = true
	}
	// Host up/down status is an Observation: fill if empty, but never clobber an
	// existing observation with a conflicting one. True latest-wins needs a
	// per-observation timestamp the proto lacks today (.claude/DEDUP.md §5, gap C1).
	if dst.Status == nil && src.Status != nil {
		dst.Status = src.Status
		changed = true
	}
	if dst.Distance == nil && src.Distance != nil {
		dst.Distance = src.Distance
		changed = true
	}

	// Unioned collections.
	changed = mergeAddresses(dst, src) || changed
	changed = mergeHostnames(dst, src) || changed
	changed = mergeExtraPorts(dst, src) || changed
	dst.HostScripts, changed = mergeScripts(dst.HostScripts, src.HostScripts, changed)
	changed = mergePorts(dst, src) || changed

	// Provenance is a unioned collection: every tool that contributed this host accumulates,
	// so a second scanner enriching a known host adds its Source rather than dropping the
	// first's (the whole point of per-tool scoping — provenance survives the merge).
	if merged, grew := provenance.MergeSources(dst.Sources, src.Sources); grew {
		dst.Sources = merged
		changed = true
	}

	return changed
}

func mergeAddresses(dst, src *host.Host) (changed bool) {
	index := make(map[string]*network.Address, len(dst.Addresses))
	for _, a := range dst.Addresses {
		if a != nil {
			index[a.Addr] = a
		}
	}
	for _, a := range src.Addresses {
		if a == nil || a.Addr == "" {
			continue
		}
		if existing := index[a.Addr]; existing != nil {
			// Same address re-reported: union its provenance rather than dropping the
			// new contributor.
			if merged, grew := provenance.MergeSources(existing.Sources, a.Sources); grew {
				existing.Sources = merged
				changed = true
			}
			continue
		}
		dst.Addresses = append(dst.Addresses, a)
		index[a.Addr] = a
		changed = true
	}
	return changed
}

func mergeHostnames(dst, src *host.Host) (changed bool) {
	seen := make(map[string]bool, len(dst.Hostnames))
	for _, h := range dst.Hostnames {
		if h != nil {
			seen[h.Name] = true
		}
	}
	for _, h := range src.Hostnames {
		if h == nil || h.Name == "" || seen[h.Name] {
			continue
		}
		dst.Hostnames = append(dst.Hostnames, h)
		seen[h.Name] = true
		changed = true
	}
	return changed
}

// mergeExtraPorts unions the "summarize-the-boring" collapsed-port buckets by state.
// Each bucket is a distinct observation of a state class (filtered/closed/…); we keep
// one per state rather than summing counts across scans (a naive sum would double-count
// on re-import, violating idempotence).
func mergeExtraPorts(dst, src *host.Host) (changed bool) {
	seen := make(map[string]bool, len(dst.ExtraPorts))
	for _, e := range dst.ExtraPorts {
		if e != nil {
			seen[e.State] = true
		}
	}
	for _, e := range src.ExtraPorts {
		if e == nil || seen[e.State] {
			continue
		}
		dst.ExtraPorts = append(dst.ExtraPorts, e)
		seen[e.State] = true
		changed = true
	}
	return changed
}

//
// Port / Service merge -------------------------------------------------------
//

// mergePorts is the scoped recursion: each src port is matched only against dst's
// ports (same host), then merged or appended (.claude/DEDUP.md §3).
func mergePorts(dst, src *host.Host) (changed bool) {
	for _, sp := range src.Ports {
		if sp == nil {
			continue
		}
		var matched *host.Port
		for _, dp := range dst.Ports {
			if SamePort(dp, sp) {
				matched = dp
				break
			}
		}
		if matched == nil {
			dst.Ports = append(dst.Ports, sp)
			changed = true
			continue
		}
		changed = mergePortInto(matched, sp) || changed
	}
	return changed
}

func mergePortInto(dst, src *host.Port) (changed bool) {
	if dst == nil || src == nil {
		return false
	}

	changed = util.Fill(&dst.Owner, src.Owner) || changed

	// Service: fill-only field merge; adopt wholesale if absent.
	if dst.Service == nil && src.Service != nil {
		dst.Service = src.Service
		changed = true
	} else if dst.Service != nil && src.Service != nil {
		changed = mergeServiceInto(dst.Service, src.Service) || changed
	}

	// Port state is an Observation. Fill if empty; if both are present and differ,
	// keep the existing one — do not clobber (.claude/DEDUP.md §5). Retaining full state
	// history needs the per-observation-timestamp proto change (gap C1); until then
	// the non-destructive choice is to preserve the first observation.
	if dst.State == nil && src.State != nil {
		dst.State = src.State
		changed = true
	}

	// Reasons and scripts are append-only observation sets.
	changed = mergeReasons(dst, src) || changed
	dst.Scripts, changed = mergeScripts(dst.Scripts, src.Scripts, changed)

	// Provenance union: two tools may each contribute a different port to the same host, so
	// provenance is tracked per port, not only at the host level.
	if merged, grew := provenance.MergeSources(dst.Sources, src.Sources); grew {
		dst.Sources = merged
		changed = true
	}

	return changed
}

func mergeServiceInto(dst, src *network.Service) (changed bool) {
	if dst == nil || src == nil {
		return false
	}
	// All fill-only: one scan may leave Product/Version blank that another fills in.
	// A genuine conflict (two different products on one port) is rare and keeps the
	// existing value rather than clobbering — surfacing it is a future enhancement.
	changed = util.Fill(&dst.Name, src.Name) || changed
	changed = util.Fill(&dst.Product, src.Product) || changed
	changed = util.Fill(&dst.Version, src.Version) || changed
	changed = util.Fill(&dst.ExtraInfo, src.ExtraInfo) || changed
	changed = util.Fill(&dst.Method, src.Method) || changed
	changed = util.Fill(&dst.DeviceType, src.DeviceType) || changed
	changed = util.Fill(&dst.Hostname, src.Hostname) || changed
	changed = util.Fill(&dst.OSType, src.OSType) || changed
	changed = util.Fill(&dst.RPCNum, src.RPCNum) || changed
	changed = util.Fill(&dst.ServiceFP, src.ServiceFP) || changed
	changed = util.Fill(&dst.Tunnel, src.Tunnel) || changed
	changed = util.Fill(&dst.LowVersion, src.LowVersion) || changed
	changed = util.Fill(&dst.HighVersion, src.HighVersion) || changed

	// Provenance union: a service reported by several tools accrues each tool's Source.
	if merged, grew := provenance.MergeSources(dst.Sources, src.Sources); grew {
		dst.Sources = merged
		changed = true
	}

	return changed
}

func mergeReasons(dst, src *host.Port) (changed bool) {
	seen := make(map[string]bool, len(dst.Reasons))
	for _, r := range dst.Reasons {
		if r != nil {
			seen[r.Reason] = true
		}
	}
	for _, r := range src.Reasons {
		if r == nil || seen[r.Reason] {
			continue
		}
		dst.Reasons = append(dst.Reasons, r)
		seen[r.Reason] = true
		changed = true
	}
	return changed
}

//
// NSE scripts — content-hash identity (.claude/DEDUP.md §6.2) ------------------------
//

// mergeScripts unions two script slices by content identity: two script outputs are
// the same observation iff they carry the same (name, normalized-output) hash. Two
// runs that produced *different* output are two facts, so both are kept; a re-run
// that produced identical output is a no-op. Opaque script content is never
// fuzzy-merged or overwritten.
func mergeScripts(dst, src []*nmap.Script, changed bool) ([]*nmap.Script, bool) {
	if len(src) == 0 {
		return dst, changed
	}
	seen := make(map[string]bool, len(dst))
	for _, s := range dst {
		seen[scriptKey(s)] = true
	}
	for _, s := range src {
		if s == nil {
			continue
		}
		k := scriptKey(s)
		if seen[k] {
			continue
		}
		dst = append(dst, s)
		seen[k] = true
		changed = true
	}
	return dst, changed
}

// scriptKey is the content-hash identity of a script observation. normalize() strips
// only provably-insignificant whitespace so an identical re-scan hashes equal; when
// in doubt a difference is treated as significant (keep both) — .claude/DEDUP.md §6.2.
func scriptKey(s *nmap.Script) string {
	if s == nil {
		return ""
	}
	sum := sha256.Sum256([]byte(s.Name + "\x00" + strings.TrimSpace(s.Output)))
	return hex.EncodeToString(sum[:])
}
