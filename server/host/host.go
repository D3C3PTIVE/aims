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
	"context"
	"errors"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"

	"github.com/d3c3ptive/aims/host"
	"github.com/d3c3ptive/aims/host/pb"
	hosts "github.com/d3c3ptive/aims/host/pb/rpc"
	"github.com/d3c3ptive/aims/internal/db"
	network "github.com/d3c3ptive/aims/network/pb"
	nmap "github.com/d3c3ptive/aims/scan/pb/nmap"
)

type server struct {
	db *gorm.DB
	*hosts.UnimplementedHostsServer
}

// New returns a new database host server, from a given db.
func New(db *gorm.DB) *server {
	return &server{db: db, UnimplementedHostsServer: &hosts.UnimplementedHostsServer{}}
}

// Read reads one or more hosts from the database, with optional filters and elements to preload.
func (s *server) Read(ctx context.Context, req *hosts.ReadHostRequest) (*hosts.ReadHostResponse, error) {
	filts := req.GetFilters()

	// Convert to ORM model
	hst, err := req.GetHost().ToORM(ctx)
	if err != nil {
		return nil, err
	}

	dbHosts := []*pb.HostORM{}

	// Preloads
	filters := WithPreloads(req.GetFilters())
	query := s.db.Where(hst)
	// Per-tool scoping: restrict to hosts contributed by a given tool ("give me only my
	// objects") via the host_sources provenance join. Empty Source is a no-op (all hosts).
	query = db.ScopeBySource(query, "host_sources", "host_id", filts.GetSource())
	database := db.Preload(query, filters)

	// Query. MaxResults==1 keeps the First fast-path (single row, ErrRecordNotFound on miss);
	// any other positive value caps the Find with a LIMIT so a large request no longer silently
	// loads the whole table. MaxResults<=0 means "no cap" (load all).
	switch {
	case filts != nil && filts.MaxResults == 1:
		database = database.First(&dbHosts)
	case filts != nil && filts.MaxResults > 1:
		database = database.Limit(int(filts.MaxResults)).Find(&dbHosts)
	default:
		database = database.Find(&dbHosts)
	}

	hostspb, err := db.ToPBs[*pb.HostORM, pb.Host](ctx, dbHosts)
	if err != nil {
		return nil, err
	}

	// Response
	res := &hosts.ReadHostResponse{Hosts: hostspb}

	// An empty result set is not an error: a MaxResults==1 First that matches no row yields
	// gorm.ErrRecordNotFound, but "no host matched" is a valid empty answer the CLI renders as
	// "No hosts in database." rather than surfacing an error. (The Find path returns no such error.)
	readErr := database.Error
	if errors.Is(readErr, gorm.ErrRecordNotFound) {
		readErr = nil
	}

	return res, readErr
}

// Create inserts hosts that are genuinely new, skipping any whose natural key already exists in
// the database. It is additive and idempotent — re-creating a host already present is a no-op —
// but it never merges: to enrich an existing host with newly-observed evidence, use Upsert.
// Identity uses the shared host.SameHost key (MAC, else a shared address), so this and every
// other ingest path agree on what "the same host" means.
func (s *server) Create(ctx context.Context, req *hosts.CreateHostRequest) (*hosts.CreateHostResponse, error) {
	if len(req.GetHosts()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "no hosts were provided")
	}

	// The whole batch runs in one transaction (P3): a Create that fails on host N must not leave
	// hosts 1..N-1 committed. New(tx) rebinds the ingest helpers to the transaction.
	var created []*pb.Host
	err := s.db.Transaction(func(tx *gorm.DB) error {
		txs := New(tx)
		existing, err := txs.loadCandidateHostsPB(ctx, req.GetHosts())
		if err != nil {
			return err
		}
		for _, h := range req.GetHosts() {
			if h == nil || findSameHost(h, existing) != nil {
				continue
			}
			saved, err := txs.insertHost(ctx, h)
			if err != nil {
				return err
			}
			existing = append(existing, saved) // so later hosts in the batch dedup against it
			created = append(created, saved)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return &hosts.CreateHostResponse{Hosts: created}, nil
}

// Upsert is the non-destructive ingest path (DEDUP.md): each incoming host is matched against the
// database by natural key and, when found, merged field-by-field into the existing record — a
// known value is never clobbered by an empty one, collections are unioned, and contradicting
// observations are kept rather than overwritten (host.MergeHost). An unmatched host is inserted.
// Re-importing an identical scan changes nothing and writes nothing; re-importing an enriched
// scan of a known host adds only the new evidence. This replaces the old match-then-drop, which
// discarded the whole incoming host on a match and so silently lost re-scan enrichment.
func (s *server) Upsert(ctx context.Context, req *hosts.UpsertHostRequest) (*hosts.UpsertHostResponse, error) {
	if len(req.GetHosts()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "no hosts were provided")
	}

	out, err := s.ingest(ctx, req.GetHosts())
	if err != nil {
		return nil, err
	}

	return &hosts.UpsertHostResponse{Hosts: out}, nil
}

// IngestHosts folds the given hosts into the shared host table non-destructively — the same
// additive, idempotent merge Upsert performs (host.MergeHost / host.SameHost) — and returns the
// persisted rows, each carrying its DB-assigned ID. It is the entry point other domains use to
// unify the hosts they observed with the global host records: a scan Run, for instance, folds its
// hosts through here and then links the returned shared rows via its own join table, rather than
// inserting a private copy of every host per run. The passed *gorm.DB may be a transaction, so the
// caller's own writes and this fold commit or roll back together.
func IngestHosts(ctx context.Context, gdb *gorm.DB, in []*pb.Host) ([]*pb.Host, error) {
	return New(gdb).ingest(ctx, in)
}

// LoadHostCandidates loads the stored hosts that could match any host in `in` (the merge
// candidates), as PB values with the full tree the merge reads — the same narrowed candidate set
// IngestHosts loads internally (loadCandidateHostsPB). It exists so a caller folding SEVERAL
// batches against ONE shared candidate set (scan Create/Upsert folding many runs' hosts) can load
// the union of all batches ONCE up front, then thread the set through FoldHosts per batch — instead
// of paying loadCandidateHostsPB's DB reload once per batch (the cross-run ingest amplifier). The
// passed *gorm.DB may be a transaction. Over-loading is safe: FoldHosts still runs the exact
// SameHost matcher against the set.
func LoadHostCandidates(ctx context.Context, gdb *gorm.DB, in []*pb.Host) ([]*pb.Host, error) {
	return New(gdb).loadCandidateHostsPB(ctx, in)
}

// FoldHosts folds `in` into the shared host table against the caller-maintained candidate set
// *candidates, persisting via gdb (which may be a transaction). It matches/merges/inserts exactly
// as IngestHosts does — identical host.SameHost / host.MergeHost semantics — but reuses the passed
// candidate set instead of reloading it, and appends every row it persists (a brand-new host, or an
// already-present one it enriched) back into *candidates, so a later FoldHosts against the same set
// unifies with it in memory. This is what lets a batch of runs unify their shared hosts across the
// batch (cross-run host-row unification) without reloading the growing host tree per run. Returns
// the persisted rows for THIS batch (with DB-assigned IDs), for the caller to link via its own join.
//
// FoldHosts does NOT open a transaction of its own (unlike IngestHosts): it runs inside the caller's
// gdb so the caller controls the transaction boundary — e.g. scan.persistRun folds within the run's
// transaction, keeping each run atomic and independent.
func FoldHosts(ctx context.Context, gdb *gorm.DB, candidates *[]*pb.Host, in []*pb.Host) ([]*pb.Host, error) {
	return New(gdb).foldHosts(ctx, candidates, in)
}

// ingest is the shared body of Upsert and IngestHosts: match each incoming host against the DB by
// natural key, merge-in-place when found (persisting only the new evidence), insert when not, and
// return the persisted rows with their DB-assigned IDs. Hosts later in the batch dedup against the
// ones already ingested, so a batch that repeats a host folds it into one row.
func (s *server) ingest(ctx context.Context, in []*pb.Host) ([]*pb.Host, error) {
	// The whole fold runs in one transaction (P3): the read (loadCandidateHostsPB), the in-memory
	// match, and every insert/merge write commit or roll back together, so a batch that fails on
	// host N never leaves 1..N-1 committed. New(tx) rebinds the helpers to the transaction; when the
	// caller already passed a transaction (scan.persistRun via IngestHosts), this nests as a
	// savepoint under it, exactly as saveMergedHost already does. It also narrows the concurrent
	// read-then-write window — though closing it fully still needs the DB unique constraint (P3,
	// blocked on schema/regen).
	var out []*pb.Host
	err := s.db.Transaction(func(tx *gorm.DB) error {
		txs := New(tx)
		existing, err := txs.loadCandidateHostsPB(ctx, in)
		if err != nil {
			return err
		}
		out, err = txs.foldHosts(ctx, &existing, in)
		return err
	})
	if err != nil {
		return nil, err
	}

	return out, nil
}

// foldHosts is the match-merge-insert core of the ingest fold, factored out so it can run either
// against a per-call candidate set (ingest, which loads one inside its transaction) or against a
// caller-maintained set shared across several batches (FoldHosts, for scan Create's cross-run
// unification). It performs NO DB read of its own — the caller supplies (and reuses) *candidates —
// and NO transaction of its own — it writes through s.db, which the caller has bound to the
// transaction it wants. Each incoming host is matched against *candidates by natural key
// (host.SameHost): a match is merged in place (host.MergeHost) and only its new evidence persisted
// (saveMergedHost), a miss is inserted whole (insertHost). Every persisted row — the enriched match
// or the fresh insert — is written back into *candidates so a later host (this batch or a later
// batch sharing the set) unifies against it. Returns the persisted rows for THIS call.
func (s *server) foldHosts(ctx context.Context, candidates *[]*pb.Host, in []*pb.Host) ([]*pb.Host, error) {
	existing := *candidates
	var out []*pb.Host

	for _, h := range in {
		if h == nil {
			continue
		}

		if i := indexSameHost(h, existing); i >= 0 {
			if host.MergeHost(existing[i], h) {
				saved, err := s.saveMergedHost(ctx, existing[i])
				if err != nil {
					return nil, err
				}
				existing[i] = saved // adopt DB-assigned IDs for any newly-merged children
			}
			out = append(out, existing[i])
			continue
		}

		saved, err := s.insertHost(ctx, h)
		if err != nil {
			return nil, err
		}
		existing = append(existing, saved)
		out = append(out, saved)
	}

	*candidates = existing // publish this call's inserts back to the shared set
	return out, nil
}

//
// [ Ingest helpers ] -----------------------------------------------------
//

// loadCandidateHostsPB loads only the stored hosts that could match some host in the incoming
// batch — the merge candidates — with their full tree preloaded, as the PB values host.SameHost /
// host.MergeHost operate on. A stored host is a candidate only if it shares a natural key with an
// incoming one (host.SameHost: a common MAC, else a common address); every other host would be
// loaded, PB-converted, and rejected for nothing. Narrowing the load to the batch is what keeps
// ingest from being O(n^2): the felt 1-host-at-a-time import path (scan/CLI) previously reloaded
// the entire host tree on every call, so importing n hosts loaded ~n^2/2 trees. Now each call
// loads only the handful sharing an address/MAC with its batch.
//
// The returned set is a superset of the true matches (it over-loads a host that merely shares an
// address but has a differing MAC, which SameHost then rejects) — over-loading is safe; the caller
// still runs the exact SameHost matcher against it. First-level associations come from db.Preload's
// clause.Associations; ingestPreloads adds the nested levels the merge reaches into.
func (s *server) loadCandidateHostsPB(ctx context.Context, in []*pb.Host) ([]*pb.Host, error) {
	// Collect the natural-key values present in the batch: MACs (case-folded, mirroring
	// SameHost's EqualFold) and addresses (matched exactly, as sharesAddress does).
	macSet := make(map[string]struct{})
	addrSet := make(map[string]struct{})
	for _, h := range in {
		if h == nil {
			continue
		}
		if h.MAC != "" {
			macSet[strings.ToLower(h.MAC)] = struct{}{}
		}
		for _, a := range h.Addresses {
			if a != nil && a.Addr != "" {
				addrSet[a.Addr] = struct{}{}
			}
		}
	}
	if len(macSet) == 0 && len(addrSet) == 0 {
		return nil, nil // no natural keys in the batch → nothing can match → all inserts
	}

	// Resolve candidate host IDs: those sharing an address (via the host_addresses join table) or
	// a MAC (a scalar column on hosts). Duplicate ids across the two queries collapse in the set.
	idSet := make(map[string]struct{})
	if len(addrSet) > 0 {
		var ids []string
		err := s.db.Table("host_addresses").
			Joins("JOIN addresses ON addresses.id = host_addresses.address_id").
			Where("addresses.addr IN ?", mapKeys(addrSet)).
			Pluck("host_addresses.host_id", &ids).Error
		if err != nil {
			return nil, err
		}
		for _, id := range ids {
			idSet[id] = struct{}{}
		}
	}
	if len(macSet) > 0 {
		var ids []string
		err := s.db.Model(&pb.HostORM{}).
			Where("LOWER(mac) IN ?", mapKeys(macSet)).
			Pluck("id", &ids).Error
		if err != nil {
			return nil, err
		}
		for _, id := range ids {
			idSet[id] = struct{}{}
		}
	}
	if len(idSet) == 0 {
		return nil, nil
	}

	var dbHosts []*pb.HostORM
	if err := db.Preload(s.db.Where("id IN ?", mapKeys(idSet)), ingestPreloads()).Find(&dbHosts).Error; err != nil {
		return nil, err
	}

	return db.ToPBs[*pb.HostORM, pb.Host](ctx, dbHosts)
}

// mapKeys returns the keys of a string-set as a slice, for use as a SQL IN list.
func mapKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// ingestPreloads names the nested associations the host merge reads into; first-level ones are
// already loaded by db.Preload (clause.Associations).
func ingestPreloads() map[string]bool {
	return map[string]bool{
		"OS.PortsUsed":       true,
		"OS.Matches":         true,
		"OS.Fingerprints":    true,
		"ExtraPorts.Reasons": true,
		"Ports.Service":      true,
		"Ports.State":        true,
		"Ports.Scripts":      true,
		"Ports.Reasons":      true,
		"Trace.Hops":         true,
	}
}

// insertHost inserts a brand-new host and returns it with DB-assigned IDs.
func (s *server) insertHost(ctx context.Context, h *pb.Host) (*pb.Host, error) {
	horm, err := h.ToORM(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.db.Create(&horm).Error; err != nil {
		return nil, err
	}
	return ormToPB(ctx, &horm)
}

// saveMergedHost persists a merged host. The merge is purely additive — it fills empty scalars
// and unions new elements into the collections — so persistence mirrors that: the host's scalar
// columns are updated, then only the newly-merged children (those the merge appended, still
// without a database ID) are inserted. Existing child rows are left untouched, so nothing is
// duplicated. A blanket FullSaveAssociations Save cannot be used: the merge works on PB values,
// and the PB→ORM roundtrip drops the ORM-only child foreign key, so GORM would re-insert every
// existing child (primary key present, parent link absent) as a duplicate. The whole save runs in
// one transaction.
//
// Enrichment landing *inside* an already-persisted child is written back too: a port the host
// already had, but which this observation enriched (a new NSE script, a filled Service.Product, a
// newly-seen state reason), has its scalars updated and its own new grandchildren appended — see
// saveMergedPorts. The recursion bottoms out at the port's children (service/state/reason/script
// are leaf scalar rows), which is as deep as MergeHost enriches.
func (s *server) saveMergedHost(ctx context.Context, h *pb.Host) (*pb.Host, error) {
	horm, err := h.ToORM(ctx)
	if err != nil {
		return nil, err
	}

	err = s.db.Transaction(func(tx *gorm.DB) error {
		// Host scalar columns only. GORM auto-saves any associations present on the struct (and
		// Omit(clause.Associations) did not reliably suppress that here), so we save a copy with
		// every association field cleared — leaving nothing for GORM to re-insert.
		scalar := horm
		clearHostAssociations(&scalar)
		if err := tx.Save(&scalar).Error; err != nil {
			return err
		}

		// Associations are appended on a FullSaveAssociations session, so a newly-merged port
		// carries its own service/state/scripts in with it. Every append below anchors on a fresh
		// hostID stub (hostRef): the append sets the association field on the model it is given, so a
		// reused stub would carry earlier appends' children along and the FullSaveAssociations Updates
		// would re-persist (duplicate) them. hostRef mints a clean stub each time.
		sess := tx.Session(&gorm.Session{FullSaveAssociations: true})
		hostRef := func() *pb.HostORM { return &pb.HostORM{Id: horm.Id} }

		// Unioned collections: append only the elements without a DB ID (the newly-merged ones).
		if err := appendNew(sess, hostRef(), "Addresses", horm.Addresses, func(a *network.AddressORM) string { return a.Id }); err != nil {
			return err
		}
		if err := appendNew(sess, hostRef(), "Hostnames", horm.Hostnames, func(h *pb.HostnameORM) string { return h.Id }); err != nil {
			return err
		}
		// Ports need both classes of write: a brand-new port is inserted whole, while a port the
		// host already had is enriched in place (its scalars, service, state, reasons, scripts).
		if err := saveMergedPorts(sess, horm.Id, horm.Ports); err != nil {
			return err
		}
		if err := appendNew(sess, hostRef(), "ExtraPorts", horm.ExtraPorts, func(e *pb.ExtraPortORM) string { return e.Id }); err != nil {
			return err
		}
		if err := appendNew(sess, hostRef(), "HostScripts", horm.HostScripts, func(sc *nmap.ScriptORM) string { return sc.Id }); err != nil {
			return err
		}

		// Fill-only singletons the host previously lacked (merge sets them only when absent).
		if horm.OS != nil && horm.OS.Id == "" {
			if err := appendOne(sess, hostRef(), "OS", horm.OS); err != nil {
				return err
			}
		}
		if horm.Status != nil && horm.Status.Id == "" {
			if err := appendOne(sess, hostRef(), "Status", horm.Status); err != nil {
				return err
			}
		}
		if horm.Distance != nil && horm.Distance.Id == "" {
			if err := appendOne(sess, hostRef(), "Distance", horm.Distance); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return ormToPB(ctx, &horm)
}

// clearHostAssociations nil-outs every association field so a scalar-only Save carries no
// children for GORM to auto-persist.
func clearHostAssociations(h *pb.HostORM) {
	h.Addresses, h.Distance, h.ExtraPorts, h.FS = nil, nil, nil, nil
	h.HostScripts, h.Hostnames, h.ICMPResponse, h.IPIDSequence = nil, nil, nil, nil
	h.OS, h.Ports, h.Processes, h.Smurfs = nil, nil, nil, nil
	h.Status, h.TCPSequence, h.TCPTSSequence = nil, nil, nil
	h.Trace, h.Uptime, h.Users = nil, nil, nil
}

// saveMergedPorts persists a merged host's ports in two classes. A brand-new port (no DB ID) is
// inserted whole via the Ports association, so the FullSaveAssociations session carries its
// service/state/reasons/scripts in with it. A port the host already had (ID set) is enriched in
// place by savePortEnrichment — its own scalars and newly-merged grandchildren — rather than being
// re-appended, which would duplicate it. Existing ports are handled before the new-port append so a
// freshly-inserted port (which gains an ID during the append) is never mistaken for an existing one.
func saveMergedPorts(sess *gorm.DB, hostID string, ports []*pb.PortORM) error {
	var fresh []*pb.PortORM
	for _, p := range ports {
		if p == nil {
			continue
		}
		if p.Id == "" {
			fresh = append(fresh, p)
			continue
		}
		if err := savePortEnrichment(sess, p); err != nil {
			return err
		}
	}
	if len(fresh) == 0 {
		return nil
	}
	return sess.Model(&pb.HostORM{Id: hostID}).Association("Ports").Append(fresh)
}

// savePortEnrichment writes back enrichment that merged into an already-persisted port. Every write
// is additive/fill-only, mirroring mergePortInto: the port's fill-only scalar (Owner) is updated, a
// newly-observed service is created and linked while an existing one has its fill-merged scalars
// written back, a newly-filled state is attached, and new reasons/scripts are appended. Rows that
// already have a DB ID (the port's pre-existing children) are left untouched, so re-saving is
// idempotent and never duplicates.
func savePortEnrichment(sess *gorm.DB, p *pb.PortORM) error {
	// Each association write anchors on its own fresh {Id} stub: an Association.Append sets the
	// association field on the model it is given, so a shared stub would carry earlier appends'
	// children along and the FullSaveAssociations session would re-persist (duplicate) them.
	portRef := func() *pb.PortORM { return &pb.PortORM{Id: p.Id} }

	// Fill-only port scalar. Merge never blanks a value, so only a non-empty Owner is a real write.
	if p.Owner != "" {
		if err := sess.Model(portRef()).Update("owner", p.Owner).Error; err != nil {
			return err
		}
	}

	// Service is belongs_to (the FK lives on the port): a newly-observed service is created and the
	// port's ServiceId is set by the association append; an existing service gets its fill-merged
	// scalars written back by primary key.
	if p.Service != nil {
		if p.Service.Id == "" {
			if err := appendOne(sess, portRef(), "Service", p.Service); err != nil {
				return err
			}
		} else if err := sess.Model(&network.ServiceORM{Id: p.Service.Id}).Updates(p.Service).Error; err != nil {
			return err
		}
	}

	// State is fill-only-when-absent (merge never enriches an existing observation), so only a
	// newly-filled (ID-less) state is ever written.
	if p.State != nil && p.State.Id == "" {
		if err := appendOne(sess, portRef(), "State", p.State); err != nil {
			return err
		}
	}

	// Append-only observation sets: only the newly-merged (ID-less) rows.
	if err := appendNew(sess, portRef(), "Reasons", p.Reasons, func(r *pb.ReasonORM) string { return r.Id }); err != nil {
		return err
	}
	return appendNew(sess, portRef(), "Scripts", p.Scripts, func(sc *nmap.ScriptORM) string { return sc.Id })
}

// appendNew inserts, via the named has-many/many2many association, only the rows the merge added
// — those still lacking a database ID. Rows already persisted (ID set) are skipped, so re-saving
// a merged parent never duplicates its existing children. The association is anchored on a bare
// parent stub carrying only the primary key: if the full (merged) parent were used as the model,
// the FullSaveAssociations session would re-persist its existing children too, duplicating them.
func appendNew[T any](sess *gorm.DB, parent any, name string, rows []T, id func(T) string) error {
	var fresh []T
	for _, r := range rows {
		if id(r) == "" {
			fresh = append(fresh, r)
		}
	}
	if len(fresh) == 0 {
		return nil
	}
	return sess.Model(parent).Association(name).Append(fresh)
}

// appendOne attaches a single newly-merged association value (a fill-only singleton) via a bare
// parent stub, for the same reason appendNew uses one.
func appendOne(sess *gorm.DB, parent any, name string, value any) error {
	return sess.Model(parent).Association(name).Append(value)
}

func ormToPB(ctx context.Context, o *pb.HostORM) (*pb.Host, error) {
	p, err := o.ToPB(ctx)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// indexSameHost returns the index of the first host in `in` that is the same machine as h (shared
// natural key), or -1.
func indexSameHost(h *pb.Host, in []*pb.Host) int {
	for i, e := range in {
		if host.SameHost(e, h) {
			return i
		}
	}
	return -1
}

func findSameHost(h *pb.Host, in []*pb.Host) *pb.Host {
	m, _ := db.FindMatch(in, func(e *pb.Host) bool { return host.SameHost(e, h) })
	return m
}

func (s *server) Delete(ctx context.Context, req *hosts.DeleteHostRequest) (*hosts.DeleteHostResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteHost not implemented")
}

// WithPreloads returns a map DB clauses, to dynamically load child struct fields.
func WithPreloads(from *hosts.HostFilters) (clauses map[string]bool) {
	if from == nil {
		return
	}

	clauses = map[string]bool{
		// Base, unconditional preloads for all hosts
		"OS":              true,
		"OS.PortsUsed":    true,
		"OS.Matches":      true,
		"OS.Fingerprints": true,

		"Status":    true,
		"Hostnames": true,
		"Uptime":    true,

		// Filtered
		"Users":     from.Users,
		"FS":        from.Files,
		"FS.Files":  from.Files,
		"Processes": from.Processes,

		"Ports":              from.Ports,
		"Ports.Service":      from.Ports,
		"Ports.State":        from.Ports,
		"Ports.Scripts":      from.Ports,
		"Ports.Reasons":      from.Ports,
		"ExtraPorts":         from.Ports,
		"ExtraPorts.Reasons": from.Ports,

		"Trace":       from.Trace,
		"Trace.Hops":  from.Trace,
		"HostScripts": from.Scripts,
	}

	return clauses
}
