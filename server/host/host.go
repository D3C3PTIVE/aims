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
	database := db.Preload(s.db.Where(hst), filters)

	// Query
	if filts != nil && filts.MaxResults == 1 {
		database = database.First(&dbHosts)
	} else {
		database = database.Find(&dbHosts)
	}

	hostspb := []*pb.Host{}

	for _, host := range dbHosts {
		pb, _ := host.ToPB(ctx)
		hostspb = append(hostspb, &pb)
	}

	// Response
	res := &hosts.ReadHostResponse{Hosts: hostspb}

	return res, database.Error
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

	existing, err := s.loadHostsPB(ctx)
	if err != nil {
		return nil, err
	}

	var created []*pb.Host
	for _, h := range req.GetHosts() {
		if h == nil || findSameHost(h, existing) != nil {
			continue
		}
		saved, err := s.insertHost(ctx, h)
		if err != nil {
			return nil, err
		}
		existing = append(existing, saved) // so later hosts in the batch dedup against it
		created = append(created, saved)
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

// ingest is the shared body of Upsert and IngestHosts: match each incoming host against the DB by
// natural key, merge-in-place when found (persisting only the new evidence), insert when not, and
// return the persisted rows with their DB-assigned IDs. Hosts later in the batch dedup against the
// ones already ingested, so a batch that repeats a host folds it into one row.
func (s *server) ingest(ctx context.Context, in []*pb.Host) ([]*pb.Host, error) {
	existing, err := s.loadHostsPB(ctx)
	if err != nil {
		return nil, err
	}

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

	return out, nil
}

//
// [ Ingest helpers ] -----------------------------------------------------
//

// loadHostsPB loads every host with its full tree preloaded, as PB values — the representation
// host.SameHost / host.MergeHost operate on. First-level associations (Addresses, Ports,
// Hostnames, OS, Trace, …) come from db.Preload's clause.Associations; ingestPreloads adds the
// nested levels the merge reaches into (a port's service/state/scripts, etc.).
func (s *server) loadHostsPB(ctx context.Context) ([]*pb.Host, error) {
	var dbHosts []*pb.HostORM
	if err := db.Preload(s.db, ingestPreloads()).Find(&dbHosts).Error; err != nil {
		return nil, err
	}

	out := make([]*pb.Host, 0, len(dbHosts))
	for _, o := range dbHosts {
		p, err := o.ToPB(ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, &p)
	}
	return out, nil
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
// Note: enrichment that lands *inside* an already-persisted child (e.g. a newly-observed NSE
// script on a port that already exists) is not yet written back — only whole new children are.
// Deep in-place enrichment is a follow-up, tracked alongside DEDUP.md's other proto/merge gaps.
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
		// carries its own service/state/scripts in with it.
		sess := tx.Session(&gorm.Session{FullSaveAssociations: true})

		// Unioned collections: append only the elements without a DB ID (the newly-merged ones).
		if err := appendNew(sess, horm.Id, "Addresses", horm.Addresses, func(a *network.AddressORM) string { return a.Id }); err != nil {
			return err
		}
		if err := appendNew(sess, horm.Id, "Hostnames", horm.Hostnames, func(h *pb.HostnameORM) string { return h.Id }); err != nil {
			return err
		}
		if err := appendNew(sess, horm.Id, "Ports", horm.Ports, func(p *pb.PortORM) string { return p.Id }); err != nil {
			return err
		}
		if err := appendNew(sess, horm.Id, "ExtraPorts", horm.ExtraPorts, func(e *pb.ExtraPortORM) string { return e.Id }); err != nil {
			return err
		}
		if err := appendNew(sess, horm.Id, "HostScripts", horm.HostScripts, func(sc *nmap.ScriptORM) string { return sc.Id }); err != nil {
			return err
		}

		// Fill-only singletons the host previously lacked (merge sets them only when absent).
		if horm.OS != nil && horm.OS.Id == "" {
			if err := appendOne(sess, horm.Id, "OS", horm.OS); err != nil {
				return err
			}
		}
		if horm.Status != nil && horm.Status.Id == "" {
			if err := appendOne(sess, horm.Id, "Status", horm.Status); err != nil {
				return err
			}
		}
		if horm.Distance != nil && horm.Distance.Id == "" {
			if err := appendOne(sess, horm.Id, "Distance", horm.Distance); err != nil {
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

// appendNew inserts, via the named has-many/many2many association, only the rows the merge added
// — those still lacking a database ID. Rows already persisted (ID set) are skipped, so re-saving
// a merged host never duplicates its existing children. The association is anchored on a bare host
// stub carrying only the primary key: if the full (merged) host were used as the model, the
// FullSaveAssociations session would re-persist its existing children too, duplicating them.
func appendNew[T any](sess *gorm.DB, hostID, name string, rows []T, id func(T) string) error {
	var fresh []T
	for _, r := range rows {
		if id(r) == "" {
			fresh = append(fresh, r)
		}
	}
	if len(fresh) == 0 {
		return nil
	}
	return sess.Model(&pb.HostORM{Id: hostID}).Association(name).Append(fresh)
}

// appendOne attaches a single newly-merged association value (a fill-only singleton) via a bare
// host stub, for the same reason appendNew uses one.
func appendOne(sess *gorm.DB, hostID, name string, value any) error {
	return sess.Model(&pb.HostORM{Id: hostID}).Association(name).Append(value)
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
	if i := indexSameHost(h, in); i >= 0 {
		return in[i]
	}
	return nil
}

func (s *server) Delete(ctx context.Context, req *hosts.DeleteHostRequest) (*hosts.DeleteHostResponse, error) {
	// Convert to ORM model
	var hostsORM []*pb.HostORM

	for _, h := range req.GetHosts() {
		horm, _ := h.ToORM(ctx)
		hostsORM = append(hostsORM, &horm)
	}

	// Filter hosts to add according to AIMS criteria first.
	dbHosts := []*pb.HostORM{}
	hostFilters := WithPreloads(&hosts.HostFilters{
		Trace: true,
		Ports: true,
	})
	database := db.Preload(s.db, hostFilters)
	database.Find(&dbHosts)

	// // Query
	// hosts := []*host.HostORM{}
	// err = s.db.Where(h).First(&hosts).Error
	//
	// hostspb := []*h.Host{}
	// for _, host := range hosts {
	// 	pb, _ := host.ToPB(ctx)
	// 	hostspb = append(hostspb, &pb)
	// }
	//
	// // Response
	// res := &h.ReadHostResponse{Hosts: hostspb}
	//
	// return res, err
	return nil, status.Errorf(codes.Unimplemented, "method CreateHost not implemented")
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
		"ExtraPorts":         from.Ports,
		"ExtraPorts.Reasons": from.Ports,

		"Trace":       from.Trace,
		"Trace.Hops":  from.Trace,
		"HostScripts": from.Scripts,
	}

	return clauses
}
