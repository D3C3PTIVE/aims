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
	"context"
	"errors"
	"sync"

	"github.com/gofrs/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	hostpb "github.com/d3c3ptive/aims/host/pb"
	hostrpcpb "github.com/d3c3ptive/aims/host/pb/rpc"
	"github.com/d3c3ptive/aims/internal/db"
	provpb "github.com/d3c3ptive/aims/provenance/pb"
	"github.com/d3c3ptive/aims/scan"
	scanpb "github.com/d3c3ptive/aims/scan/pb"
	scanrpcpb "github.com/d3c3ptive/aims/scan/pb/rpc"
	hosts "github.com/d3c3ptive/aims/server/host"
)

type server struct {
	db *gorm.DB
	*scanrpcpb.UnimplementedScansServer

	// jobs holds the scans currently (and recently) running server-side, so a foreground scan
	// survives the operator detaching and other operators can list/attach/stop it. See run.go.
	jobsMu sync.Mutex
	jobs   map[string]*scanJob
}

// New returns a new database scan server, from a given db.
func New(db *gorm.DB) *server {
	return &server{
		db:                       db,
		UnimplementedScansServer: &scanrpcpb.UnimplementedScansServer{},
		jobs:                     make(map[string]*scanJob),
	}
}

// Create stores one or more new scan runs, unifying the hosts they observed with the shared host
// table. A run is skipped wholesale when an identical run is already present (AreScansIdentical is
// RawXML-keyed), so re-importing the exact same scan is an idempotent no-op — the CLI renders the
// resulting empty Scans list as "already present (skipped)". Otherwise the run is persisted and its
// hosts are folded through the global host records (host.IngestHosts): the run is linked to the
// resulting shared rows via the run_hosts join rather than getting a private copy of every host, so
// one physical host observed by several runs is a single row referenced by each — cross-run
// host-row unification (DEDUP.md's documented follow-on), not the old match-then-drop.
func (s *server) Create(ctx context.Context, req *scanrpcpb.CreateScanRequest) (*scanrpcpb.CreateScanResponse, error) {
	// Load existing runs once to detect exact-duplicate re-imports. Their host trees need not be
	// preloaded: AreScansIdentical keys on RawXML and the scan tasks, not on the host subtree.
	dbScans := []*scanpb.RunORM{}
	if err := s.db.Find(&dbScans).Error; err != nil {
		return nil, err
	}

	var created []*scanpb.Run
	for _, run := range req.GetScans() {
		if run == nil {
			continue
		}

		// Fold this run's own hosts together first (intra-run union): a scan that observed the same
		// host across several results collapses to one host subtree before it ever hits the DB.
		folded := &scan.Run{}
		folded.AddHosts(run.GetHosts()...)
		run.Hosts = folded.Hosts

		// Stamp this run's provenance onto every object it produced, so scan-produced hosts/
		// ports/services carry "who found me" through the ingest fold (where MergeSources unions
		// it with any prior contributors). This is what lets scan-produced objects be scoped by
		// tool without a RunId back-reference on each row.
		stampScanProvenance(run)

		// Skip an exact-duplicate run wholesale (idempotent re-import).
		runORM, err := run.ToORM(ctx)
		if err != nil {
			return nil, err
		}
		if isDuplicateRun(&runORM, dbScans) {
			continue
		}

		saved, err := s.persistRun(ctx, run)
		if err != nil {
			return nil, err
		}

		created = append(created, saved)
		dbScans = append(dbScans, &runORM) // so a duplicate later in the same batch is caught too
	}

	return &scanrpcpb.CreateScanResponse{Scans: created}, nil
}

// persistRun stores a single run and unifies its hosts with the shared host table. The whole
// operation is one transaction: the run's hosts are folded into the global host records (enriching
// existing rows, inserting new ones), the run and its non-host associations are written, and the
// run is linked to the shared host rows via the run_hosts join. If any step fails, the host
// enrichment rolls back with the run.
func (s *server) persistRun(ctx context.Context, run *scanpb.Run) (*scanpb.Run, error) {
	var out *scanpb.Run

	err := s.db.Transaction(func(tx *gorm.DB) error {
		// Fold this run's hosts into the shared host table; the returned rows carry their DB IDs.
		sharedHosts, err := hosts.IngestHosts(ctx, tx, run.GetHosts())
		if err != nil {
			return err
		}

		runORM, err := run.ToORM(ctx)
		if err != nil {
			return err
		}

		// Reference the shared rows instead of the run's private host subtrees: Omit("Hosts.*")
		// makes Create write only the run_hosts join entries (the host records are left as the
		// already-persisted shared rows), and the join insert is OnConflict-DoNothing, so
		// re-linking a host a run already references is idempotent.
		runORM.Hosts = sharedStubs(sharedHosts)
		if err := tx.Omit("Hosts.*").Create(&runORM).Error; err != nil {
			return err
		}

		pb, err := runORM.ToPB(ctx)
		if err != nil {
			return err
		}
		pb.Hosts = sharedHosts // return the full shared host trees, not the bare stubs
		out = &pb
		return nil
	})
	if err != nil {
		return nil, err
	}

	return out, nil
}

// stampScanProvenance derives a provenance.Source from the run (Tool=Scanner, Type=Scan, plus
// Args/Version/ProfileName/SessionId) and attaches it to the run itself (its producer Source
// field) and to every object the run produced — each host and its addresses, ports, and port
// services. Each object gets its OWN Source value (not a shared pointer) so the ORM writes a
// distinct join row per object rather than aliasing one. Once stamped, the Sources ride through
// hosts.IngestHosts, where host.MergeSources unions them into any existing shared record.
func stampScanProvenance(run *scanpb.Run) {
	if run == nil || run.GetScanner() == "" {
		return
	}
	newSource := func(id string) *provpb.Source {
		return &provpb.Source{
			Id:          id,
			Tool:        run.GetScanner(),
			Type:        provpb.SourceType_Scan,
			Args:        run.GetArgs(),
			Version:     run.GetVersion(),
			ProfileName: run.GetProfileName(),
			SessionId:   run.GetSessionId(),
		}
	}

	// The run's own producer record (empty Id → BeforeCreate mints one).
	run.Source = newSource("")

	for _, h := range run.GetHosts() {
		if h == nil {
			continue
		}
		// One Source row per host, shared by the host and every object the run produced on it
		// (its addresses, ports, and port services): a scan of a host with N ports yields one
		// provenance row + N join links, not N identical rows. The shared pre-assigned Id now
		// survives (BeforeCreate only mints an Id when none is set), and GORM's m2m insert is
		// OnConflict-DoNothing, so the row is written once and every other object references it.
		src := newSource(uuid.Must(uuid.NewV4()).String())
		h.Sources = append(h.Sources, src)
		for _, a := range h.GetAddresses() {
			if a != nil {
				a.Sources = append(a.Sources, src)
			}
		}
		for _, p := range h.GetPorts() {
			if p == nil {
				continue
			}
			p.Sources = append(p.Sources, src)
			if p.Service != nil {
				p.Service.Sources = append(p.Service.Sources, src)
			}
		}
	}
}

// isDuplicateRun reports whether run is already stored. RawXML is the scanner's verbatim output and
// thus a definitive fingerprint of a run: when both sides carry it, equality alone decides identity
// and inequality alone rules it out — two scans with different raw documents are different scans,
// whatever their other fields. Only when a run lacks RawXML (e.g. a scanner that emitted no raw
// document) does it fall back to AreScansIdentical's field-weighted heuristic. This matters for
// cross-run host unification: a too-eager match here would skip a genuinely new run and its host
// would never be linked to it. (AreScansIdentical scores two runs with empty task-lists as matching
// regardless of RawXML, so it cannot be the sole gate.)
func isDuplicateRun(run *scanpb.RunORM, existing []*scanpb.RunORM) bool {
	return findDuplicateRun(run, existing) != nil
}

// findDuplicateRun returns the stored run that `run` duplicates (by the same RawXML-authoritative
// rule as isDuplicateRun), or nil if it is genuinely new. Upsert uses it to echo the canonical
// stored Id back for an already-present run instead of silently skipping it.
func findDuplicateRun(run *scanpb.RunORM, existing []*scanpb.RunORM) *scanpb.RunORM {
	for _, e := range existing {
		if run.RawXML != "" && e.RawXML != "" {
			if run.RawXML == e.RawXML {
				return e
			}
			continue // different raw documents: definitively distinct runs
		}
		if scan.AreScansIdentical(run, e) {
			return e
		}
	}
	return nil
}

// sharedStubs reduces persisted host rows to bare {Id} stubs — enough to write the run_hosts join
// entries that link a run to the shared host records without touching the host rows themselves.
func sharedStubs(in []*hostpb.Host) []*hostpb.HostORM {
	stubs := make([]*hostpb.HostORM, 0, len(in))
	for _, h := range in {
		if h.GetId() != "" {
			stubs = append(stubs, &hostpb.HostORM{Id: h.GetId()})
		}
	}
	return stubs
}

// Read reads one or more scans from the database, with optional filters and elements to preload.
func (s *server) Read(ctx context.Context, req *scanrpcpb.ReadScanRequest) (*scanrpcpb.ReadScanResponse, error) {
	// Convert to ORM model
	hst, err := req.GetScan().ToORM(ctx)
	if err != nil {
		return nil, err
	}

	filters := req.GetFilters()

	dbScans := []*scanpb.RunORM{}

	// Preloads
	scanFilters := WithPreloads(filters)
	query := s.db.Where(hst)
	// Per-tool scoping: a run's producing tool is its Scanner, so scoping to a tool is a
	// direct Scanner match (no join needed). Empty Source is a no-op (all runs).
	if tool := filters.GetSource(); tool != "" {
		query = query.Where("scanner = ?", tool)
	}
	database := db.Preload(query, scanFilters)

	// Query
	if filters.MaxResults == 1 {
		database = database.First(&dbScans)
	} else {
		database = database.Find(&dbScans)
	}

	scansResp := []*scanpb.Run{}

	// Load hosts if required
	for _, run := range dbScans {
		if filters.Hosts {
			filters := hosts.WithPreloads(&hostrpcpb.HostFilters{
				Trace: true,
				Ports: true,
			})
			database = db.Preload(s.db, filters)
			database.Find(&run.Hosts)
		}

		pb, _ := run.ToPB(ctx)
		scansResp = append(scansResp, &pb)
	}

	// Response
	res := &scanrpcpb.ReadScanResponse{Scans: scansResp}

	return res, database.Error
}

// List returns all scans matching the request filters. A Run has no natural key to match on (it is
// identified by its Id / RawXML), so listing is a plain filtered read — List shares Read's preload
// and host-loading path rather than maintaining a second, divergent query.
func (s *server) List(ctx context.Context, req *scanrpcpb.ReadScanRequest) (*scanrpcpb.ReadScanResponse, error) {
	return s.Read(ctx, req)
}

// Upsert stores runs that are new and returns the canonical stored run for ones already present. It
// is the idempotent sibling of Create: the same RawXML-authoritative duplicate detection and the
// same host unification via host.IngestHosts (persistRun), except a duplicate is echoed back tagged
// with the Id it already has rather than being silently dropped. A Run is an immutable historical
// record, so there is no in-place field merge here; enriching a stored run as it runs (the live-scan
// case) is the streaming follow-on (SCAN.md Part C), not an Upsert concern.
func (s *server) Upsert(ctx context.Context, req *scanrpcpb.UpsertScanRequest) (*scanrpcpb.UpsertScanResponse, error) {
	dbScans := []*scanpb.RunORM{}
	if err := s.db.Find(&dbScans).Error; err != nil {
		return nil, err
	}

	var out []*scanpb.Run
	for _, run := range req.GetScans() {
		if run == nil {
			continue
		}

		// Same intra-run host fold + provenance stamping Create performs, so identity and
		// provenance match whichever path first stored the run.
		folded := &scan.Run{}
		folded.AddHosts(run.GetHosts()...)
		run.Hosts = folded.Hosts
		stampScanProvenance(run)

		runORM, err := run.ToORM(ctx)
		if err != nil {
			return nil, err
		}

		// Already stored: return the caller's run tagged with the canonical Id (its full data is
		// what the caller passed; only the Id needs reconciling with the persisted row).
		if match := findDuplicateRun(&runORM, dbScans); match != nil {
			run.Id = match.Id
			out = append(out, run)
			continue
		}

		saved, err := s.persistRun(ctx, run)
		if err != nil {
			return nil, err
		}
		out = append(out, saved)
		dbScans = append(dbScans, &runORM) // catch a duplicate later in the same batch
	}

	return &scanrpcpb.UpsertScanResponse{Scans: out}, nil
}

// Delete removes scans by Id. A run *owns* its task/result/target/script rows but only *references*
// the hosts it observed — the run_hosts join is a many2many shared across runs (cross-run host
// unification). Deleting with Select(clause.Associations) therefore clears the run's join entries,
// unlinking the shared host rows without deleting them, and removes the run itself; every host a
// sibling run still references survives untouched. (The run's own now-unlinked task/result rows are
// left as orphans — a storage-GC concern, not a correctness one, since nothing references them.)
func (s *server) Delete(ctx context.Context, req *scanrpcpb.DeleteScanRequest) (*scanrpcpb.DeleteScanResponse, error) {
	var deleted []*scanpb.Run

	for _, run := range req.GetScans() {
		if run.GetId() == "" {
			continue // Delete is by Id; the CLI resolves an ID prefix to a full Id first
		}

		// Load the stored run so the response echoes what was removed, then delete it.
		var stored scanpb.RunORM
		if err := s.db.Where("id = ?", run.GetId()).First(&stored).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				continue
			}
			return nil, err
		}

		if err := s.db.Select(clause.Associations).Delete(&stored).Error; err != nil {
			return nil, err
		}

		pb, err := stored.ToPB(ctx)
		if err != nil {
			return nil, err
		}
		deleted = append(deleted, &pb)
	}

	return &scanrpcpb.DeleteScanResponse{Scans: deleted}, nil
}

func WithPreloads(from *scanrpcpb.RunFilters) (clauses map[string]bool) {
	if from == nil {
		return
	}

	clauses = map[string]bool{
		// Base, unconditional preloads for all hosts
		"Debugging":   true,
		"PreScripts":  true,
		"PostScripts": true,
		"Begin":       true,
		"Progress":    true,
		"End":         true,

		"Stats":          true,
		"Stats.Hosts":    true,
		"Stats.Finished": true,

		// Filtered
		"Hosts": from.Hosts,
	}

	return clauses
}
