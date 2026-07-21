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

	// Auto-collapse each new run's series: a fresh scan of an existing definition supersedes its
	// older completed siblings so `scan list` self-collapses without a manual `scan cleanup`.
	for _, r := range created {
		s.autoSupersede(ctx, r.GetId())
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
		//
		// OnConflict{UpdateAll} makes this an UPSERT by run Id: a fresh-Id run (Create/Upsert
		// import path) simply inserts, but a run persisted repeatedly under the same Id (a live
		// streaming scan snapshotting itself as hosts arrive, see run.go) updates in place rather
		// than erroring on the primary key. The run's non-host children are re-linked idempotently.
		runORM.Hosts = sharedStubs(sharedHosts)
		if err := tx.Clauses(clause.OnConflict{UpdateAll: true}).Omit("Hosts.*").Create(&runORM).Error; err != nil {
			return err
		}

		// Refresh the live progress rows. The run Create links Progress via the join but, being an
		// association insert, only ever INSERTs a new TaskProgress row — it does not update an
		// already-stored one's columns on conflict. A live scan re-snapshots the same progress row
		// (stable Id, keyed by task name, climbing Percent) every heartbeat, so without this the
		// persisted percent would freeze at the first snapshot and the cross-process progress bar
		// would stall. Upsert each row's columns explicitly (column-scoped by Id), the same way
		// applyCleanup writes are explicit rather than trusting association-save semantics.
		for _, p := range run.GetProgress() {
			pORM, err := p.ToORM(ctx)
			if err != nil {
				return err
			}
			if err := tx.Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "id"}},
				UpdateAll: true,
			}).Create(&pORM).Error; err != nil {
				return err
			}
		}

		// Refresh the target rows for the same reason: a live scan re-snapshots its Targets each
		// heartbeat with a climbing set of Status="done" marks (see run.go / scan.MarkTargetsDone),
		// but the run Create's association insert only ever INSERTs a target row and never updates a
		// stored one's Status on conflict. Without this explicit column-scoped upsert the persisted
		// Status would freeze at the first snapshot (empty), and `scan resume` would re-scan every
		// target. Pre-assigned stable Ids (set in consume) make the upsert idempotent.
		for _, t := range run.GetTargets() {
			tORM, err := t.ToORM(ctx)
			if err != nil {
				return err
			}
			if err := tx.Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "id"}},
				UpdateAll: true,
			}).Create(&tORM).Error; err != nil {
				return err
			}
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

	// Preloads. When hosts are requested, preload the run's host subtrees THROUGH the run_hosts
	// join: Preload("Hosts") (via clause.Associations in db.Preload) loads each run's OWN hosts,
	// scoped by the many-to-many, and the "Hosts.<assoc>" entries pull the nested host tree
	// (ports, services, OS, trace, ...). This replaces a former per-run `Find(&run.Hosts)` that
	// queried the whole hosts table and so loaded EVERY host into EVERY run — which made
	// `scan diff` see identical host sets ("no changes") and `scan show --hosts` wrong.
	scanFilters := WithPreloads(filters)
	if filters.Hosts {
		hostClauses := hosts.WithPreloads(&hostrpcpb.HostFilters{Trace: true, Ports: filters.Ports})
		for name, load := range hostClauses {
			if load {
				scanFilters["Hosts."+name] = true
			}
		}
		// Addresses are the host's identity anchor but are not in hosts.WithPreloads (the host
		// server loads them via clause.Associations on the Host model); preload them explicitly
		// so a run's hosts come back with their addresses.
		scanFilters["Hosts.Addresses"] = true
	}

	query := s.db.Where(hst)
	// Per-tool scoping: a run's producing tool is its Scanner, so scoping to a tool is a
	// direct Scanner match (no join needed). Empty Source is a no-op (all runs).
	if tool := filters.GetSource(); tool != "" {
		query = query.Where("scanner = ?", tool)
	}
	// Lifecycle scoping (see Run.SupersededBy). SupersededBy fetches exactly one head's tombstoned
	// children (the `scan history` query). Otherwise the default view hides tombstones, returning
	// only surviving heads; IncludeSuperseded lifts that so id-addressed reads reach any run.
	// (An older row migrated in before the column existed has NULL, not "", so match both.)
	if head := filters.GetSupersededBy(); head != "" {
		query = query.Where("superseded_by = ?", head)
	} else if !filters.GetIncludeSuperseded() {
		query = query.Where("superseded_by = ? OR superseded_by IS NULL", "")
	}
	database := db.Preload(query, scanFilters)

	// Query
	if filters.MaxResults == 1 {
		database = database.First(&dbScans)
	} else {
		database = database.Find(&dbScans)
	}

	scansResp := []*scanpb.Run{}
	for _, run := range dbScans {
		pb, err := run.ToPB(ctx)
		if err != nil {
			return nil, err
		}
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

// Cleanup collapses each scan *series* (runs of the same definition) onto a single surviving head,
// tombstoning the older siblings so `scan list` shows one row per series while `scan history`/
// `scan diff` still reach every instance. The grouping/head-picking/counting is the shared pure-Go
// fold (scan.ComputeCleanup); this method only loads the runs, applies the plan with the DB, and
// reports it.
//
// Application is deliberately column-scoped (superseded_by / former_runs) rather than a full-run
// Upsert: a whole-run write would re-fold hosts and risk clobbering the run's belongs_to FKs
// (Stats/Info) if they were not preloaded. Tombstoning also keeps the run_hosts join intact — only
// the byte-identical --prune subset is hard-deleted, via the same association-unlink path as Delete
// so shared hosts survive.
func (s *server) Cleanup(ctx context.Context, req *scanrpcpb.CleanupScanRequest) (*scanrpcpb.CleanupScanResponse, error) {
	// Load every run (tombstoned included) so the fold can group series, recount FormerRuns, and
	// flatten chains. loadRuns preloads the state relations (Stats.Finished, Begin, Progress) — stateOf
	// classifies a run from them, and a run whose Stats is not loaded would fall through to the
	// fresh-UpdatedAt heartbeat and read as "running", silently excluding just-imported runs from
	// cleanup — plus Targets (half the series identity).
	all, err := s.loadRuns(ctx)
	if err != nil {
		return nil, err
	}

	plan := scan.ComputeCleanup(all)

	resp := &scanrpcpb.CleanupScanResponse{
		Tombstoned: int32(len(plan.Tombstoned)),
		Heads:      plan.Heads,
	}

	prunable := map[string]bool{}
	if req.GetPrune() {
		for _, r := range plan.Prunable {
			prunable[r.GetId()] = true
		}
		resp.Pruned = int32(len(plan.Prunable))
		resp.Tombstoned = int32(len(plan.Tombstoned) - len(plan.Prunable))
	}

	if req.GetDryRun() {
		return resp, nil
	}

	if err := s.applyCleanup(plan, req.GetPrune()); err != nil {
		return nil, err
	}
	return resp, nil
}

// applyCleanup persists a cleanup plan in one transaction: tombstones (superseded_by), each head's
// FormerRuns, and — when prune — the hard-delete of the byte-identical subset. Writes are
// column-scoped (UpdateColumn, not Update) so a tombstone never bumps updated_at, the liveness
// heartbeat stateOf reads (else a tombstoned interrupted/done run would masquerade as running — a
// tombstone is bookkeeping, not scanner activity). Shared by the Cleanup RPC and auto-supersede.
func (s *server) applyCleanup(plan scan.CleanupPlan, prune bool) error {
	prunable := map[string]bool{}
	if prune {
		for _, r := range plan.Prunable {
			prunable[r.GetId()] = true
		}
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		for _, r := range plan.Tombstoned {
			if prunable[r.GetId()] {
				continue // hard-deleted below instead
			}
			if err := tx.Model(&scanpb.RunORM{}).Where("id = ?", r.GetId()).
				UpdateColumn("superseded_by", r.GetSupersededBy()).Error; err != nil {
				return err
			}
		}
		for _, h := range plan.Heads {
			if err := tx.Model(&scanpb.RunORM{}).Where("id = ?", h.GetId()).
				UpdateColumn("former_runs", h.GetFormerRuns()).Error; err != nil {
				return err
			}
		}
		if prune {
			// Hard-delete the byte-identical subset, unlinking run_hosts so shared hosts survive (the
			// run_hosts-shared-host invariant from Delete).
			for _, r := range plan.Prunable {
				var stored scanpb.RunORM
				if err := tx.Where("id = ?", r.GetId()).First(&stored).Error; err != nil {
					if errors.Is(err, gorm.ErrRecordNotFound) {
						continue
					}
					return err
				}
				if err := tx.Select(clause.Associations).Delete(&stored).Error; err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// autoSupersede collapses the series of a just-completed run: its older completed siblings are
// tombstoned under the newest so `scan list` self-collapses without a manual `scan cleanup`. It is
// best-effort — the run is already stored, so a collapse failure must not fail the scan; errors are
// swallowed and left for a later `scan cleanup`. Never prunes (tombstone only, so history survives).
func (s *server) autoSupersede(ctx context.Context, runID string) {
	all, err := s.loadRuns(ctx)
	if err != nil {
		return
	}
	plan := scan.SupersedeFor(all, runID)
	if plan.Empty() {
		return
	}
	_ = s.applyCleanup(plan, false)
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

// loadRuns loads every persisted run as PB with the relations stateOf needs (Stats.Finished, Begin,
// Progress) plus Targets, but not the heavy host tree — so callers can classify run state and read
// the scan definition cheaply. Shared by Cleanup (series grouping) and Jobs (cross-process
// running-scan view).
func (s *server) loadRuns(ctx context.Context) ([]*scanpb.Run, error) {
	clauses := WithPreloads(&scanrpcpb.RunFilters{})
	clauses["Targets"] = true
	var dbRuns []*scanpb.RunORM
	if err := db.Preload(s.db, clauses).Find(&dbRuns).Error; err != nil {
		return nil, err
	}
	out := make([]*scanpb.Run, 0, len(dbRuns))
	for _, r := range dbRuns {
		pb, err := r.ToPB(ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, &pb)
	}
	return out, nil
}

// readRun loads a single run by id with its full host subtree (and the state relations), for the
// cross-process DB-attach stream. Returns (nil, nil) when no such run exists.
func (s *server) readRun(ctx context.Context, id string) (*scanpb.Run, error) {
	clauses := WithPreloads(&scanrpcpb.RunFilters{Hosts: true})
	hostClauses := hosts.WithPreloads(&hostrpcpb.HostFilters{Trace: true, Ports: true})
	for name, load := range hostClauses {
		if load {
			clauses["Hosts."+name] = true
		}
	}
	clauses["Hosts.Addresses"] = true
	clauses["Targets"] = true

	var r scanpb.RunORM
	err := db.Preload(s.db.Where("id = ?", id), clauses).First(&r).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	pb, err := r.ToPB(ctx)
	if err != nil {
		return nil, err
	}
	return &pb, nil
}
