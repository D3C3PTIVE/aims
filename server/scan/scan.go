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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"

	hostrpcpb "github.com/d3c3ptive/aims/host/pb/rpc"
	"github.com/d3c3ptive/aims/internal/db"
	"github.com/d3c3ptive/aims/scan"
	scanpb "github.com/d3c3ptive/aims/scan/pb"
	scanrpcpb "github.com/d3c3ptive/aims/scan/pb/rpc"
	hosts "github.com/d3c3ptive/aims/server/host"
)

type server struct {
	db *gorm.DB
	*scanrpcpb.UnimplementedScansServer
}

// New returns a new database scan server, from a given db.
func New(db *gorm.DB) *server {
	return &server{db: db, UnimplementedScansServer: &scanrpcpb.UnimplementedScansServer{}}
}

// Create creates one or more new scan runs in the database.
func (s *server) Create(ctx context.Context, req *scanrpcpb.CreateScanRequest) (*scanrpcpb.CreateScanResponse, error) {
	var newScans []*scanpb.RunORM
	dbScans := []*scanpb.RunORM{}

	// Get scans to save. Before persisting, fold each run's own hosts together via the
	// non-destructive ingest fold (scan/fold.go): a scan that observed the same host
	// across several results collapses to one host subtree — union of evidence, never
	// duplicated and never dropped. This replaces the old per-host FilterNew, which
	// *dropped* any incoming host that matched the DB and silently lost its new ports,
	// scripts and OS guesses (the data-loss defect in DEDUP.md §1). Cross-run host-row
	// unification (so one physical host is a single row shared by many runs) is the
	// documented follow-on — it needs GORM association-merge, not a match-then-drop.
	for _, run := range req.GetScans() {
		folded := &scan.Run{}
		folded.AddHosts(run.GetHosts()...)
		run.Hosts = folded.Hosts

		scanORM, _ := run.ToORM(ctx)
		newScans = append(newScans, &scanORM)
	}

	// Load existing scans so an identical run is skipped wholesale (AreScansIdentical
	// is RawXML-keyed): re-importing the exact same scan is an idempotent no-op.
	filters := WithPreloads(&scanrpcpb.RunFilters{
		Hosts: true,
	})
	database := db.Preload(s.db, filters)
	database.Find(&dbScans)

	filtered := db.FilterNew(newScans, dbScans, scan.AreScansIdentical)
	if len(filtered) == 0 {
		return nil, errors.New("Scans already exist in the database, skipping")
	}

	err := database.Create(&filtered).Error
	if err != nil {
		return nil, err
	}

	var runsPB []*scanpb.Run
	for _, scanORM := range filtered {
		hpb, _ := scanORM.ToPB(ctx)
		runsPB = append(runsPB, &hpb)
	}

	// Response
	res := &scanrpcpb.CreateScanResponse{Scans: runsPB}

	return res, nil
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
	database := db.Preload(s.db.Where(hst), scanFilters)

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

func (server) List(context.Context, *scanrpcpb.ReadScanRequest) (*scanrpcpb.ReadScanResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetScanMany not implemented")
}

func (server) Upsert(context.Context, *scanrpcpb.UpsertScanRequest) (*scanrpcpb.UpsertScanResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpsertScan not implemented")
}

func (server) Delete(context.Context, *scanrpcpb.DeleteScanRequest) (*scanrpcpb.DeleteScanResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteScan not implemented")
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
