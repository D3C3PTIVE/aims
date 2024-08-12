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
	"sync"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	hostcore "github.com/maxlandon/aims/host"
	hostspbtype "github.com/maxlandon/aims/proto/host"
	"github.com/maxlandon/aims/proto/rpc/hosts"
	hostspb "github.com/maxlandon/aims/proto/rpc/hosts"
	"github.com/maxlandon/aims/proto/rpc/scans"
	pb "github.com/maxlandon/aims/proto/scan"
	core "github.com/maxlandon/aims/scan"
	"github.com/maxlandon/aims/server/host"
)

type server struct {
	db *gorm.DB
	*scans.UnimplementedScansServer
}

// New returns a new database scan server, from a given db.
func New(db *gorm.DB) *server {
	return &server{db: db, UnimplementedScansServer: &scans.UnimplementedScansServer{}}
}

// Create creates one or more new scan runs in the database.
func (s *server) Create(ctx context.Context, req *scans.CreateScanRequest) (*scans.CreateScanResponse, error) {
	var newScans []*pb.RunORM
	dbScans := []*pb.RunORM{}
	dbHosts := []*hostspbtype.HostORM{}

	// Get scans to save
	for _, h := range req.GetScans() {
		scanORM, _ := h.ToORM(ctx)
		newScans = append(newScans, &scanORM)
	}

	// Filter scans to add according to AIMS criteria first.
	database := Preloads(s.db, &scans.RunFilters{Hosts: true})
	database.Find(&dbScans)

	// For each host, load services, and check that this host is not
	// already existing in the database, if we can identify it with certainty.
	for _, run := range newScans {
		database := host.Preloads(s.db, &hostspb.HostFilters{Trace: true, Ports: true})
		database.Find(&dbHosts)

		run.Hosts = hostcore.FilterNewHosts(run.Hosts, dbHosts)
	}

	// Then, filter identical scans and write them to database.
	filtered := core.FilterNewScans(newScans, dbScans)
	if len(filtered) > 0 {
		err := s.db.Create(&filtered).Error
		if err != nil {
			return nil, err
		}
	}

	var runsPB []*pb.Run
	for _, scanORM := range filtered {
		hpb, _ := scanORM.ToPB(ctx)
		runsPB = append(runsPB, &hpb)
	}

	// Response
	res := &scans.CreateScanResponse{Scans: runsPB}

	return res, nil
}

// Read reads one or more scans from the database, with optional filters and elements to preload.
func (s *server) Read(ctx context.Context, req *scans.ReadScanRequest) (*scans.ReadScanResponse, error) {
	filts := getFilters(req.GetFilters())

	// Convert to ORM model
	hst, err := req.GetScan().ToORM(ctx)
	if err != nil {
		return nil, err
	}

	dbHosts := []*pb.RunORM{}

	// Preloads
	database := Preloads(s.db.Where(hst), req.GetFilters())

	// Query
	if filts.MaxResults == 1 {
		database = database.First(&dbHosts)
	} else {
		database = database.Find(&dbHosts)
	}

	// If ports are requested, load all hosts ports.
	if filts.Hosts || filts.Ports {
		for _, dbHost := range dbHosts {
			database = host.Preloads(s.db, &hosts.HostFilters{Trace: true, Ports: filts.Ports})
			database.Find(&dbHost.Hosts)
		}
	}

	hostspb := []*pb.Run{}

	for _, host := range dbHosts {
		pb, _ := host.ToPB(ctx)
		hostspb = append(hostspb, &pb)
	}

	// Response
	res := &scans.ReadScanResponse{Scans: hostspb}

	return res, database.Error
}

func (server) List(context.Context, *scans.ReadScanRequest) (*scans.ReadScanResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetScanMany not implemented")
}

func (server) Upsert(context.Context, *scans.UpsertScanRequest) (*scans.UpsertScanResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpsertScan not implemented")
}

func (server) Delete(context.Context, *scans.DeleteScanRequest) (*scans.DeleteScanResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteScan not implemented")
}

// FilterIdenticalScan returns a list of portsfrom which have been removed all ports that are
// already in the database, with a very high degree of certitude. This avoids redundance when
// manipulating new ports/services.
func FilterIdenticalScan(raw []*pb.RunORM, dbHosts []*pb.RunORM) (filtered []*pb.RunORM) {
	for _, newHost := range raw {
		done := new(sync.WaitGroup)

		allMatches := []*pb.RunORM{}

		// Check IDs: if non-nil and identical, done checking.

		// Concurrently check all hosts for an identical trace.
		go func() {
		}()

		// For now we wait for all queries to finish, but ideally,
		// some filters have more weight than others, but might be
		// longer to check, so when one shows that hosts are identical,
		// all other comparison routines should break.
		done.Wait()

		// If not identical, add it to the valid, filtered hosts
		if identical, _ := allScansIdentical(allMatches); !identical {
			filtered = append(filtered, newHost)
		}

	}
	return
}

func allScansIdentical(all []*pb.RunORM) (yes bool, matches int) {
	return false, 0
}

// Preloads loads a given database with preload scan association clauses before querying.
func Preloads(database *gorm.DB, filters *scans.RunFilters) *gorm.DB {
	if filters == nil {
		filters = &scans.RunFilters{}
	}

	filts := map[string]bool{
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
		"Hosts": filters.Hosts,
	}

	preloaded := database.Preload(clause.Associations)

	for name, load := range filts {
		if !load {
			continue
		}

		preloaded = preloaded.Preload(name)
	}

	return preloaded
}

func getFilters(filts *scans.RunFilters) *scans.RunFilters {
	if filts != nil {
		return filts
	}

	return &scans.RunFilters{}
}
