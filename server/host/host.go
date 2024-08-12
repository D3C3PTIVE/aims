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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"

	"github.com/maxlandon/aims/host"
	"github.com/maxlandon/aims/internal/db"
	pb "github.com/maxlandon/aims/proto/host"
	"github.com/maxlandon/aims/proto/rpc/hosts"
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
	filts := getFilters(req.GetFilters())

	// Convert to ORM model
	hst, err := req.GetHost().ToORM(ctx)
	if err != nil {
		return nil, err
	}

	dbHosts := []*pb.HostORM{}

	// Preloads
	hostFilters := WithPreloads(req.GetFilters())
	database := db.Preload(s.db.Where(hst), hostFilters)

	// Query
	if filts.MaxResults == 1 {
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

// Create creates one or more new hosts in the database.
func (s *server) Create(ctx context.Context, req *hosts.CreateHostRequest) (*hosts.CreateHostResponse, error) {
	var hostsORM []*pb.HostORM

	for _, h := range req.GetHosts() {
		horm, _ := h.ToORM(ctx)
		hostsORM = append(hostsORM, &horm)
	}

	if len(hostsORM) == 0 {
		return nil, errors.New("No scans were provided")
	}

	// Filter hosts to add according to AIMS criteria first.
	dbHosts := []*pb.HostORM{}
	hostFilters := WithPreloads(&hosts.HostFilters{
		Trace: true,
		Ports: true,
	})
	database := db.Preload(s.db, hostFilters)
	filtered := db.FilterNew(hostsORM, dbHosts, host.AreHostsIdentical)

	if len(filtered) == 0 {
		return nil, errors.New("Hosts already exist in the database, skipping")
	}

	err := database.Create(&filtered).Error
	if err != nil {
		return nil, err
	}

	var hostsPB []*pb.Host
	for _, horm := range hostsORM {
		hpb, _ := horm.ToPB(ctx)
		hostsPB = append(hostsPB, &hpb)
	}

	// Response
	res := &hosts.CreateHostResponse{Hosts: hostsPB}

	return res, err
}

func (s *server) Upsert(ctx context.Context, req *hosts.UpsertHostRequest) (*hosts.UpsertHostResponse, error) {
	// Convert to ORM model
	// h, err := req.GetHost().ToORM(ctx)
	// if err != nil {
	// 	return nil, err
	// }
	//
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

		"Ports":         from.Ports,
		"Ports.Service": from.Ports,
		"Ports.State":   from.Ports,
		"Ports.Scripts": from.Ports,
		"ExtraPorts":    from.Ports,

		"Trace":       from.Trace,
		"Trace.Hops":  from.Trace,
		"HostScripts": from.Scripts,
	}

	return clauses
}

func getFilters(filts *hosts.HostFilters) *hosts.HostFilters {
	if filts != nil {
		return filts
	}

	return &hosts.HostFilters{}
}
