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

	"github.com/maxlandon/aims/proto/host"
	"github.com/maxlandon/aims/proto/rpc/hosts"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type server struct {
	db *gorm.DB
	*hosts.UnimplementedHostsServer
}

func New(db *gorm.DB) *server {
	return &server{db: db, UnimplementedHostsServer: &hosts.UnimplementedHostsServer{}}
}

func (s *server) Create(ctx context.Context, req *hosts.CreateHostRequest) (*hosts.CreateHostResponse, error) {
	var hostsORM []host.HostORM

	for _, h := range req.GetHosts() {
		horm, _ := h.ToORM(ctx)
		hostsORM = append(hostsORM, horm)
	}

	err := s.db.Create(&hostsORM).Error

	var hostsPB []*host.Host
	for _, horm := range hostsORM {
		hpb, _ := horm.ToPB(ctx)
		hostsPB = append(hostsPB, &hpb)
	}

	// Response
	res := &hosts.CreateHostResponse{Hosts: hostsPB}

	return res, err
}

func (s *server) Read(ctx context.Context, req *hosts.ReadHostRequest) (*hosts.ReadHostResponse, error) {
	filts := getFilters(req.GetFilters())

	// Convert to ORM model
	hst, err := req.GetHost().ToORM(ctx)
	if err != nil {
		return nil, err
	}

	dbHosts := []*host.HostORM{}

	// Preloads
	database := hostPreloads(s.db.Where(hst), req.GetFilters())

	// Query
	if filts.MaxResults == 1 {
		database = database.First(&dbHosts)
	} else {
		database = database.Find(&dbHosts)
	}

	hostspb := []*host.Host{}

	for _, host := range dbHosts {
		pb, _ := host.ToPB(ctx)
		hostspb = append(hostspb, &pb)
	}

	// Response
	res := &hosts.ReadHostResponse{Hosts: hostspb}

	return res, database.Error
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

func getFilters(filts *hosts.HostFilters) *hosts.HostFilters {
	if filts != nil {
		return filts
	}

	return &hosts.HostFilters{}
}

func hostPreloads(database *gorm.DB, filters *hosts.HostFilters) *gorm.DB {
	if filters == nil {
		filters = &hosts.HostFilters{}
	}

	filts := map[string]bool{
		// Base, unconditional preloads for all hosts
		"OS":              true,
		"OS.PortsUsed":    true,
		"OS.Matches":      true,
		"OS.Fingerprints": true,

		"Status":    true,
		"Hostnames": true,
		"Uptime":    true,

		// Filtered
		"Users":            filters.Users,
		"FileSystem":       filters.Files,
		"FileSystem.Files": filters.Files,
		"Processes":        filters.Processes,

		"Ports":         filters.Ports,
		"Ports.Service": filters.Ports,
		"Ports.State":   filters.Ports,
		"Ports.Scripts": filters.Ports,
		"ExtraPorts":    filters.Ports,

		"Trace":       filters.Trace,
		"Trace.Hops":  filters.Trace,
		"HostScripts": filters.Scripts,
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
