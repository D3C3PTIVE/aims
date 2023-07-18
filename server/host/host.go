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
	"github.com/maxlandon/aims/proto/network"
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
	// Convert to ORM model
	h, err := req.GetHost().ToORM(ctx)
	if err != nil {
		return nil, err
	}

	// Preload everything
	db := s.db.Where(h).
		Preload("Addresses").
		Preload("HostScripts").
		Preload("OS").
		Preload("Status").
		Preload("Hostnames").
		Preload("Ports").
		Preload("Ports.Service").
		Preload("ExtraPorts").
		Preload("Uptime").
		Preload("Users").
		Preload("Trace").
		Preload("Trace.Hops").Preload(clause.Associations)

	// Query
	hs := []*host.HostORM{}
	err = db.First(&hs).Error
	// for _, h := range hs {
	// err = db.Model(&h).Association("Addresses").Find(h.Addresses)
	// err = db.Model(&h).Association("OS").Find(h.OS)
	// err = db.Model(&h).Preload("Port.Service").Association("Ports").Find(h.Ports)
	// }

	var addresses []*network.AddressORM
	err = db.Find(&addresses).Error

	hostspb := []*host.Host{}
	for _, host := range hs {
		pb, _ := host.ToPB(ctx)
		hostspb = append(hostspb, &pb)
	}

	// Response
	res := &hosts.ReadHostResponse{Hosts: hostspb}

	return res, err
}

func (s *server) List(ctx context.Context, req *hosts.ReadHostRequest) (*hosts.ReadHostResponse, error) {
	// Convert to ORM model
	h, err := req.GetHost().ToORM(ctx)
	if err != nil {
		return nil, err
	}

	// Preload everything
	// TODO: Somewhat we could pass these strings from the client, much more granular control.
	db := s.db.Where(h).
		Preload("Addresses").
		Preload("HostScripts").
		Preload("OS").
		Preload("OS.PortsUsed").
		Preload("OS.Matches").
		Preload("OS.Fingerprints").
		Preload("Status").
		Preload("Hostnames").
		Preload("Ports").
		Preload("Ports.Service").
		Preload("Ports.State").
		Preload("Ports.Scripts").
		Preload("ExtraPorts").
		Preload("Uptime").
		Preload("Users").
		Preload("Trace").
		Preload("Trace.Hops")

	// Query
	hostsORM := []*host.HostORM{}
	err = db.Find(&hostsORM).Error

	hostspb := []*host.Host{}
	for _, host := range hostsORM {
		pb, _ := host.ToPB(ctx)
		hostspb = append(hostspb, &pb)
	}

	// Response
	res := &hosts.ReadHostResponse{Hosts: hostspb}

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
