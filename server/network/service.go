package network

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

	"github.com/d3c3ptive/aims/internal/db"
	"github.com/d3c3ptive/aims/network/pb"
	network "github.com/d3c3ptive/aims/network/pb/rpc"
)

type server struct {
	db *gorm.DB
	*network.UnimplementedServicesServer
}

func New(db *gorm.DB) *server {
	return &server{db: db, UnimplementedServicesServer: &network.UnimplementedServicesServer{}}
}

func (s *server) Create(ctx context.Context, req *network.CreateServiceRequest) (*network.CreateServiceResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateService not implemented")
}

func (s *server) Read(ctx context.Context, req *network.ReadServiceRequest) (*network.ReadServiceResponse, error) {
	// Convert to ORM model
	service, err := req.GetService().ToORM(ctx)
	if err != nil {
		return nil, err
	}

	// Query. Preload the service's provenance Sources so a read service carries the tools that
	// contributed it, consistent with the other domains (host/credential) rather than coming back
	// bare (P5). Sources is a service's only association, so PreloadAll is exactly this set.
	query := db.PreloadAll(s.db).Where(service)
	// Per-tool scoping: restrict to services contributed by a given tool via the
	// service_sources provenance join. Empty Source is a no-op (all services).
	query = db.ScopeBySource(query, "service_sources", "service_id", req.GetSource())

	// QueryToPBs runs the First and swallows gorm.ErrRecordNotFound as an empty result, so a
	// filtered Read matching no rows returns an empty list the caller's len==0 branch renders.
	// Any other error is a real DB failure, so it is wrapped to a coded gRPC status (R4).
	servicespb, err := db.QueryToPBs[*pb.ServiceORM, pb.Service](ctx, query, true)
	if err != nil {
		return nil, db.WrapDBError(err)
	}
	return &network.ReadServiceResponse{Services: servicespb}, nil
}

func (s *server) List(ctx context.Context, req *network.ReadServiceRequest) (*network.ReadServiceResponse, error) {
	// Convert to ORM model
	service, err := req.GetService().ToORM(ctx)
	if err != nil {
		return nil, err
	}

	// Query. Preload provenance Sources for a consistent, non-bare list (P5) — matching Read.
	servicespb, err := db.QueryToPBs[*pb.ServiceORM, pb.Service](ctx, db.PreloadAll(s.db).Where(service), false)
	if err != nil {
		return nil, db.WrapDBError(err)
	}
	return &network.ReadServiceResponse{Services: servicespb}, nil
}

func (s *server) Upsert(ctx context.Context, req *network.UpsertServiceRequest) (*network.UpsertServiceResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpsertService not implemented")
}

func (s *server) Delete(ctx context.Context, req *network.DeleteServiceRequest) (*network.DeleteServiceResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteService not implemented")
}
