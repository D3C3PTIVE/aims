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

	pb "github.com/maxlandon/aims/proto/network"
	"github.com/maxlandon/aims/proto/rpc/network"
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

	// Query
	services := []*pb.ServiceORM{}
	err = s.db.Where(service).First(&services).Error

	servicespb := []*pb.Service{}
	for _, service := range services {
		pb, _ := service.ToPB(ctx)
		servicespb = append(servicespb, &pb)
	}

	// Response
	res := &network.ReadServiceResponse{Services: servicespb}

	return res, err
}

func (s *server) List(ctx context.Context, req *network.ReadServiceRequest) (*network.ReadServiceResponse, error) {
	// Convert to ORM model
	service, err := req.GetService().ToORM(ctx)
	if err != nil {
		return nil, err
	}

	// Query
	services := []*pb.ServiceORM{}
	err = s.db.Where(service).Find(&services).Error

	servicespb := []*pb.Service{}
	for _, service := range services {
		pb, _ := service.ToPB(ctx)
		servicespb = append(servicespb, &pb)
	}

	// Response
	res := &network.ReadServiceResponse{Services: servicespb}

	return res, err
}

func (s *server) Upsert(ctx context.Context, req *network.UpsertServiceRequest) (*network.UpsertServiceResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpsertService not implemented")
}

func (s *server) Delete(ctx context.Context, req *network.DeleteServiceRequest) (*network.DeleteServiceResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteService not implemented")
}
