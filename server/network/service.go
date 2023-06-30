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

	"github.com/maxlandon/aims/proto/gen/go/rpc/network"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
)

type server struct {
	*network.UnimplementedServicesServer
}

func New(db *gorm.DB) *server {
	return &server{}
}

func (server) CreateService(context.Context, *network.CreateServiceRequest) (*network.CreateServiceResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateService not implemented")
}

func (server) GetService(context.Context, *network.ReadServiceRequest) (*network.ReadServiceResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetService not implemented")
}

func (server) GetServiceMany(context.Context, *network.ReadServiceRequest) (*network.ReadServiceResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetServiceMany not implemented")
}

func (server) UpsertService(context.Context, *network.UpsertServiceRequest) (*network.UpsertServiceResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpsertService not implemented")
}

func (server) DeleteService(context.Context, *network.DeleteServiceRequest) (*network.DeleteServiceResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteService not implemented")
}
