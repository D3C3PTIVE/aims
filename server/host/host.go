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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"

	"github.com/maxlandon/aims/proto/gen/go/rpc/hosts"
)

type server struct {
	*hosts.UnimplementedHostsServer
}

func New(db *gorm.DB) *server {
	return &server{}
}

func (server) CreateHost(context.Context, *hosts.CreateHostRequest) (*hosts.CreateHostResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateHost not implemented")
}

func (server) GetHost(context.Context, *hosts.ReadHostRequest) (*hosts.ReadHostResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetHost not implemented")
}

func (server) GetHostMany(context.Context, *hosts.ReadHostRequest) (*hosts.ReadHostResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetHostMany not implemented")
}

func (server) UpsertHost(context.Context, *hosts.UpsertHostRequest) (*hosts.UpsertHostResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpsertHost not implemented")
}

func (server) DeleteHost(context.Context, *hosts.DeleteHostRequest) (*hosts.DeleteHostResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteHost not implemented")
}
