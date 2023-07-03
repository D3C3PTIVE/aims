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

	"github.com/maxlandon/aims/proto/rpc/hosts"
)

type userServer struct {
	db *gorm.DB
	*hosts.UnimplementedUsersServer
}

func NewUsers(db *gorm.DB) *userServer {
	return &userServer{db: db, UnimplementedUsersServer: &hosts.UnimplementedUsersServer{}}
}

func (userServer) Create(context.Context, *hosts.CreateUserRequest) (*hosts.CreateUserResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateUser not implemented")
}

func (userServer) Read(context.Context, *hosts.ReadUserRequest) (*hosts.ReadUserResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetUser not implemented")
}

func (userServer) List(context.Context, *hosts.ReadUserRequest) (*hosts.ReadUserResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetUserMany not implemented")
}

func (userServer) Upsert(context.Context, *hosts.UpsertUserRequest) (*hosts.UpsertUserResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpsertUser not implemented")
}

func (userServer) Delete(context.Context, *hosts.DeleteUserRequest) (*hosts.DeleteUserResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteUser not implemented")
}
