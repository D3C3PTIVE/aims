package credential

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

	"github.com/maxlandon/aims/proto/gen/go/rpc/credentials"
)

type loginServer struct {
	db *gorm.DB
	*credentials.UnimplementedLoginsServer
}

func NewLoginServer(db *gorm.DB) *loginServer {
	return &loginServer{db: db}
}

func (loginServer) CreateLogin(context.Context, *credentials.CreateLoginRequest) (*credentials.CreateLoginResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateLogin not implemented")
}

func (loginServer) GetLogin(context.Context, *credentials.ReadLoginRequest) (*credentials.ReadLoginResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetLogin not implemented")
}

func (loginServer) GetLoginMany(context.Context, *credentials.ReadLoginRequest) (*credentials.ReadLoginResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetLoginMany not implemented")
}

func (loginServer) UpsertLogin(context.Context, *credentials.UpsertLoginRequest) (*credentials.UpsertLoginResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpsertLogin not implemented")
}

func (loginServer) DeleteLogin(context.Context, *credentials.DeleteLoginRequest) (*credentials.DeleteLoginResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteLogin not implemented")
}
