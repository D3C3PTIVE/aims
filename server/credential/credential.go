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

type server struct {
	*credentials.UnimplementedCredentialsServer
}

func New(db *gorm.DB) *server {
	return &server{}
}

func (server) CreateCredential(ctx context.Context, req *credentials.CreateCredentialRequest) (*credentials.CreateCredentialResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateCredential not implemented")
}

func (server) GetCredential(context.Context, *credentials.ReadCredentialRequest) (*credentials.ReadCredentialResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetCredential not implemented")
}

func (server) GetCredentialMany(context.Context, *credentials.ReadCredentialRequest) (*credentials.ReadCredentialResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetCredentialMany not implemented")
}

func (server) UpsertCredential(context.Context, *credentials.UpsertCredentialRequest) (*credentials.UpsertCredentialResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpsertCredential not implemented")
}

func (server) DeleteCredential(context.Context, *credentials.DeleteCredentialRequest) (*credentials.DeleteCredentialResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteCredential not implemented")
}
