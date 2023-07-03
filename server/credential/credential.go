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

	"github.com/maxlandon/aims/proto/credential"
	"github.com/maxlandon/aims/proto/rpc/credentials"
)

type server struct {
	db *gorm.DB
	*credentials.UnimplementedCredentialsServer
}

func New(db *gorm.DB) *server {
	return &server{db: db}
}

func (s *server) Create(ctx context.Context, req *credentials.CreateCredentialRequest) (*credentials.CreateCredentialResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateCredential not implemented")
}

func (s *server) Read(ctx context.Context, req *credentials.ReadCredentialRequest) (*credentials.ReadCredentialResponse, error) {
	// Convert to ORM model
	cred, err := req.GetCredential().ToORM(ctx)
	if err != nil {
		return nil, err
	}

	// Query
	creds := []*credential.CoreORM{}
	err = s.db.Where(cred).First(&creds).Error

	credspb := []*credential.Core{}
	for _, cred := range creds {
		pb, _ := cred.ToPB(ctx)
		credspb = append(credspb, &pb)
	}

	// Response
	res := &credentials.ReadCredentialResponse{Credentials: credspb}

	return res, err
}

func (s *server) List(ctx context.Context, req *credentials.ReadCredentialRequest) (*credentials.ReadCredentialResponse, error) {
	// Convert to ORM model
	cred, err := req.GetCredential().ToORM(ctx)
	if err != nil {
		return nil, err
	}

	// Query
	creds := []*credential.CoreORM{}
	err = s.db.Where(cred).Find(&creds).Error

	credspb := []*credential.Core{}
	for _, cred := range creds {
		pb, _ := cred.ToPB(ctx)
		credspb = append(credspb, &pb)
	}

	// Response
	res := &credentials.ReadCredentialResponse{Credentials: credspb}

	return res, err
}

func (s *server) Upsert(context.Context, *credentials.UpsertCredentialRequest) (*credentials.UpsertCredentialResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpsertCredential not implemented")
}

func (s *server) Delete(context.Context, *credentials.DeleteCredentialRequest) (*credentials.DeleteCredentialResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteCredential not implemented")
}
