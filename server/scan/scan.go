package scan

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

	"github.com/maxlandon/aims/proto/gen/go/rpc/scans"
)

type server struct {
	*scans.UnimplementedScansServer
}

func New(db *gorm.DB) *server {
	return &server{}
}

func (server) CreateScan(context.Context, *scans.CreateScanRequest) (*scans.CreateScanResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateScan not implemented")
}

func (server) GetScan(context.Context, *scans.ReadScanRequest) (*scans.ReadScanResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetScan not implemented")
}

func (server) GetScanMany(context.Context, *scans.ReadScanRequest) (*scans.ReadScanResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetScanMany not implemented")
}

func (server) UpsertScan(context.Context, *scans.UpsertScanRequest) (*scans.UpsertScanResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpsertScan not implemented")
}

func (server) DeleteScan(context.Context, *scans.DeleteScanRequest) (*scans.DeleteScanResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteScan not implemented")
}
