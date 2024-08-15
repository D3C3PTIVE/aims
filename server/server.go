package server

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
	"google.golang.org/grpc"
	"gorm.io/gorm"

	c2pb "github.com/d3c3ptive/aims/c2/pb/rpc"
	credentials "github.com/d3c3ptive/aims/credential/pb/rpc"
	hosts "github.com/d3c3ptive/aims/host/pb/rpc"
	network "github.com/d3c3ptive/aims/network/pb/rpc"
	scans "github.com/d3c3ptive/aims/scan/pb/rpc"
	"github.com/d3c3ptive/aims/server/c2"
	"github.com/d3c3ptive/aims/server/credential"
	"github.com/d3c3ptive/aims/server/host"
	networkServer "github.com/d3c3ptive/aims/server/network"
	"github.com/d3c3ptive/aims/server/scan"
)

// Options is used to setup the AIMS database service with specific things,
// like the database backend, network listeners and connections, bounds, etc.
type Options func(opts *sOpts) *sOpts

// sOpts contains all customizable fields and behaviors
// to apply to a given AIMS database server.
type sOpts struct {
	db *gorm.DB
}

// WithDatabase uses a specific database backend.
func WithDatabase(db *gorm.DB) Options {
	return func(o *sOpts) *sOpts {
		o.db = db
		return o
	}
}

// New uses an existing gRPC server and registers all AIMS database services to it.
func New(conn *grpc.Server, opts ...Options) {
	// Initialize with default or user options.
	options := &sOpts{}

	for _, opt := range opts {
		options = opt(options)
	}

	// Targets
	hosts.RegisterHostsServer(conn, host.New(options.db))
	hosts.RegisterUsersServer(conn, host.NewUsers(options.db))
	network.RegisterServicesServer(conn, networkServer.New(options.db))
	credentials.RegisterCredentialsServer(conn, credential.New(options.db))
	credentials.RegisterLoginsServer(conn, credential.NewLoginServer(options.db))

	// C2
	c2pb.RegisterAgentsServer(conn, c2.New(options.db))
	c2pb.RegisterChannelsServer(conn, c2.NewChannelServer(options.db))

	// Infrastructure & tools
	scans.RegisterScansServer(conn, scan.New(options.db))
}
