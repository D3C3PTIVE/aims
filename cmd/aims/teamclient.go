package main

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
	"errors"
	"log"

	aims "github.com/maxlandon/aims/client"
	"github.com/maxlandon/aims/db"
	aimsServer "github.com/maxlandon/aims/server"
	"github.com/reeflective/team/client"
	"github.com/reeflective/team/server"
	teamGrpc "github.com/reeflective/team/transports/grpc/server"
	"google.golang.org/grpc"
)

func newTeam(aimsClient *aims.Client) (*server.Server, *client.Client) {
	// Teamserver
	gTeamserver := teamGrpc.NewListener()

	var serverOpts []server.Options
	serverOpts = append(serverOpts,
		server.WithListener(gTeamserver),
	)

	teamserver, err := server.New("aims", serverOpts...)
	if err != nil {
		log.Fatal(err)
	}

	bindServer := func(grpcServer *grpc.Server) error {
		if grpcServer == nil {
			return errors.New("No gRPC server to use for service")
		}

		aimsDB := teamserver.Database()
		if err := db.Migrate(aimsDB); err != nil {
			return err
		}

		aimsServer.New(grpcServer, aimsServer.WithDatabase(aimsDB))

		return nil
	}

	gTeamserver.PostServe(bindServer)

	// Teamclient
	gTeamclient := teamGrpc.NewClientFrom(gTeamserver)

	bindClient := func(clientConn any) error {
		grpcClient, ok := clientConn.(*grpc.ClientConn)
		if !ok || grpcClient == nil {
			return errors.New("No gRPC client to use for service")
		}

		return aimsClient.Init(grpcClient)
	}

	var clientOpts []client.Options
	clientOpts = append(clientOpts,
		client.WithDialer(gTeamclient, bindClient),
	)

	teamclient := teamserver.Self(clientOpts...)

	return teamserver, teamclient
}
