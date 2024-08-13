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
	"log"

	"github.com/reeflective/team/server"
	"github.com/reeflective/team/server/commands"
	"github.com/rsteube/carapace"
	"github.com/spf13/cobra"

	"github.com/d3c3ptive/aims/client"
	"github.com/d3c3ptive/aims/db"
	"github.com/d3c3ptive/aims/server/transport"
)

func main() {
	// Create a new Sliver Teamserver: the latter is able to serve all remote
	// clients for its users, over any of the available transport stacks (MTLS/TS.
	// Persistent teamserver client listeners are not started by default.
	teamserver, opts, err := transport.NewTeamserver()
	if err != nil {
		log.Fatal(err)
	}

	// AIMS RPC client, access to database/server.
	// No working connection yet, handled by teamclient.
	aimsClient, err := client.New(opts...)

	aimsClient.AddConnectHooks(preRunServer(teamserver, aimsClient))

	// Generate and bind all AIM objects' subcommand/trees.
	bindCommands(aimsCmd, aimsClient)

	teamserverCmds := commands.Generate(teamserver, aimsClient.Teamclient)
	aimsCmd.AddCommand(teamserverCmds)

    BindPrePost(aimsCmd, true, aimsClient.ConnectRun)

	// Completions (also pre-connect to the server)
	carapace.Gen(aimsCmd)

	// Execution
	err = aimsCmd.Execute()
	if err != nil {
		log.Fatal(err)
	}
}

var aimsCmd = &cobra.Command{
	Use:          "aims",
	Short:        "Manage and consume a database for objects for offensive security",
	SilenceUsage: true,
}

// preRunServer is the server-binary-specific pre-run; it ensures that the server
// has everything it needs to perform any client-side command/task.
func preRunServer(teamserver *server.Server, con *client.Client) func() error {
	return func() error {
		// TODO: Move this out of here.
		// serverConfig := configs.GetServerConfig()
		// c2.StartPersistentJobs(serverConfig)

		// Let our in-memory teamclient be served.
		if err := teamserver.Serve(con.Teamclient); err != nil {
			return err
		}

		// Ensure the server has what it needs.
		aimsDB := teamserver.Database()
		if err := db.Migrate(aimsDB); err != nil {
			return err
		}

		return nil
	}
}
