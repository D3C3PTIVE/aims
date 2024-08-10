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

	"github.com/maxlandon/aims/client"
	"github.com/maxlandon/aims/cmd/lib"
	"github.com/maxlandon/aims/db"
	"github.com/maxlandon/aims/server/transport"
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
	lib.BindCommandsTo(aimsCmd, aimsClient)

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

// BindPrePost is used to register specific pre/post-runs for a given command/tree.
//
// This function is special in that it will only bind the pre/post-runners to commands
// in the tree if they have a non-nil Run/RunE function, or if they are leaf commands.
//
// This allows us to optimize client-to-server connections for things like completions.
func BindPrePost(root *cobra.Command, pre bool, runs ...func(_ *cobra.Command, _ []string) error) {
	for _, cmd := range root.Commands() {
		ePreE := cmd.PersistentPreRunE
		ePostE := cmd.PersistentPostRunE
		run, runE := cmd.Run, cmd.RunE

		// Don't modify commands in charge on their own tree.
		if pre && ePreE != nil {
			continue
		} else if ePostE != nil {
			continue
		}

		// Always go to find the leaf commands, irrespective
		// of what we do with this parent command.
		if cmd.HasSubCommands() {
			BindPrePost(cmd, pre, runs...)
		}

		// If the command has no runners, there's nothing to bind:
		// If it has flags, any child command requiring them should
		// trigger the prerunners, which will connect to the server.
		if run == nil && runE == nil {
			continue
		}

		// Else we have runners, bind the pre-runs if possible.
		if pre && cmd.PreRunE != nil {
			continue
		} else if cmd.PostRunE != nil {
			continue
		}

		// Compound all runners together.
		cRun := func(c *cobra.Command, args []string) error {
			for _, run := range runs {
				err := run(c, args)
				if err != nil {
					return err
				}
			}

			return nil
		}

		// Bind
		if pre {
			cmd.PreRunE = cRun
		} else {
			cmd.PostRunE = cRun
		}
	}
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
