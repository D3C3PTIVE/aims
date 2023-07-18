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

	"github.com/maxlandon/aims/client"
	"github.com/maxlandon/aims/cmd/lib"
	"github.com/rsteube/carapace"
	"github.com/spf13/cobra"
)

func main() {
	// AIMS RPC client, access to database/server.
	// No working connection yet, handled by teamclient.
	aimsClient := client.New()

	// Teamserver/client for remote/local CLI.
	teamserver, teamclient := newTeam(aimsClient)

	// Generate and bind all AIM objects' subcommand/trees.
	lib.BindCommandsTo(aimsCmd, aimsClient)

	// Pre-commands should connect the teamclient to the server.
	aimsCmd.PersistentPreRunE = func(_ *cobra.Command, _ []string) error {
		return teamserver.Serve(teamclient)
	}

	// Completions (also pre-connect to the server)
	comps := carapace.Gen(aimsCmd)

	comps.PreRun(func(cmd *cobra.Command, args []string) {
		teamserver.Serve(teamclient)
	})

	// Execution
	err := aimsCmd.Execute()
	if err != nil {
		log.Fatal(err)
	}
}

var aimsCmd = &cobra.Command{
	Use:          "aims",
	Short:        "Manage and consume a database for objects for offensive security",
	SilenceUsage: true,
}
