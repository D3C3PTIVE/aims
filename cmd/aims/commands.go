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
	"github.com/spf13/cobra"

	"github.com/d3c3ptive/aims/client"
	"github.com/d3c3ptive/aims/cmd"
	"github.com/d3c3ptive/aims/cmd/c2"
	"github.com/d3c3ptive/aims/cmd/credentials"
	"github.com/d3c3ptive/aims/cmd/hosts"
	"github.com/d3c3ptive/aims/cmd/scan"
	"github.com/d3c3ptive/aims/cmd/services"
)

// bindCommands binds all aims commands as subcommands of a parent.
func bindCommands(rootCmd *cobra.Command, con *client.Client) {
	cmd.BindGroup("database", rootCmd, con,
		hosts.Commands,
		credentials.Commands,
		services.Commands,
		scan.Commands,
	)

	cmd.BindGroup("command & control", rootCmd, con,
		c2.AgentsCommands,
		c2.ChannelsCommands,
	)
}
// BindPrePost is used to register specific pre/post-runs for a given command/tree.
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

