package lib

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
	"github.com/maxlandon/aims/client"
	"github.com/maxlandon/aims/cmd/lib/c2"
	"github.com/maxlandon/aims/cmd/lib/credentials"
	"github.com/maxlandon/aims/cmd/lib/hosts"
	"github.com/maxlandon/aims/cmd/lib/scan"
	"github.com/maxlandon/aims/cmd/lib/services"
	"github.com/spf13/cobra"
)

// BindCommandsTo binds all aims commands as subcommands of a parent.
func BindCommandsTo(rootCmd *cobra.Command, con *client.Client) {
	bind("database", rootCmd, con,
		hosts.Commands,
		credentials.Commands,
		services.Commands,
		scan.Commands,
	)

	bind("command & control", rootCmd, con,
		c2.AgentsCommands,
		c2.ChannelsCommands,
	)
}

// bind is a helper used to bind a list of root commands to a given menu, for a given "command help group".
// @group - Name of the group under which the command should be shown. Preferably use a string in the constants package.
// @menu  - The command menu to which the commands should be bound (either server or implant menu).
// @ cmds - A list of functions returning a list of root commands to bind. See any package's `commands.go` file and function.
func bind(group string, menu *cobra.Command, con *client.Client, cmds ...func(con *client.Client) *cobra.Command) {
	found := false

	// Ensure the given command group is available in the menu.
	if group != "" {
		for _, grp := range menu.Groups() {
			if grp.Title == group {
				found = true
				break
			}
		}

		if !found {
			menu.AddGroup(&cobra.Group{
				ID:    group,
				Title: group,
			})
		}
	}

	// Bind the command to the root
	for _, initCommand := range cmds {
		menu.AddCommand(initCommand(con))
	}
}
