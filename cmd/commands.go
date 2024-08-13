package cmd

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

	"github.com/d3c3ptive/aims/client"
	"github.com/rsteube/carapace"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"google.golang.org/grpc/status"
)

// Bind is a convenience function to bind flags to a given command.
// name - The name of the flag set (can be empty).
// cmd  - The command to which the flags should be bound.
// flags - A function exposing the flag set through which flags are declared.
func Bind(name string, persistent bool, cmd *cobra.Command, flags func(f *pflag.FlagSet)) {
	flagSet := pflag.NewFlagSet(name, pflag.ContinueOnError) // Create the flag set.
	flags(flagSet)                                           // Let the user bind any number of flags to it.

	if persistent {
		cmd.PersistentFlags().AddFlagSet(flagSet)
	} else {
		cmd.Flags().AddFlagSet(flagSet)
	}
}

// BindGroup is a helper used to bind a list of root commands to a given menu, for a given "command help group".
// @group - Name of the group under which the command should be shown. Preferably use a string in the constants package.
// @menu  - The command menu to which the commands should be bound (either server or implant menu).
// @ cmds - A list of functions returning a list of root commands to bind. See any package's `commands.go` file and function.
func BindGroup(group string, menu *cobra.Command, con *client.Client, cmds ...func(con *client.Client) *cobra.Command) {
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

// CompleteFlags is a convenience function for adding completions to a command's flags.
// cmd - The command owning the flags to complete.
// bind - A function exposing a map["flag-name"]carapace.Action.
func CompleteFlags(cmd *cobra.Command, bind func(comp *carapace.ActionMap)) {
	comps := make(carapace.ActionMap)
	bind(&comps)

	carapace.Gen(cmd).FlagCompletion(comps)
}

// CheckError tries to unwrap an error, assuming its a gRPC error.
func CheckError(err error) error {
	if err == nil {
		return nil
	}

	status := status.Convert(err)
	if status == nil {
		return err
	}

	return errors.New(status.Message())
}
