package bring

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

	"github.com/rsteube/carapace"
	"github.com/spf13/cobra"

	"github.com/d3c3ptive/aims/client"
	"github.com/d3c3ptive/aims/cmd/bring/shell"
	"github.com/d3c3ptive/aims/cmd/c2"
)

// groupID places both commands under a dedicated "shell" help group.
const groupID = "shell"

// BringCommand returns the `aims bring <agent-id>` command. It emits a per-agent shell payload
// (escaped data only) that the trusted bring() function — installed by ShellInitCommand — sources
// to make the current shell "about" the given c2 agent: prompt segment, the aimsi alias root and
// scoped completions. It reads the agent from the server, so it takes the connect pre-run that
// bindRunners attaches to online leaf commands.
func BringCommand(con *client.Client) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "bring <agent-id>",
		Short:   "Source a c2 agent context into the current shell",
		GroupID: groupID,
		Args:    cobra.ExactArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			return errors.New("bring: not implemented yet (P1)")
		},
	}

	// The agent id argument completes against the live agents in the database, reusing the c2
	// completion so the candidate list matches `aims agents show`.
	carapace.Gen(cmd).PositionalCompletion(c2.CompleteByID(con))

	return cmd
}

// ShellInitCommand returns the `aims shell-init <bash|zsh|fish>` command. It emits the fixed,
// trusted shell integration — the bring()/leave() functions, the prompt logic, the aimsi alias
// and completion registration — to be sourced once from the operator's shell rc. This half
// carries no agent data. It needs no server connection: a benign PreRunE keeps bindRunners from
// attaching the connect pre-run, so `aims shell-init` works fully offline.
func ShellInitCommand(con *client.Client) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "shell-init <bash|zsh|fish>",
		Short:   "Emit the shell integration for `bring` (source once in your shell rc)",
		GroupID: groupID,
		Args:    cobra.ExactArgs(1),
		PreRunE: func(*cobra.Command, []string) error { return nil }, // offline: no server connection
		RunE: func(command *cobra.Command, args []string) error {
			if _, err := shell.Parse(args[0]); err != nil {
				return err
			}
			return errors.New("shell-init: not implemented yet (P1)")
		},
	}

	carapace.Gen(cmd).PositionalCompletion(carapace.ActionValues(shell.Supported()...).Usage("shell dialect"))

	return cmd
}
