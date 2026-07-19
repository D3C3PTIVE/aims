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
	"github.com/rsteube/carapace"
	"github.com/spf13/cobra"

	"github.com/d3c3ptive/aims/client"
	"github.com/d3c3ptive/aims/cmd/bring/shell"
)

// groupID places both commands under a dedicated "shell" help group.
const groupID = "shell"

// BringCommand returns the `aims bring <agent-id>` command. It reads the agent from the server and
// writes a per-agent context payload — inert key<TAB>value data, display fields sanitized — that
// the trusted bring() shell function (installed by `aims init`) consumes to make the current shell
// "about" that c2 agent. It takes the connect pre-run bindRunners attaches to online leaves.
func BringCommand(con *client.Client) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "bring <agent-id>",
		Short:   "Source a c2 agent context into the current shell",
		GroupID: groupID,
		Args:    cobra.ExactArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			return runBring(con, command, args)
		},
	}

	// TODO: once the c2 agents API settles, complete the id against live agents (reuse the c2
	// completion so candidates match `aims agents show`). Deferred with runBring — the only two
	// spots that touch the agents data model.
	carapace.Gen(cmd).PositionalCompletion(carapace.ActionMessage("agent id (live completion pending the c2 agents API)"))

	return cmd
}

// InitCommand returns the `aims init <bash|zsh|fish>` command. It emits the fixed, trusted shell
// integration — the bring()/leave() functions and helpers — to be sourced once from the operator's
// shell rc (`source <(aims init zsh)`). This half carries no agent data. It needs no server
// connection: a benign PreRunE keeps bindRunners from attaching the connect pre-run, so it runs
// fully offline.
func InitCommand(con *client.Client) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "init <bash|zsh|fish>",
		Short:   "Emit the shell integration for `bring` (source once in your shell rc)",
		GroupID: groupID,
		Args:    cobra.ExactArgs(1),
		PreRunE: func(*cobra.Command, []string) error { return nil }, // offline: no server connection
		RunE: func(command *cobra.Command, args []string) error {
			sh, err := shell.Parse(args[0])
			if err != nil {
				return err
			}
			return shell.Init(command.OutOrStdout(), sh)
		},
	}

	carapace.Gen(cmd).PositionalCompletion(carapace.ActionValues(shell.Supported()...).Usage("shell dialect"))

	return cmd
}
