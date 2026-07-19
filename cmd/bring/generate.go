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

	"github.com/spf13/cobra"

	"github.com/d3c3ptive/aims/client"
)

// runBring is the ONLY part of the bring feature that couples to the c2 agents data model, and it
// is deliberately left unwired for now: the agents command/model is still in flux (a parallel work
// item). When it settles, this becomes:
//
//	res, err := con.Agents.Read(command.Context(), &c2.ReadAgentRequest{
//	    Agent:   &pb.Agent{Id: args[0]},
//	    Filters: &c2.AgentFilters{MaxResults: 1},
//	})
//	// ...map the returned *pb.Agent into an agentContext, then:
//	return writePayload(command.OutOrStdout(), ctx)
//
// Everything else — the payload format (payload.go), sanitization (shell.SanitizeDisplay) and the
// whole `aims init` shell integration — is already complete and tested, so this is the last mile.
func runBring(con *client.Client, command *cobra.Command, args []string) error {
	return errors.New("bring: agent lookup is not wired to the c2 data model yet; " +
		"`aims init <shell>` (the shell integration) is ready to use — see BRING.md")
}
