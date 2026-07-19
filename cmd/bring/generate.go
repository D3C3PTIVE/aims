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
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"

	pb "github.com/d3c3ptive/aims/c2/pb"
	c2 "github.com/d3c3ptive/aims/c2/pb/rpc"
	"github.com/d3c3ptive/aims/client"
	aims "github.com/d3c3ptive/aims/cmd"
)

// agentReader is the narrow slice of c2.AgentsClient that bring needs. Depending on this one method
// keeps bring's coupling to the (still-evolving) agents API minimal and makes the lookup
// unit-testable with a mock. c2.AgentsClient satisfies it.
type agentReader interface {
	Read(ctx context.Context, in *c2.ReadAgentRequest, opts ...grpc.CallOption) (*c2.ReadAgentResponse, error)
}

// runBring reads the requested agent from the server and writes its context payload to stdout for
// the trusted bring() shell function to consume.
func runBring(con *client.Client, command *cobra.Command, args []string) error {
	return emitAgentPayload(command.Context(), con.Agents, args[0], command.OutOrStdout())
}

// emitAgentPayload looks up the agent by id and writes its payload. This is the single place bring
// touches the agents data model, so it can evolve with that API without disturbing the rest of the
// feature.
//
// Today it matches by exact id: the client exposes only Read (which resolves one exact record
// server-side), so a shortened id cannot be prefix-resolved here yet. Once the agents service adds
// a List RPC, switch the request to List and short-id prefix matching works via
// findAgentByIDPrefix below (already the resolver, and already tested) — a one-line change.
func emitAgentPayload(ctx context.Context, agents agentReader, id string, w io.Writer) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("bring: no agent id given")
	}

	res, err := agents.Read(ctx, &c2.ReadAgentRequest{
		Agent:   &pb.Agent{Id: id},
		Filters: &c2.AgentFilters{MaxResults: 1},
	})
	if err != nil {
		return aims.CheckError(err)
	}

	match := findAgentByIDPrefix(res.GetAgents(), id)
	if match == nil {
		return fmt.Errorf("bring: no agent found with id %q (use the full id — short-id resolution is pending the agents List RPC)", id)
	}
	return writePayload(w, agentContextFromPB(match))
}

// findAgentByIDPrefix returns the first agent whose id starts with the given (already-trimmed)
// value, mirroring how `agents show` resolves a possibly-shortened id. It is the resolver bring
// will reuse unchanged once a List RPC returns the full agent set.
func findAgentByIDPrefix(agents []*pb.Agent, id string) *pb.Agent {
	for _, a := range agents {
		if a != nil && strings.HasPrefix(a.GetId(), id) {
			return a
		}
	}
	return nil
}

// agentContextFromPB maps a c2 agent into the flat context bring carries into the shell.
// writePayload sanitizes the values; only the id is authoritative (used for dispatch).
func agentContextFromPB(a *pb.Agent) agentContext {
	return agentContext{
		id:   a.GetId(),
		name: a.GetName(),
		tool: a.GetTool(),
		cwd:  a.GetWorkingDirectory(),
	}
}
