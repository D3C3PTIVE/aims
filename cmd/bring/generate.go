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
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"

	pb "github.com/d3c3ptive/aims/c2/pb"
	c2 "github.com/d3c3ptive/aims/c2/pb/rpc"
	"github.com/d3c3ptive/aims/client"
	aims "github.com/d3c3ptive/aims/cmd"
	hostpb "github.com/d3c3ptive/aims/host/pb"
	networkpb "github.com/d3c3ptive/aims/network/pb"
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
// writePayload sanitizes the values; only the id is authoritative (used for dispatch). The pending
// count and route are point-in-time snapshots (like the other display fields) — they go stale as
// tasks complete or the network path changes; a live figure would need a re-query.
func agentContextFromPB(a *pb.Agent) agentContext {
	pending := a.GetTasksCount() - a.GetTasksCountCompleted()
	if pending < 0 {
		pending = 0
	}
	return agentContext{
		id:      a.GetId(),
		name:    a.GetName(),
		tool:    a.GetTool(),
		cwd:     a.GetWorkingDirectory(),
		pending: strconv.FormatInt(pending, 10),
		route:   compactRoute(a.GetHost()),
	}
}

// compactRoute renders a terse, prompt-sized summary of the network path to the agent's host: the
// hop distance and the last gateway before the target — e.g. "3h·10.0.0.1" (or "3h·gw01" when the
// gateway resolves to a name). It reads the host's preloaded Trace/Distance, so the c2 Read must
// preload Host.Trace.Hops and Host.Distance (see server/c2.Preloads); it returns "" when no route
// information is available, so the prompt shows nothing rather than an empty marker. The result is
// display data — writePayload sanitizes it like every other value.
func compactRoute(h *hostpb.Host) string {
	if h == nil {
		return ""
	}
	hops := h.GetTrace().GetHops()

	// Prefer nmap's reported distance; fall back to the number of recorded hops.
	dist := int(h.GetDistance().GetValue())
	if dist == 0 {
		dist = len(hops)
	}
	if dist == 0 {
		return "" // no trace and no distance — nothing useful to show
	}

	seg := strconv.Itoa(dist) + "h"
	if gw := lastGateway(hops); gw != "" {
		seg += "·" + gw
	}
	return seg
}

// lastGateway returns the hop just before the target — the final gateway on the path — preferring
// its resolved host name over its IP. Hops are ordered nearest-to-target, so the target itself is
// the last entry and the gateway is the penultimate one; a single-hop (directly adjacent) path has
// no intermediate gateway and yields "".
func lastGateway(hops []*networkpb.Hop) string {
	if len(hops) < 2 {
		return ""
	}
	gw := hops[len(hops)-2]
	if name := gw.GetHost(); name != "" {
		return name
	}
	return gw.GetIPAddr()
}
