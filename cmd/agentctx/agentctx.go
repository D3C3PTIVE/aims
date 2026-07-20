package agentctx

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

// Package agentctx exposes the currently loaded agent context to client-side code (completions
// above all). There is no in-process "current agent" state: `aims bring` exports the context into
// the shell environment, and a completion runs as a child of that shell, so the environment is the
// source of truth. Current() is a pure, cheap env read; CurrentHost resolves the agent to the host
// it runs on — the base for context-aware completion.

import (
	"context"
	"os"
	"strconv"

	"github.com/d3c3ptive/aims/client"
	agentpb "github.com/d3c3ptive/aims/c2/pb"
	c2rpc "github.com/d3c3ptive/aims/c2/pb/rpc"
	hostpb "github.com/d3c3ptive/aims/host/pb"
	hostrpc "github.com/d3c3ptive/aims/host/pb/rpc"
)

// Environment variable names — these MUST match the ones the bring() shell function exports
// (cmd/bring/shell/templates/*.tmpl). Reading them here is the only way client code learns the
// current context.
const (
	EnvID      = "AIMS_AGENT_ID"
	EnvName    = "AIMS_AGENT_NAME"
	EnvTool    = "AIMS_AGENT_TOOL"
	EnvCwd     = "AIMS_AGENT_CWD"
	EnvRoute   = "AIMS_AGENT_ROUTE"
	EnvPending = "AIMS_AGENT_PENDING"
	EnvDepth   = "AIMS_CONTEXT_DEPTH"
)

// Context is the loaded agent context, a cheap snapshot read straight from the environment that
// `aims bring` populated — no server round-trip. ID is the only field guaranteed present; the rest
// are the display snapshot bring emits.
type Context struct {
	ID      string
	Name    string
	Tool    string
	Cwd     string
	Route   string
	Pending string
	Depth   int
}

// Current returns the loaded agent context from the environment, and false when none is loaded (no
// AIMS_AGENT_ID). Pure and allocation-cheap: safe to call on every completion keystroke.
func Current() (Context, bool) {
	id := os.Getenv(EnvID)
	if id == "" {
		return Context{}, false
	}
	depth, _ := strconv.Atoi(os.Getenv(EnvDepth))
	return Context{
		ID:      id,
		Name:    os.Getenv(EnvName),
		Tool:    os.Getenv(EnvTool),
		Cwd:     os.Getenv(EnvCwd),
		Route:   os.Getenv(EnvRoute),
		Pending: os.Getenv(EnvPending),
		Depth:   depth,
	}, true
}

// CurrentHost resolves the loaded agent to the host it runs on — the anchor for context-aware
// completion — and returns false when no context is loaded or it can't be resolved. It reads the
// agent (for its Host id) then the full host (with addresses/ports/trace), both over the teamclient
// RPC, never the DB directly. Best-effort: any error yields (nil, false) so callers degrade to the
// context-free path. The client must already be connected (call con.ConnectComplete first).
func CurrentHost(con *client.Client) (*hostpb.Host, bool) {
	ctx, ok := Current()
	if !ok {
		return nil, false
	}

	ares, err := con.Agents.Read(context.Background(), &c2rpc.ReadAgentRequest{
		Agent: &agentpb.Agent{Id: ctx.ID},
	})
	if err != nil {
		return nil, false
	}

	var hostID string
	for _, a := range ares.GetAgents() {
		if a.GetId() == ctx.ID {
			hostID = a.GetHost().GetId()
			break
		}
	}
	if hostID == "" {
		return nil, false
	}

	hres, err := con.Hosts.Read(context.Background(), &hostrpc.ReadHostRequest{
		Host:    &hostpb.Host{Id: hostID},
		Filters: &hostrpc.HostFilters{Ports: true, Trace: true},
	})
	if err != nil {
		return nil, false
	}
	for _, h := range hres.GetHosts() {
		if h.GetId() == hostID {
			return h, true
		}
	}
	return nil, false
}
