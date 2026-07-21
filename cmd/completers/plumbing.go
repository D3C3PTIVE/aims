package completers

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

// This file holds the shared plumbing every value-typed completer wears: the panic guard, the
// agent-scoped cache + connect wrapper, the host-set read specialisation, and the tag→groups
// render tail. It is the scanner-agnostic substrate the value completers (values.go) are built on,
// lifted here so any command — not just the scanners — can borrow them.

import (
	"context"

	"github.com/carapace-sh/carapace"

	"github.com/d3c3ptive/aims/client"
	aims "github.com/d3c3ptive/aims/cmd"
	"github.com/d3c3ptive/aims/cmd/agentctx"
	pb "github.com/d3c3ptive/aims/host/pb"
	hostrpc "github.com/d3c3ptive/aims/host/pb/rpc"
)

// Guard wraps a completion callback so a panic degrades to a visible carapace message instead of
// crashing the exec-once `_carapace` subprocess — which the shell experiences as completion hanging
// with no output. The message also surfaces the failure (with its location in the panic text) so it
// can be diagnosed rather than silently swallowed. label names the completer for the message.
func Guard(label string, fn carapace.CompletionCallback) carapace.CompletionCallback {
	return func(c carapace.Context) (action carapace.Action) {
		defer func() {
			if r := recover(); r != nil {
				action = carapace.ActionMessage("%s completion panicked: %v", label, r)
			}
		}()
		return fn(c)
	}
}

// listCompleter is the shared cache + panic-guard + connect shell every DB-backed completer wears:
// an on-disk cache (read once, filter many), a Guard so a panic degrades to a visible message
// instead of hanging `_carapace`, and the teamclient connect. body does the actual read + render —
// it only runs on a cache miss with a live connection, never touching the DB directly.
func listCompleter(con *client.Client, name, label string, body func() carapace.Action) carapace.Action {
	return aims.CacheCompletion(con, name, carapace.ActionCallback(Guard(label, func(_ carapace.Context) carapace.Action {
		if msg, err := con.ConnectComplete(); err != nil {
			return msg
		}
		return body()
	})))
}

// cachedCompleter specialises listCompleter for agent-scoped completers: the loaded agent id is
// folded into the cache name so a different context is a distinct entry (the host-set completers
// render relevance relative to the loaded agent's host).
func cachedCompleter(con *client.Client, name, label string, body func() carapace.Action) carapace.Action {
	if ctx, ok := agentctx.Current(); ok {
		name += ":" + ctx.ID
	}
	return listCompleter(con, name, label, body)
}

// CachedList is the exported, generic shell for a plain DB-backed list completer — the one the
// per-domain ID completers (hosts, services, credentials, scans, agents, channels) share. It folds
// the cache + Guard + connect boilerplate each of them used to hand-roll (and, crucially, gives them
// the panic Guard they previously lacked). read runs only on a cache miss with a live connection and
// returns the domain objects; an error becomes a visible message, an empty result short-circuits to
// emptyMsg, otherwise render turns the objects into the candidate action (its own Tag/style/order).
func CachedList[T any](con *client.Client, name, label, emptyMsg string, read func() ([]T, error), render func([]T) carapace.Action) carapace.Action {
	return listCompleter(con, name, label, func() carapace.Action {
		items, err := read()
		if err = aims.CheckError(err); err != nil {
			return carapace.ActionMessage("Error: %s", err)
		}
		if len(items) == 0 {
			return carapace.ActionMessage(emptyMsg)
		}
		return render(items)
	})
}

// FilterSelected wraps a completer so already-typed positional args are dropped from its candidates.
// The filter runs per-invocation OUTSIDE the static cache key (which CachedList owns), so a cached
// read is still reused across keystrokes while the selected-args elision stays live. It is the
// shared tail the scan completers (CompleteByID, CompleteSeriesHead) used to inline.
func FilterSelected(a carapace.Action) carapace.Action {
	return carapace.ActionCallback(func(c carapace.Context) carapace.Action {
		return a.Filter(c.Args...)
	})
}

// cachedHostCompleter specialises cachedCompleter for the host-set-backed completers (targets, ports,
// URLs, domains): it does the Hosts.Read with the given filters and resolves the agent host once,
// then hands both to render. emptyHostsMsg, when non-empty, short-circuits an empty database with
// that message; pass "" to let render own the empty case (e.g. groupedPorts says "no ports known").
func cachedHostCompleter(con *client.Client, name, label string, filters *hostrpc.HostFilters, emptyHostsMsg string, render func(hosts []*pb.Host, agentHost *pb.Host) carapace.Action) carapace.Action {
	return cachedCompleter(con, name, label, func() carapace.Action {
		res, err := con.Hosts.Read(context.Background(), &hostrpc.ReadHostRequest{Host: &pb.Host{}, Filters: filters})
		if err = aims.CheckError(err); err != nil {
			return carapace.ActionMessage("Error: %s", err)
		}
		if emptyHostsMsg != "" && len(res.GetHosts()) == 0 {
			return carapace.ActionMessage(emptyHostsMsg)
		}
		agentHost, _ := agentctx.CurrentHost(con)
		return render(res.GetHosts(), agentHost)
	})
}

// renderGroups turns tag→(value, description…) buckets into a batched action — one tagged carapace
// group per tag in order, empty groups skipped, each group passed through the optional decorate funcs
// (e.g. a NoSpace). When nothing rendered it returns emptyMsg as an ActionMessage, or an empty action
// when emptyMsg is "" (so the group contributes nothing to a shared slot). This is the shared tail of
// every grouped completer (targets, ports, subnets, URLs, domains).
func renderGroups(order []string, buckets map[string][]string, emptyMsg string, decorate ...func(carapace.Action) carapace.Action) carapace.Action {
	actions := make([]carapace.Action, 0, len(order))
	for _, tag := range order {
		pairs := buckets[tag]
		if len(pairs) == 0 {
			continue
		}
		a := carapace.ActionValuesDescribed(pairs...).Tag(tag)
		for _, d := range decorate {
			a = d(a)
		}
		actions = append(actions, a)
	}
	if len(actions) == 0 {
		if emptyMsg == "" {
			return carapace.ActionValues()
		}
		return carapace.ActionMessage(emptyMsg)
	}
	return carapace.Batch(actions...).ToA()
}
