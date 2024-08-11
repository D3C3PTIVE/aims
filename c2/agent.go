package c2

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
	"fmt"
	"strings"
	"sync"

	"github.com/fatih/color"
	"github.com/maxlandon/aims/display"
	"github.com/maxlandon/aims/proto/c2"
)

type Agent c2.Agent

//
// [ Display Functions ] --------------------------------------------------
//

// DisplayHeaders returns all weighted table headers for a table of.Agents.
func DisplayHeaders() (headers []display.Options) {
	add := func(n string, w int) {
		headers = append(headers, display.WithHeader(n, w))
	}

	add("ID", 1)
	add("Hostname", 1)
	add("OS Name", 1)
	add("OS Family", 1)
	add("Addresses", 1)

	add("Status", 2)
	add("Channels", 2)

	add("Arch", 3)
	add("MAC", 3)
	add("Purpose", 3)

	return headers
}

// DetailHeaders returns the headers for a detailed.Agent view.
func DisplayDetails() []display.Options {
	var headers []display.Options
	add := func(n string, w int) {
		headers = append(headers, display.WithHeader(n, w))
	}

	// Core
	add("ID", 1)
	add("OS Name", 1)
	add("OS Family", 1)
	add("Arch", 1)
	add("Status", 1)

	add("Purpose", 2)
	add("MAC", 2)
	add("Virtual.Agent", 2)

	// Network
	add("Hostnames", 3)
	add("Addresses", 3)
	add("Hops", 3)

	// Tools
	add("Comment", 4)
	add("Host scripts", 5)

	return headers
}

// Completions returns some columns to be combined into
// completion candidates and/or their descriptions.
func Completions() []display.Options {
	var headers []display.Options
	add := func(n string, w int) {
		headers = append(headers, display.WithHeader(n, w))
	}

	add("ID", 1)
	add("", 1)
	add("OS Name", 1)
	add("Addresses", 1)

	return headers
}

// Fields maps field names to their value generators.
var DisplayFields = map[string]func(h *c2.Agent) string{
	// Table
	"ID": func(h *c2.Agent) string {
		if h.Host.Status.State == "up" {
			return color.HiGreenString(display.FormatSmallID(h.Id))
		}
		return display.FormatSmallID(h.Id)
	},
	"Addresses": func(h *c2.Agent) string {
		var addresses []string
		for _, hn := range h.Host.Addresses {
			addresses = append(addresses, hn.Addr)
		}
		return strings.Join(addresses, "\n")
	},

	"Status": func(h *c2.Agent) string {
		return ""
	},
	"Hops": func(h *c2.Agent) string {
		if h.Host.Trace == nil {
			return ""
		}

		return fmt.Sprint(len(h.Host.Trace.Hops))
	},
	"MAC": func(h *c2.Agent) string { return h.Host.MAC },
	"Purpose": func(h *c2.Agent) string {
		if h.Host.OS == nil {
			return ""
		}
		// Look at OS matches for various types.
		// Don't include them all, just 2/3 more recurring ones.
		if h.Host.Purpose != "" {
			return h.Host.Purpose
		}

		times := map[string]int{}

		for _, m := range h.Host.OS.Matches {
			for _, c := range m.Classes {
				println(c.Type)
				if c.Type != "" {
					times[c.Type]++
				}
			}
		}

		var purposes []string
		for name, times := range times {
			typeStr := name + display.Dim + fmt.Sprintf("(%d)", times)
			purposes = append(purposes, typeStr)
		}

		return strings.Join(purposes, " | ")
	},

	// Details
	"Route": func(h *c2.Agent) string {
		if h.Host.Trace == nil {
			return ""
		}

		routes := "\n" + display.Reset

		for i := len(h.Host.Trace.Hops) - 1; i >= 0; i-- {
			hop := h.Host.Trace.Hops[i]
			line := display.Dim + "  |_ "
			rtt := display.Dim + fmt.Sprintf("%*s", 6, hop.RTT) + display.Reset
			ipPad := fmt.Sprintf("%*s  ", 18, hop.IPAddr)
			line += rtt + ipPad + display.Bold + display.FgYellow + hop.Host + display.Reset
			routes += line + "\n"
		}

		return strings.TrimSuffix(routes, "\n")
	},
}

// FilterIdentical returns a list of.Agents from which have been removed all.Agents that are
// already in the database, with a very high degree of certitude. This avoids redundance when
// manipulating new.Agents.
func FilterIdenticalAgent(raw []c2.AgentORM, dbHosts []*c2.AgentORM) (filtered []c2.AgentORM) {
	// For each.Agent to add:
	for _, newAgent := range raw {
		done := new(sync.WaitGroup)

		allMatches := []*c2.AgentORM{}

		// Check IDs: if non-nil and identical, done checking.

		// For now we wait for all queries to finish, but ideally,
		// some filters have more weight than others, but might be
		// longer to check, so when one shows that.Agents are identical,
		// all other comparison routines should break.
		done.Wait()

		// If identical, add it to the valid, filtered.Agents
		if identical, _ := allAgentsIdentical(allMatches); identical {
			filtered = append(filtered, newAgent)
		}

	}

	return
}

func allAgentsIdentical(all []*c2.AgentORM) (yes bool, matches int) {
	return false, 0
}
