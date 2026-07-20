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
	"time"

	"github.com/fatih/color"

	c2 "github.com/d3c3ptive/aims/c2/pb"
	"github.com/d3c3ptive/aims/cmd/display"
	"github.com/d3c3ptive/aims/internal/util"
)

// Channel represents a C2 communication channel (transport).
type Channel c2.Channel

//
// [ Display Functions ] --------------------------------------------------
//

// DisplayHeaders returns all weighted table headers for a table of.Channels.
func DisplayHeadersChannel() []display.Options {
	return display.Headers().
		Add("Order", 1).
		Add("ID", 1).
		Add("Connection", 1).
		Add("Try/Fails", 1).
		Add("Beaconing", 1).
		Add("Last/Next Check-in", 1).
		Add("Proxy", 1).
		Options()
}

// DetailHeaders returns the headers for a detailed.Channel view.
func DisplayDetailsChannel() []display.Options {
	return display.Headers().
		// Core
		Add("Order", 1).
		Add("ID", 1).
		Add("Connection", 1).
		Add("Protocol", 1).
		// Health & cadence
		Add("Try/Fails", 2).
		Add("Beaconing", 2).
		Add("Last/Next Check-in", 2).
		// Routing
		Add("Proxy", 3).
		Options()
}

// Completions returns some columns to be combined into
// completion candidates and/or their descriptions.
func CompletionsChannel() []display.Options {
	return display.Headers().
		Add("ID", 1).
		Add("Connection", 1).
		Add("Protocol", 1).
		Options()
}

// Fields maps field names to their value generators.
var DisplayFieldsChannel = map[string]func(h *c2.Channel) string{
	// Table
	"Order": func(h *c2.Channel) string {
		return color.HiBlackString(fmt.Sprintf("%d", h.Order))
	},
	"ID": func(h *c2.Channel) string {
		if h.Running {
			return color.HiGreenString(display.FormatSmallID(h.Id))
		}
		return display.FormatSmallID(h.Id)
	},
	"Protocol": func(h *c2.Channel) string {
		return h.Protocol
	},
	"Connection": func(h *c2.Channel) string {
		direction := ""
		if strings.ToLower(h.Direction) == "bind" {
			direction = "==>"
		} else {
			direction = "<=="
		}

		return fmt.Sprintf("%s %s %s", h.LocalAddress, direction, h.RemoteAddress)
	},
	"Try/Fails": func(h *c2.Channel) string {
		tries := fmt.Sprintf("%d", h.Attempts)
		failures := fmt.Sprintf("%d", h.Failures)
		if h.Failures > 0 {
			return color.HiRedString(fmt.Sprintf("%d", h.Failures))
		}
		return fmt.Sprintf("%s/%s", tries, failures)
	},
	"Beaconing": func(h *c2.Channel) string {
		if strings.ToLower(h.Type) == "session" {
			return color.HiBlackString("none")
		}

		stats := fmt.Sprintf("%s (+/-%s)", time.Duration(h.Interval).String(), time.Duration(h.Jitter).String())
		return stats
	},
	"Last/Next Check-in": func(h *c2.Channel) string {
		last := time.Unix(h.LastCheckin, 0)
		next := time.Unix(h.NextCheckin, 0)
		lastTime := util.FormatDateDelta(last, false, false)
		nextTime := util.FormatDateDelta(next, false, true)
		return fmt.Sprintf("%s/%s", lastTime, nextTime)
	},
	"Proxy": func(h *c2.Channel) string {
		return h.ProxyURL
	},
}

// ActiveChannelFor returns the first active channel for a given agent.
func ActiveChannelFor(agent *c2.Agent) *c2.Channel {
	for _, channel := range agent.Channels {
		if channel.Running {
			return channel
		}
	}

	return nil
}

// FilterIdentical returns a list of.Channels from which have been removed all.Channels that are
// already in the database, with a very high degree of certitude. This avoids redundance when
// manipulating new.Channels.
func FilterIdenticalChannel(raw []c2.ChannelORM, dbHosts []*c2.ChannelORM) (filtered []c2.ChannelORM) {
	// For each.Channel to add:
	for _, newChannel := range raw {
		done := new(sync.WaitGroup)

		allMatches := []*c2.ChannelORM{}

		// Check IDs: if non-nil and identical, done checking.

		// For now we wait for all queries to finish, but ideally,
		// some filters have more weight than others, but might be
		// longer to check, so when one shows that.Channels are identical,
		// all other comparison routines should break.
		done.Wait()

		// If identical, add it to the valid, filtered.Channels
		if identical, _ := allChannelsIdentical(allMatches); identical {
			filtered = append(filtered, newChannel)
		}

	}

	return
}

func allChannelsIdentical(all []*c2.ChannelORM) (yes bool, matches int) {
	return false, 0
}
