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
	"sync"

	"github.com/fatih/color"
	"github.com/maxlandon/aims/display"
	"github.com/maxlandon/aims/proto/c2"
)

type Channel c2.Channel

//
// [ Display Functions ] --------------------------------------------------
//

// DisplayHeaders returns all weighted table headers for a table of.Channels.
func DisplayHeadersChannel() (headers []display.Options) {
	add := func(n string, w int) {
		headers = append(headers, display.WithHeader(n, w))
	}

	add("ID", 1)
	add("Address", 1)

	add("Status", 2)

	add("Arch", 3)
	add("MAC", 3)
	add("Purpose", 3)

	return headers
}

// DetailHeaders returns the headers for a detailed.Channel view.
func DisplayDetailsChannel() []display.Options {
	var headers []display.Options
	add := func(n string, w int) {
		headers = append(headers, display.WithHeader(n, w))
	}

	// Core
	add("ID", 1)
	add("Status", 1)

	// Network
	add("Remote Address", 3)
	add("Hops", 3)

	// Tools
	add("Comment", 4)
	add("Host scripts", 5)

	return headers
}

// Completions returns some columns to be combined into
// completion candidates and/or their descriptions.
func CompletionsChannel() []display.Options {
	var headers []display.Options
	add := func(n string, w int) {
		headers = append(headers, display.WithHeader(n, w))
	}

	add("ID", 1)
	add("Remote Address", 1)
	add("State", 1)

	return headers
}

// Fields maps field names to their value generators.
var DisplayFieldsChannel = map[string]func(h *c2.Channel) string{
	// Table
	"ID": func(h *c2.Channel) string {
		if h.Running {
			return color.HiGreenString(display.FormatSmallID(h.Id))
		}
		return display.FormatSmallID(h.Id)
	},
	"Remote Address ": func(h *c2.Channel) string {
		return h.RemoteAddress
	},
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
