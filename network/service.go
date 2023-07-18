package network

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
	"strconv"
	"strings"

	"github.com/fatih/color"
	"github.com/maxlandon/aims/display"
	"github.com/maxlandon/aims/proto/host"
	"github.com/maxlandon/aims/proto/network"
	"github.com/maxlandon/gondor/maltego"
)

// Service - A service somewhere on a network.
// The type has several categories of fields: general information,
// and Nmap-compliant fields (fingerprints, protocols, banners, versions).
type Service network.Service

//
// General Functions
//

// ToORM - Get the SQL object for the Service.
func (s *Service) ToORM(ctx context.Context) (network.ServiceORM, error) {
	return (*network.Service)(s).ToORM(ctx)
}

// ToPB - Get the Protobuf object for the Service.
func (s *Service) ToPB() *network.Service {
	return (*network.Service)(s)
}

// AsEntity - Returns the Service as a valid Maltego Entity.
func (s *Service) AsEntity() maltego.Entity {
	return maltego.Entity{}
}

// TableHeaders returns all weighted table headers for a table of services/ports.
func Headers() (headers []display.Options) {
	add := func(n string, w int) {
		headers = append(headers, display.WithHeader(n, w))
	}

	add("Num", 1)
	add("Proto", 1) // Combined transport/application protocol when possible
	add("Product", 1)

	add("State", 1) // Combined or relevant port/service state
	add("Reason", 1)
	add("Method", 1)
	add("Extra Info", 1)

	// add("Info", 3)
	// add("ID", 3)

	return headers
}

// DetailHeaders returns the headers for a detailed service view.
func Details() []display.Options {
	var headers []display.Options
	add := func(n string, w int) {
		headers = append(headers, display.WithHeader(n, w))
	}

	// Core
	add("ID", 1)
	add("Num", 1)
	add("Proto", 1)
	add("Product", 1)

	add("State", 2)
	add("Reason", 2)
	add("Method", 2)

	// Network
	add("Extra Info", 3)
	add("Info", 3)
	// add("Hops", 3)
	// add("Route", 3) -- command-line flaag --traceroute

	// Tools
	// add("Comment", 4)
	// add("Hosts scripts", 5)

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
	add("Num", 1)
	add("Proto", 1)
	add("Product", 1)
	add("State", 1)

	return headers
}

// Fields maps field names to their value generators.
var Fields = map[string]func(port *host.Port) string{
	// Table
	"ID": func(port *host.Port) string {
		id := display.FormatSmallID(port.Id)

		if port.State == nil {
			return id
		}

		switch port.State.State {
		case "open":
			return color.HiGreenString(id)
		case "filtered":
			return color.HiYellowString(id)
		case "closed":
			return color.HiRedString(id)
		}

		return id
	},
	"Num": func(port *host.Port) string {
		return strconv.Itoa(int(port.Number))
	},
	"Proto": func(port *host.Port) string {
		proto := color.HiBlackString(port.Protocol)

		if port.Service == nil {
			return proto
		} else {
			proto = ""
		}

		if port.Service.Protocol != "" {
			proto += port.Service.Protocol
		} else if port.Service.Name != "" {
			proto += port.Service.Name
		}

		return proto
	},
	"Product": func(port *host.Port) string {
		product := port.Service.Product
		if port.Service.Version == "" {
			return product
		}
		product += color.HiBlackString(fmt.Sprintf(" (v%s)", port.Service.Version))
		return product
	},
	"Extra Info": func(port *host.Port) string {
		return port.Service.ExtraInfo
	},
	"Info": func(port *host.Port) string {
		if len(port.Scripts) == 0 {
			return port.Service.ExtraInfo
		}

		var scripts string
		for _, script := range port.Scripts {
			if script.Output == "" {
				continue
			}

			scripts += fmt.Sprintf("%s %s\n", script.Name, script.Output)
		}

		return strings.TrimSuffix(scripts, "\n")
	},
	"Fingerprint": func(port *host.Port) string {
		return port.Service.ServiceFP
	},

	"Method": func(port *host.Port) string {
		return color.HiBlackString(port.Service.Method)
	},
	"State": func(port *host.Port) string {
		if port.State == nil {
			return "unknown"
		}

		switch port.State.State {
		case "open":
			return color.HiGreenString("open")
		case "filtered":
			return color.HiYellowString("filtered")
		case "closed":
			return color.HiRedString("closed")
		}

		return port.State.State
	},
	"Reason": func(port *host.Port) string {
		return port.State.Reason
	},
}
