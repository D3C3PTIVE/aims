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
	"github.com/maxlandon/gondor/maltego"

	"github.com/d3c3ptive/aims/cmd/display"
	"github.com/d3c3ptive/aims/proto/host"
	"github.com/d3c3ptive/aims/proto/network"
	"github.com/d3c3ptive/aims/proto/scan/nmap"
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
	add("Version", 1)

	add("State", 2)
	add("Reason", 2)
	add("Method", 2)

	// Network
	add("Device type", 2)
	add("Info", 3)
	add("Extra Info", 3)

	// Tools
	add("Scripts", 4)
	add("Fingerprint", 4)

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

// DisplayFields maps field names to their value generators.
var DisplayFields = map[string]func(port *host.Port) string{
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
	"Version": func(port *host.Port) string {
		serv := port.Service
		version := port.Service.Version
		if serv.HighVersion != "" && serv.LowVersion != "" {
			version += color.HiBlackString(" (%s / %s)", serv.LowVersion, serv.HighVersion)
		}
		return version
	},
	"Info": func(port *host.Port) string {
		if len(port.Scripts) == 0 {
			return port.Service.ExtraInfo
		}

		var scripts string
		for _, script := range port.Scripts {
			name := script.Name
			if script.Output == "" && script.Name == "" {
				continue
			}
			scripts += fmt.Sprintf("(%s) %s\n", name, script.Output)
		}

		return strings.TrimSuffix(scripts, "\n")
	},
	"Extra Info": func(port *host.Port) string {
		return port.Service.ExtraInfo
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
	"Scripts": func(port *host.Port) string {
		scripts := ""
		for _, script := range port.Scripts {
			scripts += printScript(script, 0)
		}

		return scripts
	},
}

// Recursive function to print a ScriptORM object with nested structures
func printScript(script *nmap.Script, indentLevel int) string {
	buf := new(strings.Builder)
	indent := strings.Repeat("  ", indentLevel)

	name := script.Name
	if name == "" {
		name = script.Id
	}
	fmt.Fprintf(buf, "\n%sName: %s\n", indent, color.HiBlueString(name))
	if script.Output != "" {
		fmt.Fprintf(buf, "%sOutput: %s\n", indent, script.Output)
	}

	// Print Elements
	if len(script.Elements) > 0 {
		fmt.Fprintf(buf, "%sElements:\n", indent)
		for _, element := range script.Elements {
			fmt.Fprintf(buf, "%s %s : %s\n", indent, element.Key, element.Value)
		}
	}

	// Print Tables and their rows
	if len(script.Tables) > 0 {
		fmt.Printf("%sTables:\n", indent)
		for _, table := range script.Tables {
			printTable(table, indentLevel+1, buf)
		}
	}

	return buf.String()
}

// Recursive function to print a TableORM object with nested rows
func printTable(table *nmap.Table, indentLevel int, buf *strings.Builder) {
	indent := strings.Repeat("  ", indentLevel)
	fmt.Fprintf(buf, "%s %s\n", indent, table.Key)

	// Print rows
	if len(table.Elements) > 0 {
		for _, element := range table.Elements {
			fmt.Fprintf(buf, "%s %s : %s\n", indent, element.Key, element.Value)
		}
	}

	if len(table.Tables) > 0 {
		printTable(table, indentLevel+1, buf)
	}
}
