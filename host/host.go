package host

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
	"strings"

	"github.com/maxlandon/aims/display"
	"github.com/maxlandon/aims/proto/host"
	"github.com/maxlandon/gondor/maltego"
)

// Host - A physical or virtual computer host.
// The type has several categories of fields: general information,
// and Nmap-compliant fields (ports, status, route, scripts etc).
type Host host.Host

//
// [ General Functions ] --------------------------------------------------
//

// ToORM - Get the SQL object for the Host.
func (h *Host) ToORM(ctx context.Context) (host.HostORM, error) {
	return (*host.Host)(h).ToORM(ctx)
}

// ToPB - Get the Protobuf object for the Host.
func (h *Host) ToPB() *host.Host {
	return (*host.Host)(h)
}

// AsEntity - Returns the Host as a valid Maltego Entity.
func (h *Host) AsEntity() maltego.Entity {
	return maltego.Entity{}
}

//
// [ Display Functions ] --------------------------------------------------
//

// Table returns the headers and their row contents from a list of network services.
func Table(hosts ...*host.Host) (headers []string, rows [][]string) {
	// Headers
	headers = append(headers, []string{
		"Id",
		"Hostnames",
		"OSName",
		"OSFamily",
		"Arch",
		"Addresses",
		"Status",
	}...)

	for _, h := range hosts {
		var row []string

		// ID & Naming
		row = append(row, display.FormatSmallID(h.Id))

		var hostnames []string
		for _, hn := range h.Hostnames {
			hostnames = append(hostnames, hn.Name)
		}
		row = append(row, strings.Join(hostnames, "\n"))

		// OS Information determination.
		var osName, osFamily string
		osName, osFamily = h.OSName, h.OSFamily
		row = append(row, osName, osFamily)

		// Hardware
		row = append(row, h.Arch)

		// Addressing
		var addresses []string
		for _, hn := range h.Addresses {
			addresses = append(addresses, hn.Addr.Value)
		}
		row = append(row, strings.Join(addresses, "\n"))

		// Status
		row = append(row, h.Status.State)

		rows = append(rows, row)
	}

	return
}

// Details prints a detailed information page for a given host.
func Details(h *host.Host) (details string) {
	return
}
