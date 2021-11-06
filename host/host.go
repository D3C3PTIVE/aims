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
	"github.com/maxlandon/aims/proto/gen/go/host"
	"github.com/maxlandon/gondor/maltego"
)

// Host - A physical or virtual computer host.
// The type has several categories of fields: general information,
// and Nmap-compliant fields (ports, status, route, scripts etc).
type Host struct {
	*host.Host
}

// NewHost - Creates a new aims.Host with its embedded Protobuf type.
func NewHost() *Host {
	return &Host{
		Host: &host.Host{},
	}
}

// HostFromPB - Get a Host from its Protobuf equivalent.
func HostFromPB(pb *host.Host) *Host {
	return &Host{Host: pb}
}

// AsEntity - Returns the Host as a valid Maltego Entity.
func (h *Host) AsEntity() maltego.Entity {
	return maltego.Entity{}
}
