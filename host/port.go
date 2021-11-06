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

// Port - A port on a Host.
// The type has several categories of fields: general information,
// and Nmap-compliant fields (status, owner, service, scripts etc).
type Port struct {
	*host.Port
}

// NewPort - Create a new aims.Port with its embedded Protobuf type.
func NewPort() *Port {
	return &Port{
		Port: &host.Port{},
	}
}

// PortFromPB - Get a Port from its Protobuf equivalent.
func PortFromPB(pb *host.Port) *Port {
	return &Port{Port: pb}
}

// AsEntity - Returns the Port as a valid Maltego Entity.
func (p *Port) AsEntity() maltego.Entity {
	return maltego.Entity{}
}
