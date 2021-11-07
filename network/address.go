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

	"github.com/maxlandon/aims/proto/gen/go/network"
	"github.com/maxlandon/gondor/maltego"
)

// Address - An address somewhere on a network, or on a host.
// Can be an IPv4/v6 address, a MAC address, or else.
// This type has fields that are compliant with Nmap scan schemas.
type Address network.Address

//
// General Functions
//

// ToORM - Get the SQL object for the Host
func (a *Address) ToORM(ctx context.Context) (network.AddressORM, error) {
	return (*network.Address)(a).ToORM(ctx)
}

// ToPB - Get the Protobuf object for the Host
func (a *Address) ToPB(ctx context.Context) *network.Address {
	return (*network.Address)(a)
}

// AsEntity - Returns the Address as a valid Maltego Entity.
func (a *Address) AsEntity() maltego.Entity {
	return maltego.Entity{}
}
