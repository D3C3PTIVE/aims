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
	"github.com/maxlandon/aims/proto/gen/go/network"
	"github.com/maxlandon/gondor/maltego"
)

// Address - An address somewhere on a network, or on a host.
// Can be an IPv4/v6 address, a MAC address, or else.
// This type has fields that are compliant with Nmap scan schemas.
type Address struct {
	*network.Address
}

// NewAddress - Creates a new aims.Address with its embedded Protobuf type.
func NewAddress() *Address {
	return &Address{
		Address: &network.Address{},
	}
}

// AddressFromPB - Get an Address from its Protobuf equivalent.
func AddressFromPB(pb *network.Address) *Address {
	return &Address{Address: pb}
}

// AsEntity - Returns the Address as a valid Maltego Entity.
func (a *Address) AsEntity() maltego.Entity {
	return maltego.Entity{}
}
