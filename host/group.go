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

// Group - A computer group of users.
// This type will be closely related to the various aims/credential types.
type Group struct {
	*host.Group
}

// NewGroup - Create a new aims.Group with its embedded Protobuf type.
func NewGroup() *Group {
	return &Group{
		Group: &host.Group{},
	}
}

// GroupFrom - Get a Group from its Protobuf equivalent.
func GroupFrom(pb *host.Group) *Group {
	return &Group{Group: pb}
}

// AsEntity - Returns the Group as a valid Maltego Entity.
func (u *Group) AsEntity() maltego.Entity {
	return maltego.Entity{}
}
