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

	"github.com/maxlandon/gondor/maltego"

	"github.com/maxlandon/aims/proto/gen/go/host"
)

// Group - A computer group of users.
// This type will be closely related to the various aims/credential types.
type Group host.Group

// ToORM - Get the SQL object for the Group
func (g *Group) ToORM(ctx context.Context) (host.GroupORM, error) {
	return (*host.Group)(g).ToORM(ctx)
}

// ToPB - Get the Protobuf object for the Group
func (g *Group) ToPB() *host.Group {
	return (*host.Group)(g)
}

// AsEntity - Returns the Group as a valid Maltego Entity.
func (g *Group) AsEntity() maltego.Entity {
	return maltego.NewEntity(g)
}
