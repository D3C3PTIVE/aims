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

	host "github.com/d3c3ptive/aims/host/pb"
)

// User - A computer (login) user.
// This type will be closely related to the various aims/credential types.
type User host.User

//
// General Functions
//

// ToORM - Get the SQL object for the User.
func (u *User) ToORM(ctx context.Context) (host.UserORM, error) {
	return (*host.User)(u).ToORM(ctx)
}

// ToPB - Get the Protobuf object for the User.
func (u *User) ToPB() *host.User {
	return (*host.User)(u)
}

// AsEntity - Returns the User as a valid Maltego Entity.
func (u *User) AsEntity() maltego.Entity {
	return maltego.Entity{}
}
