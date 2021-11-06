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

// User - A computer (login) user.
// This type will be closely related to the various aims/credential types.
type User struct {
	*host.User
}

// NewUser - Create a new aims.User with its embedded Protobuf type.
func NewUser() *User {
	return &User{
		User: &host.User{},
	}
}

// UserFromPB - Get a User from its Protobuf equivalent.
func UserFromPB(pb *host.User) *User {
	return &User{User: pb}
}

// AsEntity - Returns the User as a valid Maltego Entity.
func (u *User) AsEntity() maltego.Entity {
	return maltego.Entity{}
}
