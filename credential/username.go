package credential

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

	"github.com/maxlandon/aims/proto/gen/go/credential"
)

// Username - A public credential in the form of a Username .
type Username Public

// NewUsername - Create a new Username Public credential.
// Using this type ensures that its .Username field is not
// nil when saved into DB by default.
func NewUsername() *Username {
	h := Username(Public{})
	h.Type = credential.PublicType_Username
	return &h
}

//
// General Functions
//

// ToORM - Get the SQL object for the Username credential.
func (h *Username) ToORM(ctx context.Context) (credential.PublicORM, error) {
	h.Type = credential.PublicType_Username
	return (*Public)(h).ToORM(ctx)
}

// ToPB - Get the Protobuf object for the Username credential.
func (h *Username) ToPB() *credential.Public {
	h.Type = credential.PublicType_Username
	return (*Public)(h).ToPB()
}

// AsEntity - Returns the Public as a valid Maltego Entity.
func (h *Username) AsEntity() maltego.Entity {
	// e:= maltego.NewEntity(h)
	// base := (*Public)(h).AsEntity()
	// e.SetBase(base)
	// return e
	return maltego.NewEntity(h)
}
