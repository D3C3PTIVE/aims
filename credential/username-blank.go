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

	"github.com/d3c3ptive/aims/proto/credential"
)

// BlankUsername - A public credential in the form of a Username.
// Note that upon saving this object in DB, any .Username value
// will be replaced by an empty string.
type BlankUsername Public

// NewBlankUsername - Create a new BlankUsername Public credential.
// Using this type ensures that its .Username field is nil when saved.
func NewBlankUsername() *BlankUsername {
	h := BlankUsername(Public{})
	h.Type = credential.PublicType_BlankUsername
	return &h
}

//
// General Functions
//

// ToORM - Get the SQL object for the BlankUsername credential.
func (u *BlankUsername) ToORM(ctx context.Context) (credential.PublicORM, error) {
	u.Type = credential.PublicType_BlankUsername
	u.Username = ""
	return (*Public)(u).ToORM(ctx)
}

// ToPB - Get the Protobuf object for the BlankUsername credential.
func (u *BlankUsername) ToPB() *credential.Public {
	u.Type = credential.PublicType_BlankUsername
	u.Username = ""
	return (*Public)(u).ToPB()
}

// AsEntity - Returns the Public as a valid Maltego Entity.
func (u *BlankUsername) AsEntity() maltego.Entity {
	// e:= maltego.NewEntity(h)
	// base := (*Public)(h).AsEntity()
	// e.SetBase(base)
	// return e
	return maltego.NewEntity(u)
}
