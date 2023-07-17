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

	"github.com/maxlandon/aims/proto/credential"
)

// Public - A Publicly disclosed credential, like a username or a public key.
// NOTE: By default, a credential.Public is of Type Username, and any blank
// Public.Username field value will be treated as incorrect.
type Public credential.Public

//
// General Functions
//

// ToORM - Get the SQL object for the Public credential.
func (p *Public) ToORM(ctx context.Context) (credential.PublicORM, error) {
	return (*credential.Public)(p).ToORM(ctx)
}

// ToPB - Get the Protobuf object for the Public credential.
func (p *Public) ToPB() *credential.Public {
	return (*credential.Public)(p)
}

// AsEntity - Returns the Public as a valid Maltego Entity.
func (p *Public) AsEntity() maltego.Entity {
	return maltego.NewEntity(p)
}
