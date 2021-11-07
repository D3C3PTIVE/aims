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

// PostgresMD5 - A credential.Private.PasswordHash password hash that can be
// credential.Private.ReplayableHash replayed to authenticate to PostgreSQL
// servers. It is composed of a hexadecimal string of 32 characters prepended
// by the string 'md5'
type PostgresMD5 Private

// NewPostgresMD5 - Create a new PostgreSQL MD5 Credential and its embedded Protobuf type.
func NewPostgresMD5() *PostgresMD5 {
	md := PostgresMD5(Private{})
	md.Type = credential.PrivateType_PostgresMD5
	return &md
}

//
// General Functions
//

// ToORM - Get the SQL object for the PostgresMD5 credential.
func (p *PostgresMD5) ToORM(ctx context.Context) (credential.PrivateORM, error) {
	return (*Private)(p).ToORM(ctx)
}

// ToPB - Get the Protobuf object for the PostgresMD5 credential.
func (p *PostgresMD5) ToPB(ctx context.Context) *credential.Private {
	return (*Private)(p).ToPB(ctx)
}

// AsEntity - Returns the Private as a valid Maltego Entity.
func (p *PostgresMD5) AsEntity() maltego.Entity {
	// e:= maltego.NewEntity(h)
	// base := (*Private)(p).AsEntity()
	// e.SetBase(base)
	// return e
	return maltego.NewEntity(p)
}
