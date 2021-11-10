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

// Password - A credential.Private password.
// NOTE: A blank password is considered invalid if BOTH 1) the Password.Type is not
// set to credential.PrivateType_BlankPassword and 2) the Password.Data is "". This
// will throw a validation error when saving the password to DB. If you want to save
// an empty password, you MUST change the .Type to PrivateType_BlankPassword.
// NOTE: Please instantiate a new Password with NewPassword().
type Password Private

// NewPassword - Create a new Password Credential.
func NewPassword() *Password {
	p := Password(Private{})
	p.Type = credential.PrivateType_Password
	return &p
}

//
// General Functions
//

// ToORM - Get the SQL object for the Password credential.
// NOTE: A blank password is considered invalid if BOTH 1) the Password.Type is not
// set to credential.PrivateType_BlankPassword and 2) the Password.Data is "". This
// will throw a validation error when saving the password to DB. If you want to save
// an empty password, you MUST change the .Type to PrivateType_BlankPassword.
func (p *Password) ToORM(ctx context.Context) (credential.PrivateORM, error) {
	p.Type = credential.PrivateType_Password
	return (*Private)(p).ToORM(ctx)
}

// ToPB - Get the Protobuf object for the Password credential.
func (p *Password) ToPB() *credential.Private {
	p.Type = credential.PrivateType_Password
	return (*Private)(p).ToPB()
}

// AsEntity - Returns the Private as a valid Maltego Entity.
func (p *Password) AsEntity() maltego.Entity {
	// e:= maltego.NewEntity(h)
	// base := (*Private)(h).AsEntity()
	// e.SetBase(base)
	// return e
	return maltego.NewEntity(p)
}
