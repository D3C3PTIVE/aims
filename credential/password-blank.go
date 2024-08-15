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

	credential "github.com/d3c3ptive/aims/credential/pb"
)

// BlankPassword - A credential.Private password.
// Note that upon saving this object in DB, any .Data value
// will be replaced by an empty string.
type BlankPassword Private

// NewBlankPassword - Create a new blank Password Credential.
func NewBlankPassword() *BlankPassword {
	p := BlankPassword(Private{})
	p.Type = credential.PrivateType_BlankPassword
	return &p
}

//
// General Functions
//

// ToORM - Get the SQL object for the BlankPassword credential.
// NOTE: A blank password is considered invalid if BOTH 1) the BlankPassword.Type is not
// set to credential.PrivateType_BlankBlankPassword and 2) the BlankPassword.Data is "". This
// will throw a validation error when saving the password to DB. If you want to save
// an empty password, you MUST change the .Type to PrivateType_BlankBlankPassword.
func (p *BlankPassword) ToORM(ctx context.Context) (credential.PrivateORM, error) {
	p.Type = credential.PrivateType_BlankPassword
	p.Data = ""
	return (*Private)(p).ToORM(ctx)
}

// ToPB - Get the Protobuf object for the BlankPassword credential.
func (p *BlankPassword) ToPB() *credential.Private {
	p.Type = credential.PrivateType_BlankPassword
	p.Data = ""
	return (*Private)(p).ToPB()
}

// AsEntity - Returns the Private as a valid Maltego Entity.
func (p *BlankPassword) AsEntity() maltego.Entity {
	// e:= maltego.NewEntity(h)
	// base := (*Private)(h).AsEntity()
	// e.SetBase(base)
	// return e
	return maltego.NewEntity(p)
}
