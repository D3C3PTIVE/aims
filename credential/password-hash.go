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

// PasswordHash - The cryptographic hash of a credential.Password password}.
// Like some other private.Credential types, the PasswordHash.Data cannot be nil.
type PasswordHash Private

// NewPasswordHash - Create a new PasswordHash Credential.
// Its .Type attribute is set to PrivateType_NonReplayableHash by default, so
// when you know that is not the case, do not forget to change it if needed.
func NewPasswordHash() *PasswordHash {
	h := PasswordHash(Private{})
	h.Type = credential.PrivateType_NonReplayableHash
	return &h
}

//
// General Functions
//

// ToORM - Get the SQL object for the PasswordHash credential.
func (h *PasswordHash) ToORM(ctx context.Context) (credential.PrivateORM, error) {
	h.Type = credential.PrivateType_NonReplayableHash
	return (*Private)(h).ToORM(ctx)
}

// ToPB - Get the Protobuf object for the PasswordHash credential.
func (h *PasswordHash) ToPB() *credential.Private {
	h.Type = credential.PrivateType_NonReplayableHash
	return (*Private)(h).ToPB()
}

// AsEntity - Returns the Private as a valid Maltego Entity.
func (h *PasswordHash) AsEntity() maltego.Entity {
	// e:= maltego.NewEntity(h)
	// base := (*Private)(h).AsEntity()
	// e.SetBase(base)
	// return e
	return maltego.NewEntity(h)
}
