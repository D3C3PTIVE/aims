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

// ReplayableHash - A credential.PasswordHash password hash that
// can be replayed to authenticate to additional services.
type ReplayableHash PasswordHash

// NewReplayableHash - Create a new ReplayableHash Credential.
func NewReplayableHash() *ReplayableHash {
	h := ReplayableHash(PasswordHash{})
	h.Type = credential.PrivateType_ReplayableHash
	return &h
}

//
// General Functions
//

// ToORM - Get the SQL object for the ReplayableHash credential.
func (h *ReplayableHash) ToORM(ctx context.Context) (credential.PrivateORM, error) {
	h.Type = credential.PrivateType_ReplayableHash
	return (*PasswordHash)(h).ToORM(ctx)
}

// ToPB - Get the Protobuf object for the ReplayableHash credential.
func (h *ReplayableHash) ToPB() *credential.Private {
	h.Type = credential.PrivateType_ReplayableHash
	return (*PasswordHash)(h).ToPB()
}

// AsEntity - Returns the Private as a valid Maltego Entity.
func (h *ReplayableHash) AsEntity() maltego.Entity {
	// e:= maltego.NewEntity(h)
	// base := (*Private)(h).AsEntity()
	// e.SetBase(base)
	// return e
	return maltego.NewEntity(h)
}
