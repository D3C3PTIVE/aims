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

// Private - Base type for all private credentials. A private credential is any credential
// that should not be publicly disclosed, such as a credential.Private.Password password,
// password hash, or key file.
// NOTE: By default, a credential.Private is of Type Password, and
// any blank Private.Data field value will be treated as incorrect.
type Private credential.Private

//
// General Functions
//

// ToORM - Get the SQL object for the Private credential.
func (p *Private) ToORM(ctx context.Context) (credential.PrivateORM, error) {
	return (*credential.Private)(p).ToORM(ctx)
}

// ToPB - Get the Protobuf object for the Private credential.
func (p *Private) ToPB() *credential.Private {
	return (*credential.Private)(p)
}

// AsEntity - Returns the Private as a valid Maltego Entity.
func (p *Private) AsEntity() maltego.Entity {
	return maltego.NewEntity(p)
}
