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
	"github.com/maxlandon/aims/proto/gen/go/credential"
	"github.com/maxlandon/gondor/maltego"
)

// Private - Base type for all private credentials. A private credential is any credential
// that should not be publicly disclosed, such as a credential.Private.Password password,
// password hash, or key file.
type Private credential.Private

// type Private struct {
//         *credential.Private
// }

// NewPrivate - Creates a new credential.Private with its embedded Protobuf type.
// func NewPrivate() *Private {
//         return &Private{
//                 Private: &credential.Private{},
//         }
// }

// PrivateFromPB - Get a Private from its Protobuf equivalent.
// func PrivateFromPB(pb *credential.Private) *Private {
//         return &Private{Private: pb}
// }

// AsEntity - Returns the Private as a valid Maltego Entity.
func (h *Private) AsEntity() maltego.Entity {
	return maltego.Entity{}
}
