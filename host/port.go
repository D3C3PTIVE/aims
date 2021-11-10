package host

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

	"github.com/maxlandon/aims/proto/gen/go/host"
)

// Port - A port on a Host.
// The type has several categories of fields: general information,
// and Nmap-compliant fields (status, owner, service, scripts etc).
type Port host.Port

//
// General Functions
//

// ToORM - Get the SQL object for the Port
func (p *Port) ToORM(ctx context.Context) (host.PortORM, error) {
	return (*host.Port)(p).ToORM(ctx)
}

// ToPB - Get the Protobuf object for the Port
func (p *Port) ToPB() *host.Port {
	return (*host.Port)(p)
}

// AsEntity - Returns the Port as a valid Maltego Entity.
func (p *Port) AsEntity() maltego.Entity {
	return maltego.Entity{}
}
