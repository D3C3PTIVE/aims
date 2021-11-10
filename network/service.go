package network

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

	"github.com/maxlandon/aims/proto/gen/go/network"
)

// Service - A service somewhere on a network.
// The type has several categories of fields: general information,
// and Nmap-compliant fields (fingerprints, protocols, banners, versions)
type Service network.Service

//
// General Functions
//

// ToORM - Get the SQL object for the Service
func (s *Service) ToORM(ctx context.Context) (network.ServiceORM, error) {
	return (*network.Service)(s).ToORM(ctx)
}

// ToPB - Get the Protobuf object for the Service
func (s *Service) ToPB() *network.Service {
	return (*network.Service)(s)
}

// AsEntity - Returns the Service as a valid Maltego Entity.
func (s *Service) AsEntity() maltego.Entity {
	return maltego.Entity{}
}
