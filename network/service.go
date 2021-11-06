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
	"github.com/maxlandon/aims/proto/gen/go/network"
	"github.com/maxlandon/gondor/maltego"
)

// Service - A service somewhere on a network.
// The type has several categories of fields: general information,
// and Nmap-compliant fields (fingerprints, protocols, banners, versions)
type Service struct {
	*network.Service
}

// NewService - Creates a new aims.Service with its embedded Protobuf type.
func NewService() *Service {
	return &Service{
		Service: &network.Service{},
	}
}

// ServiceFromPB - Get a Service from its Protobuf equivalent.
func ServiceFromPB(pb *network.Service) *Service {
	return &Service{Service: pb}
}

// AsEntity - Returns the Service as a valid Maltego Entity.
func (s *Service) AsEntity() maltego.Entity {
	return maltego.Entity{}
}
