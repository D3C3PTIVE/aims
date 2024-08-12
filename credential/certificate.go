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
	"crypto/x509"

	"github.com/maxlandon/gondor/maltego"

	"github.com/d3c3ptive/aims/proto/credential"
)

// Certificate - An x509 Certificate potentially containing a public key
// and any root certificates, as well as various details pertaining to them.
type Certificate Public

//
// General Functions
//

// ToORM - Get the SQL object for the Certificate credential.
func (p *Certificate) ToORM(ctx context.Context) (credential.PublicORM, error) {
	p.Type = credential.PublicType_Certificate
	return (*Public)(p).ToORM(ctx)
}

// ToPB - Get the Protobuf object for the Certificate credential.
func (p *Certificate) ToPB() *credential.Public {
	p.Type = credential.PublicType_Certificate
	return (*Public)(p).ToPB()
}

// AsEntity - Returns the Certificate as a valid Maltego Entity.
func (p *Certificate) AsEntity() maltego.Entity {
	// e:= maltego.NewEntity(h)
	// base := (*Private)(h).AsEntity()
	// e.SetBase(base)
	// return e
	return maltego.NewEntity(p)
}

// AsX509 - Returns the Certificate as a Go native x509 certificate.
func (p *Certificate) AsX509() *x509.Certificate {
	// We don't make any check here, as creating the
	// involves validating that the data could be parsed.
	cert, _ := x509.ParseCertificate([]byte(p.Data))
	return cert
}
