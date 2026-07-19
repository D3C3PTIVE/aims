//go:build maltego

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

package credential

// Maltego entity conversions for the credential domain.
//
// These are isolated behind the `maltego` build tag because they depend on
// github.com/maxlandon/gondor/maltego, which is currently broken at its pinned
// version. Default builds omit this file (and the dependency) entirely; build
// with `-tags maltego` once the gondor dependency is repaired/replaced.

import (
	"github.com/maxlandon/gondor/maltego"
)

// AsEntity - Returns the Certificate as a valid Maltego Entity.
func (p *Certificate) AsEntity() maltego.Entity {
	// e:= maltego.NewEntity(h)
	// base := (*Private)(h).AsEntity()
	// e.SetBase(base)
	// return e
	return maltego.NewEntity(p)
}

// AsEntity - Returns the PrivateKey as a valid Maltego Entity.
func (p *PrivateKey) AsEntity() maltego.Entity {
	// e:= maltego.NewEntity(h)
	// base := (*Private)(h).AsEntity()
	// e.SetBase(base)
	// return e
	return maltego.NewEntity(p)
}

// AsEntity - Returns the PublicKey as a valid Maltego Entity.
func (p *PublicKey) AsEntity() maltego.Entity {
	// e:= maltego.NewEntity(h)
	// base := (*Private)(h).AsEntity()
	// e.SetBase(base)
	// return e
	return maltego.NewEntity(p)
}

// AsEntity - Returns the Private as a valid Maltego Entity.
func (h *NonReplayableHash) AsEntity() maltego.Entity {
	// e:= maltego.NewEntity(h)
	// base := (*Private)(h).AsEntity()
	// e.SetBase(base)
	// return e
	return maltego.NewEntity(h)
}

// AsEntity - Returns the Private as a valid Maltego Entity.
func (h *NTLMHash) AsEntity() maltego.Entity {
	// e:= maltego.NewEntity(h)
	// base := (*Private)(h).AsEntity()
	// e.SetBase(base)
	// return e
	return maltego.NewEntity(h)
}

// AsEntity - Returns the Private as a valid Maltego Entity.
func (p *BlankPassword) AsEntity() maltego.Entity {
	// e:= maltego.NewEntity(h)
	// base := (*Private)(h).AsEntity()
	// e.SetBase(base)
	// return e
	return maltego.NewEntity(p)
}

// AsEntity - Returns the Private as a valid Maltego Entity.
func (h *PasswordHash) AsEntity() maltego.Entity {
	// e:= maltego.NewEntity(h)
	// base := (*Private)(h).AsEntity()
	// e.SetBase(base)
	// return e
	return maltego.NewEntity(h)
}

// AsEntity - Returns the Private as a valid Maltego Entity.
func (p *Password) AsEntity() maltego.Entity {
	// e:= maltego.NewEntity(h)
	// base := (*Private)(h).AsEntity()
	// e.SetBase(base)
	// return e
	return maltego.NewEntity(p)
}

// AsEntity - Returns the Private as a valid Maltego Entity.
func (p *PostgresMD5) AsEntity() maltego.Entity {
	// e:= maltego.NewEntity(h)
	// base := (*NonReplayableHash)(p).AsEntity()
	// e.SetBase(base)
	// return e
	return maltego.NewEntity(p)
}

// AsEntity - Returns the Private as a valid Maltego Entity.
func (p *Private) AsEntity() maltego.Entity {
	return maltego.NewEntity(p)
}

// AsEntity - Returns the Public as a valid Maltego Entity.
func (p *Public) AsEntity() maltego.Entity {
	return maltego.NewEntity(p)
}

// AsEntity - Returns the Private as a valid Maltego Entity.
func (h *ReplayableHash) AsEntity() maltego.Entity {
	// e:= maltego.NewEntity(h)
	// base := (*Private)(h).AsEntity()
	// e.SetBase(base)
	// return e
	return maltego.NewEntity(h)
}

// AsEntity - Returns the Public as a valid Maltego Entity.
func (u *BlankUsername) AsEntity() maltego.Entity {
	// e:= maltego.NewEntity(h)
	// base := (*Public)(h).AsEntity()
	// e.SetBase(base)
	// return e
	return maltego.NewEntity(u)
}

// AsEntity - Returns the Public as a valid Maltego Entity.
func (h *Username) AsEntity() maltego.Entity {
	// e:= maltego.NewEntity(h)
	// base := (*Public)(h).AsEntity()
	// e.SetBase(base)
	// return e
	return maltego.NewEntity(h)
}
