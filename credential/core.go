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
	"github.com/maxlandon/aims/host"
	"github.com/maxlandon/aims/proto/gen/go/credential"
)

// Core - A wrapper around the credential.Core protobuf type. This is unexported
// because the core is always only a driver that orchestrates one or more Credential types,
// along with an optional realm. Various functions in the package allow users to instantiate
// Credential sets, similarly to Metasploit Credential API.
type Core credential.Core

//
// Database Scopes
//

// WhereLoggedInHost - Finds credential.Cores that have successfully logged into a given host.
func WhereLoggedInHost() {
}

// WhereOriginIs - Returns a relation that is scoped to the given origin.
func WhereOriginIs(o *credential.Origin) {
}

// WhereOriginServiceForHost - Finds credential.Cores that have an
// OriginType_Service and that are attached for the given host.
func WhereOriginServiceForHost(h *host.Host) {
}

// WhereOriginSessionForHost - Finds credential.Cores that have an
// OriginType_Session, and that were collected on the  given host.
func WhereOriginSessionForHost(h *host.Host) {
}
