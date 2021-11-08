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

	"github.com/maxlandon/aims/host"
	"github.com/maxlandon/aims/network"
	"github.com/maxlandon/aims/proto/gen/go/credential"
)

// Login - The use of a credential.Core against a service.
//
// This type, like some other types in the user-facing AIMS API, offers some database filtering
// functions (which are no more than reexported & populated SQL where clauses) to get one or more
// Logins for a given context (a host, a service, one or more origins, etc)
//
// You can also, like all the other types, get the ORM-compliant object
// with ToORM(), and then construct your own database filtering clauses.
type Login credential.Login

//
// General Functions
//

// ToORM - Get the SQL object for the credential Login.
func (l *Login) ToORM(ctx context.Context) (credential.LoginORM, error) {
	return (*credential.Login)(l).ToORM(ctx)
}

// ToPB - Get the Protobuf object for the credential Login.
func (l *Login) ToPB(ctx context.Context) *credential.Login {
	return (*credential.Login)(l)
}

//
// Database Scopes
//

// ForHostsAndServices - Finds all credential.Logins that are associated with a list of hosts and/or services.
func ForHostsAndServices(hosts []*host.Host, services ...[]*network.Service) {
}

// ForHost - Finds all credential.Logins associated with a Host.
func ForHost(h *host.Host) {

}

//
// Search Methods
//

// FailedLoginsByUsername - Each username that is related to a credential.Login
// on the passed host, and for each username, the logins of particular statuses
// that are related to that username as credential.Public, ordered by the login
// last attempt date.
func (l *Login) FailedLoginsByUsername(h *host.Host) {
	return
}
