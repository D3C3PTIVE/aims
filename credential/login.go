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
	"github.com/maxlandon/aims/proto/credential"
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
// Creation & Update Functions
//

// LoginOptions - A template used as a parameter to functions creating/updating/
// invalidating logins. None of these fields are nil by default, but some of their
// own values are checked in the InvalidateLogin() function.
// Each field in this struct list its fields checked by InvalidateLogin().
// NOTE: At no point any ID will be required from any of those types, so this function
// does NOT require any database-existing object.
type LoginOptions struct {
	// Port - A port is lower-level item that we require to check a login.
	// This is so because the credential.Service that you must pass as a
	// field is usually an attribute of a host.Port.
	// Port host.Port

	// Service - The service against which a Login has been performed.
	// Fields that are checked:
	// .Hostname  - an IP or a domain name, that you can populate.
	// .Protocol  - The transport and/or application protocol of the service
	Service network.Service

	// Public - The credential.Public that we tried.
	// Fields that are checked:
	// .Username  - if PublicType_Username
	// .Key,      - if PublicType_Key
	Public Public

	// Private - The credential.Private that we tried.
	// Fields that are checked:
	// .Data    - checked against the .PrivateType
	Private Private

	// Status - The status symbol that the user
	// gives when populating this template.
	Status credential.LoginStatus
}

// NewLogin - This method is responsible for creating a credential.Login
// object which ties a credential.Core to the .Service in the LoginOptions,
// it is a valid credential for.
func NewLogin(core *Core, opts *LoginOptions) (*Core, *Login, error) {
	return &Core{}, &Login{}, nil
}

// InvalidateLogin - Checks to see if a credential.Login exists for a given set of details.
// If it does exists, we then appropriately set the status to one of our failure statuses.
//
// @param: The template that you pass as argument must be populated with several fields,
//         each of them in turn checking some of its own required fields. Please refer
//         to the InvalidateLoginOpts documentation for a list of each of those required.
//
// Raises an error if any of the above options are missing
func InvalidateLogin(opts *LoginOptions) (err error) {

	// Check the Port+Service fields validity,
	// and create any missing stuff if needed.

	// We must find a credential.Core matching ALL fields, and if
	// any condition is missing, we don't have a valid combination.

	// If one is found, update the login last attempt.

	return
}

//
// General Functions
//

// ToORM - Get the SQL object for the credential Login.
func (l *Login) ToORM(ctx context.Context) (credential.LoginORM, error) {
	return (*credential.Login)(l).ToORM(ctx)
}

// ToPB - Get the Protobuf object for the credential Login.
func (l *Login) ToPB() *credential.Login {
	return (*credential.Login)(l)
}

//
// Database Scopes
//

// ForHost - Finds all credential.Logins associated with a Host.
func ForHost(h *host.Host) {
}

// ForHostsAndServices - Finds all credential.Logins that are associated with a list of hosts and/or services.
func ForHostsAndServices(hosts []*host.Host, services ...[]*network.Service) {
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
