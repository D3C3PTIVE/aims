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

import "github.com/maxlandon/aims/proto/gen/go/credential"

// CreateOptions - A type holding the objects (either optional or required
// depending on the context) that can be passed as parameter to functions
// creating either credential.Cores, Logins, pairs, etc.
// Each of these functions generally describes the fields that matter to it,
// and each of the types have their own fields' documentation.
//
// Generally, it is advised to slowly construct and populate such a type,
// taking care of each considered field one at a time, and when everything
// is set, submit this struct to one of the CreateCredential...() functions.
type CreateOptions struct {
	// Public - The credential.Public that we tried.
	// .Username  - if PublicType_Username  (required)
	// .Key,      - if PublicType_Key       (required)
	Public *Public

	// Private - The credential.Private that we tried.
	// .Data    - checked against the .PrivateType (required)
	Private *Private

	// Origin - The origin of the credentials that we are submitting
	// for creation: this also contains ALL elements for this origin:
	// ports, services, tools and filenames we need depending on the
	// proclaimed .Type attribute of the Origin.
	Origin *Origin

	// Realm - The credential realm to which the Public/Private belong.
	Realm *credential.Realm
}

// CreateCredential - Create a credential.Core, and all the sub-objects that
// it depends upon. Some assertions might be made in this function, but they
// are kept to the bare minimum, and the purpose of the Options parameter is
// to make callers able to prepare their call in more detail.
func CreateCredential(opts *CreateOptions) *Core {
	return &Core{}
}

// CreateCredentialAndLogin - Create a credential.Core and its associated
// credential.Login. This, in effect, ties the Core with a Service passed
// in the options (required), through the created Login type.
// The login contains the credential.Core created/fetched in this function.
func CreateCredentialAndLogin(opts *CreateOptions) *Login {
	return &Login{}
}
