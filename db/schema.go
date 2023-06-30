package db

import (
	"gorm.io/gorm"

	"github.com/maxlandon/aims/proto/gen/go/credential"
	"github.com/maxlandon/aims/proto/gen/go/host"
	"github.com/maxlandon/aims/proto/gen/go/network"
	"github.com/maxlandon/aims/proto/gen/go/scan"
)

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

// Schema returns all AIMS objects to be registered as a database schema.
func Migrate(db *gorm.DB) error {
	return db.AutoMigrate(
		// Host
		host.HostORM{},
		host.GroupORM{},

		// Network
		network.ServiceORM{},
		network.AddressORM{},

		// Credentials
		credential.CoreORM{},

		// Scans
		scan.RunORM{},
	)
}
