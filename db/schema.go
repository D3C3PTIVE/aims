package db

import (
	"gorm.io/gorm"

	c2 "github.com/d3c3ptive/aims/c2/pb"
	credential "github.com/d3c3ptive/aims/credential/pb"
	host "github.com/d3c3ptive/aims/host/pb"
	network "github.com/d3c3ptive/aims/network/pb"
	scan "github.com/d3c3ptive/aims/scan/pb"
	nmap "github.com/d3c3ptive/aims/scan/pb/nmap"
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
		// Network
		network.AddressORM{},
		network.TimesORM{},
		network.DistanceORM{},
		network.HopORM{},
		network.TraceORM{},
		network.ServiceORM{},

		// OS
		host.OSFingerprintORM{},
		host.OSMatchORM{},
		host.OSORM{},

		// Host
		host.StateORM{},
		host.StatusORM{},
		host.ReasonORM{},

		host.PortORM{},
		host.PortUsedORM{},
		host.ExtraPortORM{},

		host.HostnameORM{},
		host.UserORM{},
		host.GroupORM{},
		host.HostORM{},
		host.FileSystemORM{},
		host.FileORM{},

		// Credentials
		credential.CoreORM{},

		// Scans
		scan.RunORM{},
		scan.InfoORM{},
		scan.DebuggingORM{},
		scan.VerboseORM{},
		scan.FinishedORM{},
		scan.StatsORM{},
		scan.HostStatsORM{},
		scan.TargetORM{},
		scan.ScanTaskORM{},
		scan.TaskProgressORM{},

		nmap.ScriptORM{},
		nmap.SmurfORM{},
		nmap.TableORM{},
		nmap.ElementORM{},

		// C2
		c2.TaskORM{},
		c2.ChannelORM{},
		c2.AgentORM{},
	)
}
