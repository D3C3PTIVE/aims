package db

import (
	"gorm.io/gorm"

	c2 "github.com/d3c3ptive/aims/c2/pb"
	credential "github.com/d3c3ptive/aims/credential/pb"
	host "github.com/d3c3ptive/aims/host/pb"
	network "github.com/d3c3ptive/aims/network/pb"
	provenance "github.com/d3c3ptive/aims/provenance/pb"
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
	// SQLite emits foreign-key constraints inline at CREATE TABLE, so a self/circular reference
	// (e.g. cores.login_id -> logins.id while logins has a Core association) makes table-creation
	// order-sensitive and can fail with "no such table". Skipping FK-constraint creation lets all
	// tables be created regardless of order; the ORM relationships and preloads are unaffected, and
	// SQLite does not enforce FKs by default anyway.
	db.DisableForeignKeyConstraintWhenMigrating = true

	if err := db.AutoMigrate(
		// Network
		network.AddressORM{},
		network.TimesORM{},
		network.DistanceORM{},
		network.HopORM{},
		network.TraceORM{},
		network.ServiceORM{},
		network.SequenceORM{},
		network.TCPSequenceORM{},
		network.TCPTSSequenceORM{},
		network.IPIDSequenceORM{},
		network.ICMPResponseORM{},

		// OS
		host.OSClassORM{},
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
		host.ProcessORM{},
		host.UptimeORM{},
		host.HostORM{},
		host.FileSystemORM{},
		host.FileORM{},

		// Provenance. The shared contribution record every merge-unit object joins to
		// (many-to-many); registered before its owners so the join tables resolve.
		provenance.SourceORM{},

		// Credentials.
		// Order matters for SQLite: cores.login_id references logins.id, and the
		// public/private/realm children reference cores.id — so logins → cores → children.
		// Provenance (the former Origin) is now a many-to-many via provenance.SourceORM.
		credential.LoginORM{},
		credential.CoreORM{},
		credential.RealmORM{},
		credential.PublicORM{},
		credential.PrivateORM{},

		// Scans
		scan.RunORM{},
		scan.ResultORM{},
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
	); err != nil {
		return err
	}

	return createIndexes(db)
}

// secondaryIndex is one non-primary-key index to create after AutoMigrate. GORM's AutoMigrate
// only builds primary-key indexes (and, for many-to-many join tables, a *composite* PK whose
// leading column is the owner id) — it never indexes has-many foreign keys, scope/lookup
// columns, or the reverse (referenced) leg of a join. So every identity read (.Where(orm)),
// child preload (WHERE host_id IN …), provenance scope join, and cross-run host unification is
// a full table scan until we add these by hand.
//
// These live here as raw DDL rather than as proto `(gorm.field)` index tags on purpose: the
// tag route requires regenerating the *.pb.gorm.go layer (blocked on the codegen toolchain),
// whereas post-migrate DDL is regen-free and backend-agnostic. `IF NOT EXISTS` makes Migrate
// idempotent across restarts. Supported by SQLite (the default gormlite store) and Postgres.
type secondaryIndex struct {
	name    string
	table   string
	columns string
}

// indexes is the targeted set — only columns on measured or documented hot paths, not a blanket
// "index every FK". Adding an index costs write-amplification on ingest and disk, so each entry
// earns its place by backing a real query.
var indexes = []secondaryIndex{
	// Provenance scope ("give me only my objects"): WhereContributedBy filters sources.tool then
	// joins each object's *_sources table on source_id. The join tables' composite PK leads with
	// the owner id, so the reverse source_id lookup is unindexed without these.
	{"idx_sources_tool", "sources", "tool"},
	{"idx_host_sources_source", "host_sources", "source_id"},
	{"idx_address_sources_source", "address_sources", "source_id"},
	{"idx_port_sources_source", "port_sources", "source_id"},
	{"idx_service_sources_source", "service_sources", "source_id"},
	{"idx_core_sources_source", "core_sources", "source_id"},
	{"idx_login_sources_source", "login_sources", "source_id"},

	// Host identity/dedup: SameHost matches on a shared address, and the P1 narrowed reload
	// scopes candidates with WHERE addr IN (…). Both scan the addresses table without this.
	{"idx_addresses_addr", "addresses", "addr"},

	// Host child preloads: every Read/list fans a WHERE host_id IN (batch) per association.
	{"idx_ports_host", "ports", "host_id"},
	{"idx_extra_ports_host", "extra_ports", "host_id"},
	{"idx_hostnames_host", "hostnames", "host_id"},
	{"idx_processes_host", "processes", "host_id"},
	{"idx_users_host", "users", "host_id"},
	{"idx_statuses_host", "statuses", "host_id"},

	// Credential preloads: Core fans to private/public/realm by core_id, Login to Core by login_id.
	{"idx_cores_login", "cores", "login_id"},
	{"idx_privates_core", "privates", "core_id"},
	{"idx_publics_core", "publics", "core_id"},
	{"idx_realms_core", "realms", "core_id"},

	// Scan: cross-run host unification reverse-looks-up run_hosts by host_id (composite PK leads
	// with run_id), and supersede/history reads filter scanner / superseded_by.
	{"idx_run_hosts_host", "run_hosts", "host_id"},
	{"idx_runs_scanner", "runs", "scanner"},
	{"idx_runs_superseded_by", "runs", "superseded_by"},
}

// createIndexes builds the secondary indexes AutoMigrate does not. It is called once at the tail
// of Migrate; failures surface as a migration error rather than silently degrading to scans.
func createIndexes(db *gorm.DB) error {
	for _, idx := range indexes {
		stmt := "CREATE INDEX IF NOT EXISTS " + idx.name + " ON " + idx.table + "(" + idx.columns + ")"
		if err := db.Exec(stmt).Error; err != nil {
			return err
		}
	}
	return nil
}
