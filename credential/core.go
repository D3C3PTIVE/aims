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
	"gorm.io/gorm"

	credential "github.com/d3c3ptive/aims/credential/pb"
	"github.com/d3c3ptive/aims/host"
	provenance "github.com/d3c3ptive/aims/provenance/pb"
)

// Core - A wrapper around the credential.Core protobuf type. This is unexported
// because the core is always only a driver that orchestrates one or more Credential types,
// along with an optional realm. Various functions in the package allow users to instantiate
// Credential sets, similarly to Metasploit Credential API.
type Core credential.Core

//
// Database Scopes
//
// The functions below are the Metasploit-style credential-query API: each returns a
// composable GORM scope (func(*gorm.DB) *gorm.DB) so callers chain them with .Scopes(...),
// exactly like provenance.WhereContributedBy. They restrict a *CoreORM query to the cores
// matching a relationship, and a nil/empty argument is a no-op so a filter value can be
// passed through unconditionally.
//

// WhereOriginIs scopes a Core query to those whose provenance includes the given source (the
// former credential.Origin, now the shared provenance.Source). When o carries an Id it matches
// that exact source row; otherwise it matches by the source's identity tuple (tool/type/
// session/filename/cracker/service). The join runs through the core_sources m2m table.
func WhereOriginIs(o *provenance.Source) func(*gorm.DB) *gorm.DB {
	return func(d *gorm.DB) *gorm.DB {
		if o == nil {
			return d
		}
		sub := d.Session(&gorm.Session{NewDB: true}).
			Table("core_sources").
			Select("core_sources.core_id").
			Joins("JOIN sources ON sources.id = core_sources.source_id")
		if o.Id != "" {
			sub = sub.Where("sources.id = ?", o.Id)
		} else {
			sub = sub.Where(
				"sources.tool = ? AND sources.type = ? AND sources.session_id = ? "+
					"AND sources.filename = ? AND sources.cracker = ? AND sources.service_id = ?",
				o.Tool, int32(o.Type), o.SessionId, o.Filename, o.Cracker, o.ServiceId,
			)
		}
		return d.Where("id IN (?)", sub)
	}
}

// WhereLoggedInHost scopes a Core query to those whose provenance was gathered from a service
// running on the given host (its origin service belongs to the host).
//
// NOTE: exact login tracking — the credential.Login use of a Core against a specific service —
// awaits a Core<->Login foreign key in the schema (Core.Logins is commented out and the
// generated LoginORM carries no core_id). Until then this approximates "logged into this host"
// through the service-scoped provenance the model does record.
func WhereLoggedInHost(h *host.Host) func(*gorm.DB) *gorm.DB {
	return whereSourcedFromHostService(h)
}

// WhereOriginServiceForHost scopes a Core query to those with a Service-type origin gathered
// from a service on the given host (the former OriginType_Service).
func WhereOriginServiceForHost(h *host.Host) func(*gorm.DB) *gorm.DB {
	return whereSourcedFromHostService(h, provenance.SourceType_Service)
}

// WhereOriginSessionForHost scopes a Core query to those with a session/C2 origin gathered on
// the given host. The former OriginType_Session maps onto the c2/session producer
// (SourceType_C2) in the unified provenance model, scoped to the host's services.
func WhereOriginSessionForHost(h *host.Host) func(*gorm.DB) *gorm.DB {
	return whereSourcedFromHostService(h, provenance.SourceType_C2)
}

// whereSourcedFromHostService is the shared body of the host-scoped credential queries: it
// restricts a Core query to cores whose provenance sources reference a service running on host
// h, optionally narrowed to the given source types. Host services are resolved via the ports
// table (host_id -> service_id); the core<->source link via the core_sources m2m table. A nil
// or id-less host is a no-op.
func whereSourcedFromHostService(h *host.Host, types ...provenance.SourceType) func(*gorm.DB) *gorm.DB {
	return func(d *gorm.DB) *gorm.DB {
		if h == nil || h.Id == "" {
			return d
		}

		services := d.Session(&gorm.Session{NewDB: true}).
			Table("ports").
			Select("service_id").
			Where("host_id = ? AND service_id IS NOT NULL", h.Id)

		sub := d.Session(&gorm.Session{NewDB: true}).
			Table("core_sources").
			Select("core_sources.core_id").
			Joins("JOIN sources ON sources.id = core_sources.source_id").
			Where("sources.service_id IN (?)", services)

		if len(types) > 0 {
			ints := make([]int32, len(types))
			for i, t := range types {
				ints[i] = int32(t)
			}
			sub = sub.Where("sources.type IN ?", ints)
		}

		return d.Where("id IN (?)", sub)
	}
}
