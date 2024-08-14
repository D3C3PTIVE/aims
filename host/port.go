package host

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
	"sync"

	"github.com/maxlandon/gondor/maltego"

	"github.com/d3c3ptive/aims/proto/host"
)

// Port - A port on a Host.
// The type has several categories of fields: general information,
// and Nmap-compliant fields (status, owner, service, scripts etc).
type Port host.Port

//
// General Functions
//

// ToORM - Get the SQL object for the Port.
func (p *Port) ToORM(ctx context.Context) (host.PortORM, error) {
	return (*host.Port)(p).ToORM(ctx)
}

// ToPB - Get the Protobuf object for the Port.
func (p *Port) ToPB() *host.Port {
	return (*host.Port)(p)
}

// AsEntity - Returns the Port as a valid Maltego Entity.
func (p *Port) AsEntity() maltego.Entity {
	return maltego.Entity{}
}

// FilterIdenticalPort returns a list of portsfrom which have been removed all ports that are
// already in the database, with a very high degree of certitude. This avoids redundance when
// manipulating new ports/services.
func FilterIdenticalPort(raw []host.PortORM, dbHosts []*host.PortORM) (filtered []host.PortORM) {
	for _, newHost := range raw {
		done := new(sync.WaitGroup)

		allMatches := []*host.PortORM{}

		// Check IDs: if non-nil and identical, done checking.

		// Concurrently check all hosts for an identical trace.
		done.Add(1)
		go func() {
			allMatches = append(allMatches, portHasIdenticalNumber(newHost, dbHosts))
		}()

		// Concurrently check all hosts for identical user/hostnames
		done.Add(1)
		go func() {
			allMatches = append(allMatches, portHasIdenticalReasons(newHost, dbHosts))
			allMatches = append(allMatches, portHasIdenticalScripts(newHost, dbHosts))
		}()

		// Concurrently check all hosts ports
		done.Add(1)
		go func() {
			allMatches = append(allMatches, portHasIdenticalServices(newHost, dbHosts))
		}()

		// For now we wait for all queries to finish, but ideally,
		// some filters have more weight than others, but might be
		// longer to check, so when one shows that hosts are identical,
		// all other comparison routines should break.
		done.Wait()

		// If identical, add it to the valid, filtered hosts
		if identical, _ := allPortsIdentical(allMatches); identical {
			filtered = append(filtered, newHost)
		}

	}
	return
}

func portHasIdenticalServices(p host.PortORM, all []*host.PortORM) (found *host.PortORM) {
	return nil
}

func portHasIdenticalNumber(p host.PortORM, all []*host.PortORM) (found *host.PortORM) {
	return nil
}

func portHasIdenticalScripts(p host.PortORM, all []*host.PortORM) (found *host.PortORM) {
	return nil
}

func portHasIdenticalReasons(p host.PortORM, all []*host.PortORM) (found *host.PortORM) {
	return nil
}

func allPortsIdentical(all []*host.PortORM) (yes bool, matches int) {
	return false, 0
}
