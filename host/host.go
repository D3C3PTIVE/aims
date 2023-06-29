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
	"reflect"

	"github.com/infobloxopen/protoc-gen-gorm/types"
	"github.com/maxlandon/aims/internal/display"
	"github.com/maxlandon/aims/proto/gen/go/host"
	"github.com/maxlandon/gondor/maltego"
)

// Host - A physical or virtual computer host.
// The type has several categories of fields: general information,
// and Nmap-compliant fields (ports, status, route, scripts etc).
type Host host.Host

//
// [ General Functions ] --------------------------------------------------
//

// ToORM - Get the SQL object for the Host.
func (h *Host) ToORM(ctx context.Context) (host.HostORM, error) {
	return (*host.Host)(h).ToORM(ctx)
}

// ToPB - Get the Protobuf object for the Host.
func (h *Host) ToPB() *host.Host {
	return (*host.Host)(h)
}

// AsEntity - Returns the Host as a valid Maltego Entity.
func (h *Host) AsEntity() maltego.Entity {
	return maltego.Entity{}
}

//
// [ Display Functions ] --------------------------------------------------
//

// Headers returns the entity's fields as a list to be used in a table row.
// The headers parameter can be used to restrict printing to some fields.
// Those headers strings should be the name of the field as used by the
// reflect package (ie. the name used in the source code).
func (h *Host) Headers(headers ...string) (names []string, indexes [][]int) {
	var heads []string

	if len(headers) == 0 {
		heads = append(heads, []string{
			"Id",
			"OSName",
			"OSFamily",
			"Arch",
			"MAC",
			"Purpose",
			// "Status",
		}...)
	} else {
		heads = headers
	}

	fType := reflect.TypeOf(h).Elem()

	// For each field, check if it has a display tag to use.
	for _, header := range heads {
		field, ok := fType.FieldByName(header)
		if !ok {
			continue
		}

		// Determine the header string value.
		displayTag, ok := field.Tag.Lookup("display")
		if ok {
			names = append(names, displayTag)
		} else {
			names = append(names, field.Name)
		}

		// And keep the index to be used by rows.
		indexes = append(indexes, field.Index)
	}

	return names, indexes
}

// Values returns a list of field names that
// should be used as headers in a table of hosts.
func (h *Host) Rows(filters ...string) []string {
	// field, _ := reflect.TypeOf(h).FieldByName("Testing")
	return nil
}

func (h *Host) Values(indexes [][]int) []string {
	fType := reflect.Indirect(reflect.ValueOf(h))
	f := reflect.TypeOf(h).Elem()
	values := make([]string, len(indexes))

	for i, index := range indexes {
		field := fType.FieldByIndex(index)
		val := field.Interface()
		tfield := f.FieldByIndex(index)

		// Adjustments
		if tfield.Name == "Id" {
			id := val.(*types.UUID)
			values[i] = display.FormatSmallID(id.String())
		} else {
			values[i] = val.(string)
		}
	}

	return values
}
