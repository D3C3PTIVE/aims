package scan

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
	"errors"
	"strings"

	uuid "github.com/satori/go.uuid"

	"github.com/maxlandon/aims/proto/gen/go/scan"
)

// Run - Represents a scan before, after or while being run.
// This run can be the one of any scanner: fields are not mandatorily used
// by all scanners for all scans, but this type gives a common tree in which
// to store hosts, ports, services, statistics and various other information.
//
// The type provides many convenience methods to process all the output of the
// scan, either at once or continuously, or even to refine the objects based on/
// with those already in a database. Therefore, all the methods of this type
// are meant to be used server-side, and not in an implant.
//
// For having similar functionality from within an implant, use the Protobuf
// scan.Run type, which itself has some convenience methods that do NOT need
// any database or its related libraries.
type Run scan.Run

// NewRun - Create a new scan.Run based on a tool (scanner) name, and with an
// optional Options type holding various settings to be customized for your use.
func NewRun(scanner string, args ...string) *Run {
	return &Run{
		Scanner: scanner,
		Args:    strings.Join(args, " "),
	}
}

// Functionality
//
// Return a concurrent spinner/progress bar / interface for progress
// Function to update progress

// AddTarget - Add a Target to the Scan. The fields are only checked
// when they are needed by the service probing stack used by the scan.
func (r *Run) AddTarget(t *Target) {
}

// InitResult - Instantiate a new result that has the Run UUID in ref.
// The rest of the object can be populated by the user as he wishes.
func (r *Run) InitResult() *Result {
	return &Result{
		ScanId: r.Id,
	}
}

// AddResult - Return a Result (which must be created with construtor: has mapped ID)
// This function takes care of matching anything against DB, populates various fields,
// and adds all of those into the Run object tree.
//
// Note that when you call this function, if your scan makes use of the Result.Data field
// (used by custom/specific service scanner), we assume that it is correctly populated.
// You however have access to a few functions to manage the types you can put in this .Data
//
// As for many other objects that you'll find as field in "request option structs", this
// Result can hold a host, service, port, etc. It is always advised to pass objects that
// are themselves coming from other tools/pipes, so as to keep track of them in complex workflows.
func (r *Run) AddResult(res *Result) (err error) {
	if res.ScanId == nil || res.ScanId.String() == uuid.Nil.String() {
		return errors.New("Result is not tied to any scan.Run")
	}
	return
}

//
//
// Nmap-specific ------------------------------------------------------
//

//
//
//

//
// Zgrab-specific ------------------------------------------------------
//
