package nmap

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
	"encoding/xml"

	"github.com/maxlandon/aims/proto/gen/go/scan/nmap"
	"github.com/maxlandon/gondor/maltego"
)

// Run - The results of an Nmap scan that has been ran.
// This object is the root of the complete output XML tree of the scan.
type Run nmap.Run

// FromRun - If you have ran a Scan and parsed its XML output
// into an nmap.Run protobuf type, you can create a scan out of it.
func FromRun(pb *nmap.Run) *Run {
	return (*Run)(pb)
}

// FromXML - Given the output of an Nmap Scan as a string in XML format,
// parse it and return a Run with its contents. If the unmarshalling fails,
// it returns both the model and the error, so always check the latter.
func FromXML(data []byte) (*Run, error) {
	r := &nmap.Run{}
	err := xml.Unmarshal(data, r)
	return (*Run)(r), err
}

// AsEntity - Returns the Scan as a valid Maltego Entity.
func (s *Run) AsEntity() maltego.Entity {
	return maltego.Entity{}
}
