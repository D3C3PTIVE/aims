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

	"github.com/d3c3ptive/aims/scan"
)

// Run - The results of an Nmap scan that has been ran.
// This object is the root of the complete output XML tree of the scan.
type Run scan.Run

// FromRun - If you have ran a Scan and parsed its XML output
// into an scan.Run protobuf type, you can create a scan out of it.
func FromRun(pb *scan.Run) *Run {
	return (*Run)(pb)
}

// FromXML - Given the output of an Nmap Scan as a string in XML format,
// parse it and return a Run with its contents. If the unmarshalling fails,
// it returns both the model and the error, so always check the latter.
//
// The run keeps its verbatim input as RawXML: it is the scanner's authoritative output, so it
// serves both as the decisive run-dedup fingerprint (AreScansIdentical: two nmap scans of one
// target at different times carry the same Args/Version and would otherwise field-collide, but
// their raw output differs) and as the per-run snapshot that `scan diff` re-parses to see drift
// that host unification has folded away in the stored rows.
func FromXML(data []byte) (*scan.Run, error) {
	r := &scan.Run{}
	err := xml.Unmarshal(data, r)
	r.RawXML = string(data)
	return r, err
}
