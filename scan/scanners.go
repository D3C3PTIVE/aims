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

// Scanner identity keys.
//
// A scanner's name is the single string that ties its pieces together across
// packages: the server-side driver dispatch (server/scan/run.go), the ingestor
// Name() + the Scanner value it stamps on a Run (scan/ingest), the provenance
// Tool, and the completion guards (cmd/scan). A spelling drift (e.g. "zgrab2"
// vs "zgrab") silently breaks the driver↔ingestor lookup, so the identity lives
// here once rather than as literals scattered across those call sites.
const (
	ScannerNmap    = "nmap"
	ScannerMasscan = "masscan"
	ScannerZgrab2  = "zgrab2"
	// ScannerNuclei names nuclei (github.com/projectdiscovery/nuclei) — a JSON-emitting scanner
	// jsonscript.go's schemaless Script mapping already anticipates (see its doc comment: "all
	// zgrab2 modules, and by extension nuclei/httpx/testssl"). Today it names only the local
	// `scan run nuclei` passthrough (cmd/scan/run_nuclei.go) and the template/tag/severity/id
	// completers (cmd/completers/nuclei_templates.go); there is no drive.Scanner or ingest.Ingestor
	// for it yet — that is real, anticipated future work, not done here.
	ScannerNuclei = "nuclei"
)
