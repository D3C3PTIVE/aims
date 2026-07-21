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

// Host status and port states.
//
// These are NOT an enum: the values are the exact strings nmap writes into its
// XML `state` attribute (Status.State for a host, Port.State/ExtraPort.State for
// a port), unmarshalled straight into the `string` fields via their `xml:"…"`
// tags. They are therefore an external contract whose spelling must not drift —
// these consts give the codebase one authoritative spelling to switch/compare
// against instead of the literals that were duplicated across the host, network,
// scan and cmd packages.
const (
	// StateUp / StateDown are host liveness (Status.State).
	StateUp   = "up"
	StateDown = "down"

	// Port states (Port.State.State). Open/Closed/Filtered are the common trio;
	// the remaining variants are the other values nmap may emit.
	PortOpen           = "open"
	PortClosed         = "closed"
	PortFiltered       = "filtered"
	PortUnfiltered     = "unfiltered"
	PortOpenFiltered   = "open|filtered"
	PortClosedFiltered = "closed|filtered"
)
