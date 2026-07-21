package network

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

// Address types and transport protocols.
//
// These are NOT an enum: the values are the exact strings nmap writes into its XML
// `addrtype`/`proto` attributes (Address.Type, Port.Protocol/Service.Protocol),
// unmarshalled straight into the `string` fields via their `xml:"…"` tags. They are
// therefore an external contract whose spelling must not drift — these consts give the
// codebase one authoritative spelling to switch/compare against instead of literals
// duplicated across the network, scan/ingest and cmd packages.
const (
	// Address.Type (nmap `addrtype` attribute).
	AddrTypeIPv4 = "ipv4"
	AddrTypeIPv6 = "ipv6"
	AddrTypeMAC  = "mac"

	// Port.Protocol / Service.Protocol (nmap `proto` attribute).
	ProtoTCP  = "tcp"
	ProtoUDP  = "udp"
	ProtoSCTP = "sctp"
)
