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

// icmpCodeMessages - Mapping the .Code of an ICMP
// response with its human-readable description/name.
type icmpCodeMessages map[uint32]string

// icmpTypeCodes - Mapping of the .Type of an ICMP
// response with its appropriate .Codes and descriptions.
type icmpTypeCodes map[ICMPType]icmpCodeMessages

var (
	// ICMPCodes - A map containing all valid (non-reserved)
	// ICMP response codes, and for each of them, a map containing
	// all its valid response code.
	// Eg: by calling ICMPCodes[ICMPType(3)][4], you get the message
	// "Fragmentation required, and DF flag set"
	//
	// List taken from:
	// https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol
	ICMPCodes = icmpTypeCodes{
		ICMPType_EchoReply: icmpCodeMessages{
			0: "Echo reply",
		},
		// 1 and 2 reserved
		ICMPType_DestinationUnreachable: icmpCodeMessages{
			0:  "Destination network unreachable",
			1:  "Destination host unreachable",
			2:  "Destination protocol unreachable",
			3:  "Destination port unreachable",
			4:  "Fragmentation required, and DF (Don't Fragment) flag set",
			5:  "Source route failed",
			6:  "Destination network unknown",
			7:  "Destination host unknown",
			8:  "Source host isolated",
			9:  "Network administratively prohibited",
			10: "Host administratively prohibited",
			11: "Network unreachable for ToS",
			12: "Host unreachable for ToS",
			13: "Communication administratively prohibited",
			14: "Host Precedence Violation",
			15: "Precedence cutoff in effect",
		},
		ICMPType_SourceQuench: icmpCodeMessages{
			0: "Source quench (congestion control)",
		},
		ICMPType_RedirectMessage: icmpCodeMessages{
			0: "Redirect Datagram for the Network",
			1: "Redirect Datagram for the Host",
			2: "Redirect Datagram for the ToS & Network",
			3: "Redirect Datagram for the ToS & Host",
		},
		ICMPType_EchoRequest: icmpCodeMessages{
			0: "Echo request",
		},
		ICMPType_RouterAdvertisement: icmpCodeMessages{
			0: "Router Advertisement",
		},
		ICMPType_RouterSolicitation: icmpCodeMessages{
			0: "Router discovery/selection/solicitation",
		},
		ICMPType_TimeExceeded: icmpCodeMessages{
			0: "TTL expired in transit",
			1: "Fragment reassembly time exceeded",
		},
		ICMPType_BadIPHeader: icmpCodeMessages{
			0: "Pointer indicates the error",
			1: "Missing a required option",
			2: "Bad length",
		},
		ICMPType_Timestamp: icmpCodeMessages{
			0: "Timestamp",
		},
		ICMPType_TimestampReply: icmpCodeMessages{
			0: "Timestamp reply",
		},
		// 15-18 deprecated
		// 19,20-29 reserved
		// 30-39 deprecated
		ICMPType_Photuris: icmpCodeMessages{
			// 0 is therefore the default
			0: "Photuris (session key mgmt protocol), Security failures",
		},
		ICMPType_MobilityProto: icmpCodeMessages{
			// 0 is therefore the default
			0: "[Experimental] ICMP for experimental mobility protocols such as Seamoby [RFC4065]",
		},
		ICMPType_ExtendedEchoRequest: icmpCodeMessages{
			0: "Request Extended Echo (XPing)",
		},
		ICMPType_ExtendedEchoReply: icmpCodeMessages{
			0: "No error",
			1: "Malformed Query",
			2: "No Such Interface",
			3: "No Such Table Entry",
			4: "Multiple Interfaces Satisfy Query",
		},
		// 44-252 reserved
		ICMPType_RFC3692Experiment1: icmpCodeMessages{
			0: "RFC3692 Experiment 1 [RFC4727]",
		},
		ICMPType_RFC3692Experiment2: icmpCodeMessages{
			0: "RFC3692 Experiment 2 [RFC4727]",
		},
		// 255 reserved

	}
)
