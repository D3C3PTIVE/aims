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
	"strings"

	host "github.com/d3c3ptive/aims/host/pb"
	"github.com/d3c3ptive/aims/internal/util"
	network "github.com/d3c3ptive/aims/network/pb"
)

// AreHostsIdentical compares two pb.HostORM objects to determine if they represent the same host.
func AreHostsIdentical(host1, host2 *host.HostORM) bool {
	if host1 == nil || host2 == nil {
		return false
	}

	// Step 1: Perform unambiguous identification check
	// if identical, _ := IsHostUnambiguouslyIdentifiable(host1); identical {
	// 	return true
	// }

	weightBy := util.WeightedCompare
	intCmp := util.CompareInts
	strCmp := util.CompareStrings
	compareStringSlices := util.CompareStringSlices
	score := 0

	// Strong indicators
	score += weightBy(strCmp(host1.MAC, host2.MAC), 5)
	score += weightBy(compareStringSlices(getHostAddresses(host1), getHostAddresses(host2)), 4)
	score += weightBy(compareStringSlices(getHostHostnames(host1), getHostHostnames(host2)), 4)
	score += weightBy(strCmp(host1.OSName, host2.OSName) && strCmp(host1.Arch, host2.Arch), 3)
	score += weightBy(intCmp(host1.StartTime, host2.StartTime) && intCmp(host1.EndTime, host2.EndTime), 5)
	// score += weightedCompare(compareStrings(host1.TCPSequence, host2.TCPSequence), 3)
	score += weightBy(compareProcesses(host1.Processes, host2.Processes), 3)
	score += weightBy(compareUsers(host1.Users, host2.Users), 4)

	// Strong but niche, less likely to appear.
	score += weightBy(compareStatusORMs(host1.Status, host2.Status), 2)
	score += weightBy(compareExtraPortORMs(host1.ExtraPorts, host2.ExtraPorts), 3)
	score += weightBy(compareTraces(host1.Trace, host2.Trace), 3)

	// Weaker indicators
	score += weightBy(strCmp(host1.Comm, host2.Comm), 2)
	score += weightBy(strCmp(host1.OSFamily, host2.OSFamily), 2)
	score += weightBy(strCmp(host1.Info, host2.Info), 1)

	return score >= 10 // Adjust this threshold based on your confidence level
}

// compareExtraPortORMs compares two slices of ExtraPortORM for equality.
func compareExtraPortORMs(a, b []*host.ExtraPortORM) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Count != b[i].Count {
			return false
		}
		if len(a[i].Reasons) != len(b[i].Reasons) {
			return false
		}
		for j := range a[i].Reasons {
			if a[i].Reasons[j].Reason != b[i].Reasons[j].Reason {
				return false
			}
		}
	}
	return true
}

// compareTraces compares two TraceORM objects for equality.
func compareTraces(a, b *network.TraceORM) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.Id != b.Id || a.Port != b.Port || a.Protocol != b.Protocol {
		return false
	}
	return compareHops(a.Hops, b.Hops)
}

// compareHops compares two slices of HopORM for equality.
func compareHops(a, b []*network.HopORM) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Host != b[i].Host ||
			a[i].IPAddr != b[i].IPAddr ||
			a[i].RTT != b[i].RTT ||
			a[i].TTL != b[i].TTL {
			return false
		}
	}
	return true
}

// Helper function to compare the processes.
func compareProcesses(processes1, processes2 []*host.ProcessORM) bool {
	return util.CompareStringSlices(extractProcessNames(processes1), extractProcessNames(processes2))
}

// Helper function to extract process names from a list of processes.
func extractProcessNames(processes []*host.ProcessORM) []string {
	names := make([]string, 0, len(processes))
	for _, process := range processes {
		if process != nil {
			names = append(names, strings.TrimSpace(process.Executable))
		}
	}
	return names
}

// Helper function to compare users.
func compareUsers(users1, users2 []*host.UserORM) bool {
	return util.CompareStringSlices(extractUserNames(users1), extractUserNames(users2))
}

// compareStatusORMs compares two StatusORM objects for equality using weighted comparison.
func compareStatusORMs(a, b *host.StatusORM) bool {
	if a == nil || b == nil {
		return a == b
	}

	// Define weights for each field
	totalScore := 0
	maxScore := 4 * 10 // Example max score (4 fields with a weight of 10 each)

	totalScore += util.WeightedCompare(util.CompareStrings(a.Id, b.Id), 40)
	totalScore += util.WeightedCompare(util.CompareStrings(a.Reason, b.Reason), 10)
	totalScore += util.WeightedCompare(util.CompareStrings(a.ReasonTTL, b.ReasonTTL), 10)
	totalScore += util.WeightedCompare(util.CompareStrings(a.State, b.State), 10)

	// Return true if total score meets or exceeds the threshold
	return totalScore >= (maxScore / 2)
}

// Helper function to extract user names from a list of users.
func extractUserNames(users []*host.UserORM) []string {
	names := make([]string, 0, len(users))
	for _, user := range users {
		if user != nil {
			names = append(names, strings.TrimSpace(user.Name))
		}
	}
	return names
}

// Helper functions to extract relevant data from pb.HostORM (assuming string representations).
func getHostAddresses(host *host.HostORM) []string {
	if host == nil || host.Addresses == nil {
		return nil
	}
	var addresses []string
	for _, addr := range host.Addresses {
		if addr != nil {
			addresses = append(addresses, addr.Addr) // Assuming AddressORM has an IP field
		}
	}
	return addresses
}

func getHostHostnames(host *host.HostORM) []string {
	if host == nil || host.Hostnames == nil {
		return nil
	}
	var hostnames []string
	for _, hn := range host.Hostnames {
		if hn != nil {
			hostnames = append(hostnames, hn.Name) // Assuming HostnameORM has a Name field
		}
	}
	return hostnames
}

// // IsHostUnambiguouslyIdentifiable checks selected fields ending with *ID that are non-nil and attempts to find an existing host in the database.
// // Returns true if the host is unambiguously identified as the same.
// func IsHostUnambiguouslyIdentifiable(host *pb.HostORM, db *Database) (bool, *pb.HostORM) {
// 	if host == nil {
// 		return false, nil
// 	}
//
// 	// Selected fields to check for unambiguous identification
// 	idFields := []string{
// 		"TraceId",
// 		"TCPSequenceId",
// 		"ICMPResponseId",
// 		"FileSystemId",
// 		"DistanceId",
// 		"UptimeId",
// 		"OSId",
// 	}
//
// 	hostValue := reflect.ValueOf(*host)
//
// 	// Iterate through selected fields and check if they identify an existing host
// 	for _, fieldName := range idFields {
// 		fieldValue := hostValue.FieldByName(fieldName)
//
// 		if fieldValue.IsValid() && !fieldValue.IsNil() {
// 			id := fieldValue.Elem().String() // Get the ID value as a string
// 			// Check the database for an existing host with this ID
// 			existingHost := db.FindHostByID(fieldName, id)
// 			if existingHost != nil {
// 				return true, existingHost
// 			}
// 		}
// 	}
//
// 	// No unambiguous identification found
// 	return false, nil
// }
//
// // FindHostByID simulates a database query to find a host by a specific ID field.
// func (db *Database) FindHostByID(fieldName, id string) *pb.HostORM {
// 	for _, host := range db.hosts {
// 		hostValue := reflect.ValueOf(*host)
// 		fieldValue := hostValue.FieldByName(fieldName)
//
// 		if fieldValue.IsValid() && !fieldValue.IsNil() && fieldValue.Elem().String() == id {
// 			return host
// 		}
// 	}
// 	return nil
// }
