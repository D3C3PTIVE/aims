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

import (
	"github.com/d3c3ptive/aims/internal/util"
	pb "github.com/d3c3ptive/aims/proto/network"
)

// AreServicesIdentical compares two ServiceORM objects for similarity based on weighted fields.
func AreServicesIdentical(service1, service2 *pb.ServiceORM) bool {
	if service1 == nil || service2 == nil {
		return service1 == service2
	}

	weightBy := util.WeightedCompare
	intCmp := util.CompareInts
	strCmp := util.CompareStrings

	totalWeight := 0
	matchScore := 0

	// Check if the service is running on a given port, and if yes, try
	// to find an identical service running on it.

	// High Importance (Weight 3)
	totalWeight += 3 * 4
	matchScore += weightBy(strCmp(service1.Protocol, service2.Protocol), 3)
	matchScore += weightBy(strCmp(service1.Product, service2.Product), 3)
	matchScore += weightBy(strCmp(service1.Version, service2.Version), 3)
	matchScore += weightBy(strCmp(service1.ServiceFP, service2.ServiceFP), 3)
	matchScore += weightBy(strCmp(service1.ExtraInfo, service2.ExtraInfo), 3)

	// Medium Importance (Weight 2)
	totalWeight += 2 * 3
	matchScore += weightBy(strCmp(service1.Hostname, service2.Hostname), 2)
	matchScore += 2 * boolToFloat(service1.Authenticated == service2.Authenticated)
	matchScore += weightBy(strCmp(service1.RPCNum, service2.RPCNum), 2)

	// Low Importance (Weight 1)
	totalWeight += 1 * 8
	matchScore += weightBy(strCmp(service1.DeviceType, service2.DeviceType), 1)
	matchScore += weightBy(strCmp(service1.OSType, service2.OSType), 1)
	matchScore += weightBy(strCmp(service1.Method, service2.Method), 1)
	matchScore += weightBy(strCmp(service1.Tunnel, service2.Tunnel), 1)
	matchScore += weightBy(strCmp(service1.HighVersion, service2.HighVersion), 1)
	matchScore += weightBy(strCmp(service1.LowVersion, service2.LowVersion), 1)
	matchScore += weightBy(intCmp(int64(service1.Confidence), int64(service2.Confidence)), 1)

	// Determine if the services are sufficiently identical
	// Depending on the strictness, you can set a threshold.
	// For example, a score of 0.8 (80%) might be considered a match.
	similarityThreshold := 0.8
	similarityScore := float64(matchScore) / float64(totalWeight)
	return similarityScore >= similarityThreshold
}

// boolToFloat converts a boolean comparison result to a float (1 for true, 0 for false).
func boolToFloat(result bool) int {
	if result {
		return 1
	}
	return 0
}
