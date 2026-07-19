package util

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

import "strings"

// Helper function to add weight to comparison results.
func WeightedCompare(condition bool, weight int) int {
	if condition {
		return weight
	}
	return 0
}

// Helper function to compare two strings with tolerance for nil or empty values.
func CompareStrings(str1, str2 string) bool {
	return strings.TrimSpace(str1) != "" && strings.EqualFold(str1, str2)
}

// Helper function to compare two slices of strings with tolerance for nil or empty slices.
func CompareStringSlices(slice1, slice2 []string) bool {
	if len(slice1) == 0 || len(slice2) == 0 {
		return false
	}

	map1 := make(map[string]struct{}, len(slice1))
	for _, item := range slice1 {
		map1[strings.TrimSpace(item)] = struct{}{}
	}

	for _, item := range slice2 {
		if _, found := map1[strings.TrimSpace(item)]; found {
			return true
		}
	}

	return false
}

// Helper function to compare two integers.
func CompareInts(int1, int2 int64) bool {
	return int1 == int2
}
