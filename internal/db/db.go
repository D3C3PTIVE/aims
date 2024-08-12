package db

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
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// FilterNew accepts to objects of the same type and compares it with a user-provided equality tester.
func FilterNew[object any](newTypes, existingTypes []object, cmp func(a, b object) bool) (filtered []object) {
    if cmp == nil {
        return newTypes
    }

	for _, newHost := range newTypes {
		isIdentical := false
		for _, existingHost := range existingTypes {
			if cmp(newHost, existingHost) {
				isIdentical = true
				break
			}
		}

		// If no identical host was found in the existing hosts, add the new host to the filtered list
		if !isIdentical {
			filtered = append(filtered, newHost)
		}
	}

	return filtered
}

// Preload loads a given database with preload hosts association clauses before querying.
func Preload(database *gorm.DB, filts map[string]bool) *gorm.DB {
	preloaded := database.Preload(clause.Associations)

	for name, load := range filts {
		if !load {
			continue
		}

		preloaded = preloaded.Preload(name)
	}

	return preloaded
}
