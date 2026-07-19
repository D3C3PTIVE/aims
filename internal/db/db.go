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
