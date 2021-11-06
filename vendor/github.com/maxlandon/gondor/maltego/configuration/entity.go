package configuration

/*
   Gondor - Go Maltego Transform Framework
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

// EntityCategory - A type holding information on a category
// of Entities, and able to write itself as XML for a configuration.
type EntityCategory struct {
}

// WriteConfig - The EntityCategory creates a file in
// path/EntityCategories/EntityCategoryName, and writes
// itself as an XML message into it.
func (ec EntityCategory) WriteConfig(path string) (err error) {
	return
}
