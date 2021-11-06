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

// TransformServer - A type holding all the information of a Transform Server,
// and able to marshal itself as an XML object for inclusion in a configuration.
type TransformServer struct {
}

// WriteConfig - The TransformServer creates a file in path/Servers/TransformServerName,
// and writes itself as an XML message into it.
func (ts TransformServer) WriteConfig(path string) (err error) {
	return
}
