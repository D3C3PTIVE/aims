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

// This file is a reproduction of the Canari Framework configuration.py file:
//
// """
// This module defines the various configuration elements that appear in the Maltego
// profile files (*.mtz). These configuration elements specify the configuration options
// for Maltego transforms, servers, entities, machines, and viewlets. Canari uses these
// elements to generate Maltego profiles that can be imported into Maltego.
// """
//
// We have added some utility code to generate the corresponding configurations.

// PropertyType - String representation of a Property type
type PropertyType string

const (
	PropertyTypeString  PropertyType = "string"
	PropertyTypeBoolean PropertyType = "boolean"
	PropertyTypeInteger PropertyType = "int"
)

type globalConfig struct {
}

// GlobalConfigFromFile - Reads the Maltego Transform Configuration file located
// at path. If not found, returns a default, empty (but non-nil) configuration, and
// an error to indicate the user that some action might be required for perfect work.
func GlobalConfigFromFile(path string) (conf *globalConfig, err error) {
	return
}

// GlobalConfigFromBytes - Unmarshal a Maltego Transform Configuration as bytes
// If unmarshaling fails, returns a default, empty (but non-nil) configuration, and
// an error to indicate the user that some action might be required for perfect work.
func GlobalConfigFromBytes(data []byte) (conf *globalConfig, err error) {
	return
}
