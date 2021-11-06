package maltego

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

import (
	"sync"

	"github.com/maxlandon/gondor/maltego/configuration"
)

// Distribution - A distribution is a set of Entities, Transforms, Machines
// and all their associated data, optionally strutured into sets and categories.
// Use this type when you want to produce a Maltego Distribution file (.mtz) to
// be included into a Maltego Client.
//
// Note that you can also register your Entities/Transforms directly to a server,
// which can also produce this Distribution, but only for its own context/content.
type Distribution struct {
	// Base information

	// Contents
	entities   map[string]Entity                        // Entities write themselves to files
	transforms map[string]configuration.Transform       // Transforms write themselves to files
	machines   map[string]Machine                       // Machines write themselves to files
	servers    map[string]configuration.TransformServer // Servers write themselves to files
	// Assets

	// Other
	mutex *sync.RWMutex
}

// NewDistribution - Create a new Maltego Distribution,
// with default operating parameters and empty contents.
func NewDistribution() Distribution {
	return Distribution{
		mutex: &sync.RWMutex{},
	}
}

//
// Maltego Distribution - Contents Management -----------------------------------------
//

// RegisterEntity - Add an Entity to this distribution.
func (d *Distribution) RegisterEntity(e ValidEntity) {
}

// RegisterTransform - Register a Transform to this distribution.
func (d *Distribution) RegisterTransform(t Transform) {
}

// RegisterMachine - Register a Machine to this distribution.
func (d *Distribution) RegisterMachine(t Transform) {
}

// RegisterServer - Register a new Server to the distribution.
// This function has the following effects:
// - It merges the server Distribution contents with its own.
// - It adds a new Server XML message in its Servers/ section.
func (d *Distribution) RegisterServer(s *TransformServer) {
}

//
// Maltego Distribution - Utility Methods -----------------------------------------
//

// Merge - Given another Maltego Distribution, we are able to merge both into one.
// This is useful when you don't want to fully overwrite an existing configuration
// that you have previously loaded from disk.
// Do NOT use this function if this Distribution is a Server's one, as the Server
// will not be able to serve the content from the external distribution.
func (d *Distribution) Merge(ed *Distribution) {
	return
}

// WriteToFile - The distribution creates a temporary directory in which it outputs
// a tree containing its contents, zip it into a Maltego Distribution file (.mtz) and
// writes it to the specified path. The path must obviously be writable.
func (d *Distribution) WriteToFile(path string) (err error) {
	return
}
