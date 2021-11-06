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
	"encoding/xml"

	"github.com/maxlandon/gondor/maltego/configuration"
)

// TransformSetting - An individual Transform Setting, which can be customized
// by a user in control of a Transform type (through its .Settings field).
type TransformSetting struct {
	Name        string
	Description string
	Default     interface{} // The default value CAN ONLY BE a string, boolean or int
	Optional    bool
	Popup       bool
}

// CmdLineTransformSetting - Create a new special Transform property
// for local execution, if the transform is ran locally.
func (t *Transform) CmdLineTransformSetting(command string, args ...[]string) {

	// Add one property for the command
	// "transform.local.command"

	// And another property for the args
	// "transform.local.parameters"
}

// CmdWorkDirTransformSetting - Specify the working
// directory to be used when executing the transform locally.
func (t *Transform) CmdWorkDirTransformSetting(path string) {
}

// CmdDebugTransformSetting - Add a property for controlling whether the
// transform is to be ran locally in Debug mode, and the default value.
func (t *Transform) CmdDebugTransformSetting(isDefault bool) {

}

// toTransformProperty - The setting wraps itself into a Transform property,
// the latter being in charge of XML marshalling/unmarshalling for the config.
func (t *TransformSetting) toTransformProperty() (tp configuration.TransformProperty) {

	// Don't forget, we don't have a Type field, so we must
	// use the config.PropertyType string version of the interface
	// after checking its a good one (string/int/bool)

	return
}

// TransformSettings - Holds all settings for
// a Transform, and their local configurations.
type TransformSettings struct {
	Enabled    bool
	RunWithAll bool
	Favorite   bool
	Accepted   bool               `xml:"disclaimerAccepted,attr"`
	ShowHelp   bool               `xml:"showHelp,attr"`
	settings   []TransformSetting // The settings added by the user, before XML marshalling
}

// MarshalXML - The Transform Settings implement the xml.Marshaller interface in order to
// marshal a few of its elements that are not accessible to Transform writers, like Properties.
func (ts *TransformSettings) MarshalXML(e *xml.Encoder, start xml.StartElement) (err error) {
	if err = e.EncodeToken(start); err != nil {
		return
	}

	// Create a new temporary struct similar to us
	template := struct {
		Enabled    bool
		RunWithAll bool
		Favorite   bool
		Accepted   bool `xml:"disclaimerAccepted,attr"`
		ShowHelp   bool `xml:"showHelp,attr"`
		Properties []configuration.TransformProperty
	}{
		Enabled:    ts.Enabled,
		RunWithAll: ts.RunWithAll,
		Favorite:   ts.Favorite,
		Accepted:   ts.Accepted,
		ShowHelp:   ts.ShowHelp,
	}

	// Add the actual settings as properties
	for _, setting := range ts.settings {
		property := setting.toTransformProperty()
		template.Properties = append(template.Properties, property)
	}

	// And encore it to XML
	if err = e.Encode(template); err != nil {
		return
	}

	return e.EncodeToken(start.End())
}
