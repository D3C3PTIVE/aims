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
)

// Message - A type containing all the output elements of a Transform.
type Message struct {
	x xml.Name // Modify the xml tag name for this type ("MaltegoMessage")

	// Request
	Value      string             `xml:"-"`               // Fetched with custom UnmarshalXML
	Type       string             `xml:"-"`               // Fetched from the Entity
	Weight     int                `xml:"Weight"`          // Weight of Input Entity
	Slider     int                `xml:"-"`               // Transform limits, fetched with custom UnmarshalXML
	Geneaology []Geneaology       `xml:"Geneaology"`      // All the parent transforms and entities tree
	Entity     Entity             `xml:"-"`               // A unique input Entity
	Settings   []TransformSetting `xml:"TransformFields"` // Settings for Transform (global/local, and their properties)

	// Response
	Response  TransformResponseMessage  `xml:"MaltegoTransformResponseMessage,omitempty"`
	Exception TransformExceptionMessage `xml:"MaltegoTransformExceptionMessage,omitempty"`
}

// UnmarshalXML - The Message type needs to do a bit of custom
// XML unmarshalling because of unwished lists to process.
func (m Message) UnmarshalXML(d *xml.Decoder, start xml.StartElement) (err error) {

	// Temporary types/structs for deserialing fields that cannot be
	// directly unmarshaled into the message, because they are lists.
	type slider = struct {
		SoftLimit int `xml:"SoftLimit,attr"`
	}
	temp := struct {
		// Input
		Values   []string `xml:"Value"`
		Entities []Entity `xml:"Entity"`
		// Transform settings
		Slider slider `xml:"Limits"`
	}{}
	if err = d.Decode(&temp); err != nil {
		return
	}

	// Then we can decode the whole Message type.
	if err = d.Decode(&m); err != nil {
		return
	}

	// And finally write the temp struct contents to the Message
	m.Entity = temp.Entities[0] // Hard-coded in Maltego Python/Go libs
	m.Type = m.Entity.Type
	m.Value = temp.Values[0]         // Same hard-coding
	m.Slider = temp.Slider.SoftLimit // And finally, the limit of output entities

	return
}

// TransformResponseMessage - A type containing all the output elements of a Transform.
type TransformResponseMessage struct {
	Entities []Entity    `xml:"Entities"`   // All entities to be returned as the Transform output.
	Messages []MessageUI `xml:"UIMessages"` // Transform log messages
}

// TransformExceptionMessage - A type containing all the exceptions (errors) that
// occured during the execution of a Transform. While you can return an error at
// any point in your code, thereby terminating execution, you can also simply log
// them with Transform.AddError(), and they will be passed along any other output.
type TransformExceptionMessage struct {
	Exceptions []Exception
}

// Exception - Term for an error in a Transform. Can be terminating, or not.
type Exception string

// MessageUI - A log message passed along a Transform
// output for display in the Maltego transform window.
type MessageUI struct {
	Text string `xml:"text"`
	Type string `xml:"type"`
}

// Geneaology - A geneaologic node, member of a Geneaology
// (list of nodes) transmitted in a Maltego Transform Request.
type Geneaology struct {
	Name    string
	OldName string
	Type    string
}
