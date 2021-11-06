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

import "encoding/xml"

// Field - A property field for a Maltego entity. You can use this
// type from within a transform, when you want to add a property to
// it because the input/output entity is either not a native Go type,
// or because you don't have access to it, or because you want this
// field to be added into the Maltego UI but not in the persistent Go code.
//
// Note that you can't directly set a field as an overlay when declaring it
// through this function. You need to reference it again in Entity.AddOverlay().
type Field struct {
	Name         string       `xml:"Name,attr"`         // The programmatic name, required.
	Display      string       `xml:"DisplayName,attr"`  // The display name of this field
	MatchingRule MatchingRule `xml:"MatchingRule,attr"` // The individual match rule for this field
	Alias        string       `xml:"-"`                 // An alias for the field, default to .Name
	Hidden       bool         // Hide this field in the Entity Properties window.
	ReadOnly     bool         // The user cannot edit this value from the Maltego GUI
	SampleValue  interface{}
	Value        interface{} `xml:",cdata"` // Its value, automatically passed as an XML string
}

// Properties - Holds all the Properties of an Entity, used to ensure
// there is no two properties having the same namespace+Name in the list.
type Properties map[string]Field

// MarshalXML - Properties implement the xml.Marshaller interface,
// to wrap themselves as a valid list of Maltego Overlays XML objects.
func (p Properties) MarshalXML(e *xml.Encoder, start xml.StartElement) (err error) {
	if len(p) == 0 {
		return
	}
	if err = e.EncodeToken(start); err != nil {
		return
	}
	for _, property := range p {
		e.Encode(property)
	}

	return e.EncodeToken(start.End())
}
