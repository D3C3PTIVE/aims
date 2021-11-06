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

// Overlay - An overlay is a piece of information that is displayed
// at some position relative (close) to the Entity. An overlay can
// be a piece of text, an image or a color. You specify its position
// and its value which, for example if the Overlay type is an Image
// can hold the URL to this image, or in other cases, the name of
// the Entity property that must be used to find a value.
type Overlay struct {
	PropertyName string          `xml:"property_name,attr"` // Either an Entity property name, a URL to an image, etc
	Position     OverlayPosition `xml:"position,attr"`      // The relative position of the item relative to the Entity
	Type         OverlayType     `xml:"type,attr"`          // The type of overlay that we want to show.
}

// Overlays - Specifies how overlays are stored into an Entity Go type.
type Overlays map[OverlayPosition]Overlay

// MarshalXML - Overlays implement the xml.Marshaller interface,
// to wrap themselves as a valid list of Maltego Overlays XML objects.
func (o Overlays) MarshalXML(e *xml.Encoder, start xml.StartElement) (err error) {
	if len(o) == 0 {
		return
	}
	if err = e.EncodeToken(start); err != nil {
		return
	}
	for _, overlay := range o {
		e.Encode(overlay)
	}

	return e.EncodeToken(start.End())
}

// OverlayPosition - The position of a Maltego Entity Overlay element.
type OverlayPosition string

const (
	OverlayNorth     OverlayPosition = "N"
	OverlaySouth     OverlayPosition = "S"
	OverlayWest      OverlayPosition = "W"
	OverlayNorthWest OverlayPosition = "NW"
	OverlaySouthWest OverlayPosition = "SW"
	OverlayCenter    OverlayPosition = "C"
)

// OverlayType - The type of a Maltego Entity Overlay element.
type OverlayType string

const (
	OverlayImage  OverlayType = "image"
	OverlayColour OverlayType = "colour"
	OverlayText   OverlayType = "text"
)

// isOverlayType - Verify the overlay struct tag, and its type value
func isOverlayType(a string) bool {
	list := []OverlayType{
		OverlayText,
		OverlayImage,
		OverlayColour,
	}
	for _, b := range list {
		if string(b) == a {
			return true
		}
	}
	return false
}

// isOverlayPosition - Verify the overlay tag, and its position value
func isOverlayPosition(a string) bool {
	list := []OverlayPosition{
		OverlayCenter,
		OverlayNorth,
		OverlayNorthWest,
		OverlaySouth,
		OverlaySouthWest,
		OverlayWest,
	}
	for _, b := range list {
		if string(b) == a {
			return true
		}
	}
	return false
}

// Label - Used to convey extra information associated with an Entity in the Maltego
// client GUI. Unlike entity fields, labels are only transmitted in response messages
// and cannot be passed from transform to transform as a source of input.
type Label struct {
	Name    string `xml:"Name,attr"` // The name (key) for the label
	Content string `xml:",cdata"`    // The content, displayed in Maltego
	Type    string `xml:"Type,attr"` // The type of content (if empty, defaults to "text/html")
}
