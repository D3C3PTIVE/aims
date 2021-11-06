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

// Link - Access and set all settings for the link to/from this entity
type Link struct {
	Label      string
	Style      LinkStyle
	Thickness  LineThickness
	ShowLabel  LinkShowLabel
	Color      string
	Direction  LinkDirection
	properties []Field // Additional custom Link fields
}

// TODO: check link sync.Mutex not nil when instantiating

// Reverse - Set the reverse direction for this Entity link:
// insted of being Input => Output, set it to Input <= Output.
func (l *Link) Reverse() {
	l.Direction = OutputToInputLink
}

// AddField - Exactly as you can AddField() to an entity,
// you can add custom property fields to an Entity link.
func (l *Link) AddField(f Field) {
	l.properties = append(l.properties, f)
}

// LinkStyle - The appearance style of a link to between two Entities.
type LinkStyle int

const (
	// LinkNormal - Continuous line
	LinkNormal LinkStyle = iota
	// LinkDashed - Dash-cut line
	LinkDashed
	// LinkDotted - A line made of dots
	LinkDotted
	// LinkDashDot - An alternance of dashes and dots
	LinkDashDot
)

// LineThickness - The thickness of a link line between two Entities.
type LineThickness int

const (
	// LineVeryThin - The thinest line for a link
	LineVeryThin LineThickness = iota
	// LineThin - A slightly thin link
	LineThin
	// LineNormal - Normal thickness for link
	LineNormal
	// LineThick - A slightly thick link
	LineThick
	// LineVeryThick - The thickest line for a link
	LineVeryThick
)

// LinkShowLabel - Defines the display options for a link to an entity.
type LinkShowLabel int

const (
	//LinkLabelGlobal - Use the global settings from the Maltego client to
	// determine if the link should show or hide its label.
	LinkLabelGlobal LinkShowLabel = iota
	// LinkLabelShow - Show the label of the link to the Entity, if any.
	LinkLabelShow
	// LinkLabelHide - Hide the label of the link to the Entity.
	LinkLabelHide
)

// LinkDirection - The directionality of a link to an Entity.
type LinkDirection string

const (
	InputToOutputLink LinkDirection = "input-to-output"
	OutputToInputLink LinkDirection = "output-to-input"
	Bidirectional     LinkDirection = "bidirectional"
)

// BookmarkColor - The color of an Entity bookmark
type BookmarkColor string

const (
	BOOKMARK_COLOR_NONE   BookmarkColor = "-1"
	BOOKMARK_COLOR_BLUE   BookmarkColor = "0"
	BOOKMARK_COLOR_GREEN  BookmarkColor = "1"
	BOOKMARK_COLOR_YELLOW BookmarkColor = "2"
	BOOKMARK_COLOR_PURPLE BookmarkColor = "3"
	BOOKMARK_COLOR_RED    BookmarkColor = "4"
)
