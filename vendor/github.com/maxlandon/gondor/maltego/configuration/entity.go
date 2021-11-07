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

// Field - A property field for a Maltego entity.
type Field struct {
	Name         string `xml:"name,attr"` // The programmatic name, required.
	Type         string
	Nullable     bool   `xml:"nullable,attr"`
	Display      string `xml:"displayName,attr,omitempty"` // The display name of this field
	Description  string
	MatchingRule string `xml:"matchingRule,attr"` // The individual match rule for this field
	Alias        string `xml:"-"`                 // An alias for the field, default to .Name
	Hidden       bool   `xml:"hidden,attr"`       // Hide this field in the Entity Properties window.
	ReadOnly     bool   `xml:"readonly,attr"`     // The user cannot edit this value from the Maltego GUI
	SampleValue  interface{}
	DefaultValue interface{} `xml:",omitempty"` // Its value, automatically passed as an XML string
}

// Properties - All Properties for an Entity.
type Properties struct {
	Value  string   `xml:"value,attr,omitempty"`
	Groups []string // Not implemented in Maltego or Canari
	Fields []Field  `xml:"Fields>Field,omitempty"`
}

// Converter - Allows you to choose whether a regular expression is used to
// automatically identify an Entity when text is pasted onto a graph from the clipboard.
type Converter struct {
	Value       interface{} `xml:",cdata"`
	RegexGroups []string    `xml:"RegexGroups>RegexGroup,omitempty"`
}

// Entity - A type holding all the information for an Entity, and
// able to write itself as XML for inclusion in a configuration file.
type Entity struct {
	ID              string     // Namespace + Type
	DisplayName     string     `xml:"displayName,attr,omitempty"`
	Plural          string     `xml:"displayNamePlural,attr,omitempty"`
	Description     string     `xml:",omitempty"`
	Category        string     `xml:",omitempty"`
	SmallIconTag    string     `xml:"SmallIcon,omitempty"`
	LargeIconTag    string     `xml:"Icon,omitempty"`
	SmallIcon       string     `xml:"smallIconResource,attr,omitempty"`
	LargeIcon       string     `xml:"largeIconResource,attr,omitempty"`
	AllowedRoot     bool       `xml:",omitempty"`
	ConversionOrder int64      `xml:"conversionOrder,attr,omitempty"`
	Visible         bool       `xml:",omitempty"`
	Converter       Converter  `xml:",omitempty"`
	BaseEntities    []string   `xml:"BaseEntities>BaseEntity,omitempty"`
	Properties      Properties `xml:"Properties"`
}
