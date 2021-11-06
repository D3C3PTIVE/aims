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

import "encoding/xml"

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

// TransformAdapter - Defines the transform adapter for the running transform. Currently, there are only
// two transform adapters available in Maltego. They are listed below. This is just an enumeration class.
type TransformAdapter string

const (
	TransformAdapterLocal   TransformAdapter = "com.paterva.maltego.transform.protocol.v2.LocalTransformAdapterV2"
	TransformAdapterLocalv2 TransformAdapter = "com.paterva.maltego.transform.protocol.v2api.LocalTransformAdapterV2"
	TransformAdapterRemote  TransformAdapter = "com.paterva.maltego.transform.protocol.v2.RemoteTransformAdapterV2"
)

// VisibilityType - Defines the visibility of a Transform
type VisibilityType string

const (
	VisibilityTypePublic  VisibilityType = "public"
	VisibilityTypePrivate VisibilityType = "private"
)

// IOConstraint - A set of Input/Output constraint parameters
// to be applied to a Entity used by a Transform.
type IOConstraint struct {
	Min  int    `xml:"min"`
	Max  int    `xml:"max"`
	Type string `xml:"type"`
}

// type OutputEntity string
// type InputEntity string

// BuiltinTransform - A builtin Maltego transform name
type BuiltinTransform string

const (
	ConvertToDomain             BuiltinTransform = "Convert to Domain"
	DomainsUsingMXNS            BuiltinTransform = "Domains using MX NS"
	FindOnWebpage               BuiltinTransform = "Find on webpage"
	RelatedEmailAddresses       BuiltinTransform = "Related Email addresses"
	DNSFromDomain               BuiltinTransform = "DNS from Domain"
	EmailAddressesFromDomain    BuiltinTransform = "Email addresses from Domain"
	IPOwnerDetail               BuiltinTransform = "IP owner detail"
	ResolveToIP                 BuiltinTransform = "Resolve to IP"
	DNSFromIP                   BuiltinTransform = "DNS from IP"
	EmailAddressesFromPerson    BuiltinTransform = "Email addresses from Person"
	InfoFromNS                  BuiltinTransform = "Info from NS"
	DomainFromDNS               BuiltinTransform = "Domain From DNS"
	FilesAndDocumentsFromDomain BuiltinTransform = "Files and Documents from Domain"
	LinksInAndOutOfSite         BuiltinTransform = "Links in and out of site"
	DomainOwnerDetail           BuiltinTransform = "Domain owner detail"
	FilesAndDocumentsFromPhrase BuiltinTransform = "Files and Documents from Phrase"
)

// TransformInfo - A type holding all user-facing information for a transform, excluding
// its input/output entities. This type is embedded into the maltego.Transform type and
// the configuration.Transform, one (used for marshalling Maltego configurations).
type TransformInfo struct {
	Name         string
	DisplayName  string `xml:"displayName,attr"`
	Description  string // Defaults to the Go-doc comment of the user-provided TransformFunc
	HelpURL      string `xml:"helpURL,attr"`
	Author       string
	Owner        string
	Version      string
	RequireInfo  bool   `xml:"requireDisplayInfo,attr"`
	Help         string `xml:",cdata"`
	Disclaimer   string `xml:",cdata"`
	StealthLevel int
	Debug        string // Whether the transform should open a debugging window in Maltego when executed.
}

// Transform - A type holding all the information for a Transform,
// and able to write itself as XML for inclusion in a configuration file
type Transform struct {
	TransformInfo
	Abstract          bool
	Template          bool
	Visibility        VisibilityType
	TransformAdapter  TransformAdapter
	Authenticator     string
	LocationRelevance string            `xml:"locationRelevance,attr"`
	Sets              []string          `xml:"defaultSets"`             // Optional name of a transform set to which we belong
	Settings          TransformSettings `xml:"Properties"`              // All transform settings, and their local configuration.
	Input             []IOConstraint    `xml:"InputConstraints>Entity"` // Input Entity, max/min/type
	Output            []IOConstraint    `xml:"OutputEntities>Entity"`   // Output Entity types/max/min
}

// WriteConfig - The transform creates a file in
// path/TransformRegistries/TransformLocal/TransformName, and
// writes itself as an XML message into it.
func (t *Transform) WriteConfig(path string) (err error) {
	// Check defaults
	if t.LocationRelevance == "" {
		t.LocationRelevance = "global"
	}
	if t.Version == "" {
		t.Version = "1.0"
	}
	return
}

// TransformSet - A set of Maltego transforms
type TransformSet struct {
	Description string
	Transforms  []Transform
}

// WriteConfig - The transform set creates a file in
// path/TransformSets/TransformSetName, and
// writes itself as an XML message into it.
func (t TransformSet) WriteConfig(path string) (err error) {
	return
}

// TransformSettings - Holds all settings for
// a Transform, and their local configurations.
type TransformSettings struct {
	Enabled    bool
	RunWithAll bool
	Favorite   bool
	Accepted   bool                `xml:"disclaimerAccepted,attr"`
	ShowHelp   bool                `xml:"showHelp,attr"`
	Settings   []TransformProperty // The settings added by the user, before XML marshalling
}

// MarshalXML - The Transform Settings implement the xml.Marshaller interface in order to
// marshal a few of its elements that are not accessible to Transform writers, like Properties.
func (ts *TransformSettings) MarshalXML(e *xml.Encoder, start xml.StartElement) (err error) {
	return
}

// TransformProperty - A type very similar to an Entity property, targeting a transform.
type TransformProperty struct {
	Name         string
	DisplayName  string
	DefaultValue string
	SampleValue  string
	Abstract     bool
	Description  string
	Hidden       bool
	Nullable     bool
	ReadOnly     bool
	Popup        bool
	Type         string // Enum
	Visibility   string // Enum
}
