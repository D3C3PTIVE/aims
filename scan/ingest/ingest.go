package ingest

/*
   AIMS (Attacked Infrastructure Modular Specification)
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

// Package ingest is the ingest-side plug point of the scanner substrate (SCAN.md Part C):
// it turns any scanner's native output into the shared scan.Run object tree so that many
// tools contribute to and consume the same host/port/service objects. Each supported tool
// is an Ingestor registered under its name; nmap is the reference adapter (its XML already
// is the model's native shape), and the generic jsonToScript walker lets any JSON scanner
// (zgrab2, and by extension nuclei/httpx/testssl) file its bespoke output into the same
// recursive NSE Script/Table/Element tree nmap's own scripts land in — with no per-tool
// proto columns.
//
// This package sits above the scan domain and its adapters: it imports scan, scan/nmap and
// the pb packages, none of which import it back, so there is no cycle. Ingestors build only
// the in-memory Run — dedup/merge and persistence happen downstream in Scans.Create, which
// folds hosts through host.IngestHosts.

import (
	"fmt"
	"sort"
	"strings"

	scanpb "github.com/d3c3ptive/aims/scan/pb"
)

// Ingestor maps one scanner's native output into the shared scan model. Any tool that can
// emit bytes — nmap XML, masscan/zgrab JSON, a naabu port list — becomes a contributor to
// the same objects by implementing this one method. nmap.FromXML already has this shape.
type Ingestor interface {
	// Name is the scanner identifier ("nmap", "zgrab2", ...). It is both the key the
	// Ingestor registers under and the value stamped onto Run.Scanner.
	Name() string

	// Ingest parses one scanner's raw output into a scan.Run. Implementations MUST NOT
	// touch the database: they only build the in-memory Run tree. Deduplication, merge and
	// storage happen downstream via Scans.Create (which folds through host.IngestHosts), so
	// the same identity/merge primitives are shared with every other ingest path.
	Ingest(raw []byte) (*scanpb.Run, error)
}

// registry holds the known ingestors keyed by Name(). Adapter files (nmap.go, zgrab.go)
// populate it from their init(); the CLI import path reads it.
var registry = map[string]Ingestor{}

// Register makes an Ingestor available under its Name(). Adapters call it from init().
// A duplicate name panics: that is a programming error and is caught at startup.
func Register(in Ingestor) {
	name := in.Name()
	if _, dup := registry[name]; dup {
		panic(fmt.Sprintf("ingest: duplicate ingestor registered: %q", name))
	}
	registry[name] = in
}

// Get returns the Ingestor registered under name, if any.
func Get(name string) (Ingestor, bool) {
	in, ok := registry[name]
	return in, ok
}

// Names returns the sorted list of registered ingestor names (for CLI help/completion).
func Names() []string {
	names := make([]string, 0, len(registry))
	for n := range registry {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Ingest looks up the named scanner and runs it against raw. It is the one-call entry point
// the CLI uses; an unknown name yields an error that lists the scanners that are registered.
func Ingest(name string, raw []byte) (*scanpb.Run, error) {
	in, ok := Get(name)
	if !ok {
		return nil, fmt.Errorf("ingest: unknown scanner %q (known: %s)", name, strings.Join(Names(), ", "))
	}
	return in.Ingest(raw)
}
