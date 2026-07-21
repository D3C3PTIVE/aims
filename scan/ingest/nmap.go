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

import (
	scandomain "github.com/d3c3ptive/aims/scan"
	nmapscan "github.com/d3c3ptive/aims/scan/nmap"
	scanpb "github.com/d3c3ptive/aims/scan/pb"
)

func init() { Register(nmapIngestor{}) }

// nmapIngestor is the reference adapter: nmap's XML output is already the model's native
// shape (the xml:"…" struct tags map straight onto the Run tree), so ingesting it is a single
// Unmarshal via scan/nmap.FromXML. masscan emits nmap-compatible XML (-oX), so masscan XML
// rides this same adapter for free — which is exactly why masscan does not need its own.
type nmapIngestor struct{}

func (nmapIngestor) Name() string { return scandomain.ScannerNmap }

func (nmapIngestor) Ingest(raw []byte) (*scanpb.Run, error) {
	run, err := nmapscan.FromXML(raw)
	if err != nil {
		return nil, err
	}
	pbRun := run.ToPB()
	if pbRun.Scanner == "" {
		pbRun.Scanner = scandomain.ScannerNmap
	}
	return pbRun, nil
}
