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
	scanpb "github.com/d3c3ptive/aims/scan/pb"
)

// DiffStored computes true run-to-run drift between two STORED runs by re-parsing each run's
// verbatim output (Run.RawXML) into an ephemeral, pre-fold Run and diffing THOSE — rather than
// diffing the persisted host rows.
//
// Why this is needed: hosts are unified across runs (one shared row per physical host, enriched
// by host.MergeHost as each scan folds in), and every run that observed a host links that one
// shared row through run_hosts. So two runs that both saw host X read back with the SAME union
// of ports — the drift between them has already been merged away in the DB, and scan.DiffRuns
// over the stored rows reports "no changes" even when the surface genuinely moved. Each run's
// RawXML, by contrast, is that scan's own untouched observation, so re-ingesting it recovers the
// per-run snapshot the fold discarded.
//
// It returns (diff, true) only when BOTH runs carry RawXML AND a registered ingestor matches
// their Scanner; otherwise (nil, false), and the caller should fall back to scan.DiffRuns over
// whatever host trees it holds (an approximate diff, honest about its limits).
func DiffStored(a, b *scanpb.Run) (*scandomain.RunDiff, bool) {
	ea, ok := reingest(a)
	if !ok {
		return nil, false
	}
	eb, ok := reingest(b)
	if !ok {
		return nil, false
	}
	return scandomain.DiffRuns(ea, eb), true
}

// reingest re-parses a stored run's verbatim output back into an ephemeral Run through the
// ingestor registered under its Scanner. It fails (false) when the run has no RawXML, no
// ingestor is registered for its scanner, or parsing errors — every case in which the caller
// cannot trust a reparse and must fall back.
func reingest(run *scanpb.Run) (*scanpb.Run, bool) {
	if run == nil || run.GetRawXML() == "" {
		return nil, false
	}
	in, ok := Get(run.GetScanner())
	if !ok {
		return nil, false
	}
	parsed, err := in.Ingest([]byte(run.GetRawXML()))
	if err != nil || parsed == nil {
		return nil, false
	}
	return parsed, true
}
