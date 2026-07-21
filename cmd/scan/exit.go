package scan

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

// ExitSuccess is nmap's Finished.Exit value (xml:"exit,attr") on a run that completed without
// error. Exit is a plain string field, not an enum — this const is the one authoritative spelling
// for the client-side live/history views to compare against instead of a bare "success" literal.
// Mirrors scan.ExitInterrupted (scan/scan.go), the server/scan-side counterpart that stamps and
// compares the same contract; that is the natural place to consolidate this const too if/when
// server/scan and scan/ingest are touched.
const ExitSuccess = "success"
