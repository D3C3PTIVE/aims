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

import (
	scan "github.com/d3c3ptive/aims/scan/pb"
)

// Result - A type containing various objects that are outputs of a scan.
// It has only one .Target, which theoretically means that we must have
// n Results for n Results.
// This type is to be created from and used by a scan.Run type, which has
// various methods to set up, populate, curate and save the data from a
// complete Scan, sometimes concurrently.
// A Result is not meant to be saved in a database:
// it is only used as a feeder type for the scan.Run.
type Result scan.Result

// ToPB - Get the Protobuf object for the Result.
func (r *Result) ToPB() *scan.Result {
	return (*scan.Result)(r)
}
