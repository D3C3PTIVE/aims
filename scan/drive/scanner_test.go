package drive

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
	"context"
	"testing"

	scan "github.com/d3c3ptive/aims/scan/pb"
)

// TestScanNoTargets asserts the guard fires before any nmap exec, so the driver never launches
// a scan with an empty target list (which nmap would reject or, worse, interpret oddly). This
// needs no nmap binary.
func TestScanNoTargets(t *testing.T) {
	if _, _, err := (Nmap{}).Scan(context.Background(), nil); err == nil {
		t.Error("Scan with no targets should error")
	}
	if _, _, err := (Nmap{}).Scan(context.Background(), []*scan.Target{{}}); err == nil {
		t.Error("Scan with only empty targets should error")
	}
}

// Nmap must satisfy the Scanner interface.
var _ Scanner = Nmap{}
