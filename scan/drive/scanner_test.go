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
	"os"
	"strings"
	"testing"

	scan "github.com/d3c3ptive/aims/scan/pb"
)

// TestLookToolPath covers the sbin-fallback resolver: the $PATH hit, the not-found miss, and — the
// bug this fixes — resolving a tool that lives only in a standard sbin dir absent from $PATH.
func TestLookToolPath(t *testing.T) {
	if _, ok := lookToolPath("sh"); !ok {
		t.Error("expected to resolve 'sh' via $PATH")
	}
	if p, ok := lookToolPath("definitely-not-a-real-tool-xyz"); ok {
		t.Errorf("nonexistent tool resolved to %q", p)
	}
	// The exact bug: setcap/getcap live in /usr/sbin, commonly off a non-root $PATH. If present there,
	// the fallback must find it.
	for _, tool := range []string{"setcap", "getcap"} {
		if _, err := os.Stat("/usr/sbin/" + tool); err == nil {
			if _, ok := lookToolPath(tool); !ok {
				t.Errorf("%s present in /usr/sbin but lookToolPath did not find it (sbin fallback broken)", tool)
			}
		}
	}
}

// TestScanNoTargets asserts the guard fires before any nmap exec, so the driver never launches
// a scan with an empty target list (which nmap would reject or, worse, interpret oddly). This
// needs no nmap binary.
func TestScanNoTargets(t *testing.T) {
	if _, _, _, _, err := (Nmap{}).Scan(context.Background(), nil); err == nil {
		t.Error("Scan with no targets should error")
	}
	if _, _, _, _, err := (Nmap{}).Scan(context.Background(), []*scan.Target{{}}); err == nil {
		t.Error("Scan with only empty targets should error")
	}
}

// Nmap must satisfy the Scanner interface.
var _ Scanner = Nmap{}

// TestExtractXMLOutput covers the output-file handling (#2b): a user's -oX/-oA must be pulled out of
// the nmap args (so the driver's own -oX - has no rival) and mapped to a file the driver writes.
func TestExtractXMLOutput(t *testing.T) {
	tests := []struct {
		name        string
		in          []string
		wantCleaned []string
		wantXML     string
	}{
		{
			"the reported case: -oX <file> is extracted, not passed to nmap",
			[]string{"-A", "-p-", "--osscan-guess", "-oX", "lan.xml", "192.168.1.1/24"},
			[]string{"-A", "-p-", "--osscan-guess", "192.168.1.1/24"},
			"lan.xml",
		},
		{
			"-oA keeps .nmap/.gnmap and maps the XML to <base>.xml",
			[]string{"-sV", "-oA", "scan", "10.0.0.1"},
			[]string{"-sV", "-oN", "scan.nmap", "-oG", "scan.gnmap", "10.0.0.1"},
			"scan.xml",
		},
		{
			"no output flag: args pass through unchanged",
			[]string{"-sT", "-p22", "10.0.0.1"},
			[]string{"-sT", "-p22", "10.0.0.1"},
			"",
		},
		{
			"-oN/-oG (non-XML formats) are left untouched — they coexist with -oX -",
			[]string{"-oN", "out.nmap", "-oG", "out.gnmap", "10.0.0.1"},
			[]string{"-oN", "out.nmap", "-oG", "out.gnmap", "10.0.0.1"},
			"",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cleaned, xml := extractXMLOutput(tt.in)
			if xml != tt.wantXML {
				t.Errorf("xmlFile = %q, want %q", xml, tt.wantXML)
			}
			if strings.Join(cleaned, " ") != strings.Join(tt.wantCleaned, " ") {
				t.Errorf("cleaned = %v, want %v", cleaned, tt.wantCleaned)
			}
		})
	}
}
