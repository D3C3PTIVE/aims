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
	"os"
	"testing"

	nmapscan "github.com/d3c3ptive/nmap"

	pb "github.com/d3c3ptive/aims/scan/pb"
)

// TestRunNmapIntegration proves the native-run path — the AIMS-native nmap fork's
// Scanner.Run() parsing real nmap XML into a *scan.Run, the exact value `scan run nmap`
// hands to Scans.Create. Opt-in (needs the nmap binary): set AIMS_NMAP_IT=1. Uses a
// -sT connect scan of localhost, so it needs no privileges and no external network.
func TestRunNmapIntegration(t *testing.T) {
	if os.Getenv("AIMS_NMAP_IT") == "" {
		t.Skip("set AIMS_NMAP_IT=1 to run (requires the nmap binary)")
	}

	scanner, err := nmapscan.NewScanner(
		nmapscan.WithCustomArguments("-sT", "-p", "22,80,443", "127.0.0.1"),
	)
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}

	run, warnings, err := scanner.Run()
	if err != nil {
		t.Fatalf("Run: %v (warnings: %v)", err, warnings)
	}

	// The fork's Run is `type Run scan.Run` over the same scan/pb package.
	pbRun := (*pb.Run)(run)
	if pbRun.Scanner != "nmap" {
		t.Errorf("want Scanner=nmap, got %q", pbRun.Scanner)
	}
	if len(pbRun.Hosts) == 0 {
		t.Fatal("want at least the localhost host in the run")
	}
	if pbRun.RawXML == "" {
		t.Error("want RawXML populated")
	}
	t.Logf("parsed run: scanner=%q hosts=%d ports(host0)=%d rawxml=%dB",
		pbRun.Scanner, len(pbRun.Hosts), len(pbRun.Hosts[0].Ports), len(pbRun.RawXML))
}
