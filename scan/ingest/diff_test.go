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
	"fmt"
	"testing"

	scanpb "github.com/d3c3ptive/aims/scan/pb"
)

// nmapXML builds a minimal but valid nmap XML run observing one host at addr with the given open
// TCP ports — enough for FromXML to yield a host with those ports.
func nmapXML(addr string, ports ...int) string {
	xml := `<?xml version="1.0"?><nmaprun scanner="nmap" args="nmap ` + addr + `">` +
		`<host><status state="up" reason="syn-ack"/>` +
		`<address addr="` + addr + `" addrtype="ipv4"/><ports>`
	for _, p := range ports {
		xml += fmt.Sprintf(`<port protocol="tcp" portid="%d"><state state="open" reason="syn-ack"/>`+
			`<service name="svc%d"/></port>`, p, p)
	}
	xml += `</ports></host></nmaprun>`
	return xml
}

// storedNmapRun mimics what the DB holds after import: a run stamped with the scanner name and its
// verbatim RawXML. Crucially it carries NO Hosts — as if host unification had folded them into a
// shared row elsewhere — so the ONLY way to recover per-run drift is by re-parsing RawXML.
func storedNmapRun(addr string, ports ...int) *scanpb.Run {
	return &scanpb.Run{Scanner: "nmap", RawXML: nmapXML(addr, ports...)}
}

// TestDiffStoredRecoversDriftFromRawXML is the core of the fix: two stored runs whose Hosts have
// been unified away (empty Hosts slices) still diff correctly, because DiffStored re-parses each
// run's RawXML. Run a saw :22; run b saw :22 and :80 — the diff must surface :80 as a new port on
// the shared host, which a stored-rows diff (scan.DiffRuns over empty Hosts) could never see.
func TestDiffStoredRecoversDriftFromRawXML(t *testing.T) {
	a := storedNmapRun("10.0.0.1", 22)
	b := storedNmapRun("10.0.0.1", 22, 80)

	d, exact := DiffStored(a, b)
	if !exact {
		t.Fatal("DiffStored returned exact=false for two runs that both carry nmap RawXML")
	}
	if d.Empty() {
		t.Fatal("DiffStored found no drift, but :80 opened between the runs")
	}
	if len(d.NewHosts) != 0 || len(d.GoneHosts) != 0 {
		t.Fatalf("expected a changed host, not new/gone: new=%d gone=%d", len(d.NewHosts), len(d.GoneHosts))
	}
	if len(d.Changed) != 1 {
		t.Fatalf("expected 1 changed host, got %d", len(d.Changed))
	}
	hd := d.Changed[0]
	if len(hd.NewPorts) != 1 || hd.NewPorts[0].GetNumber() != 80 {
		t.Fatalf("expected exactly :80 as a new port, got %+v", hd.NewPorts)
	}
	if len(hd.GonePorts) != 0 {
		t.Fatalf("expected no gone ports, got %+v", hd.GonePorts)
	}
}

// TestDiffStoredNewAndGoneHosts covers whole-host appearance/disappearance across the reparse.
func TestDiffStoredNewAndGoneHosts(t *testing.T) {
	a := storedNmapRun("10.0.0.1", 22)
	b := storedNmapRun("10.0.0.2", 22)

	d, exact := DiffStored(a, b)
	if !exact {
		t.Fatal("expected exact=true")
	}
	if len(d.NewHosts) != 1 || d.NewHosts[0].Addresses[0].Addr != "10.0.0.2" {
		t.Fatalf("expected 10.0.0.2 as a new host, got %+v", d.NewHosts)
	}
	if len(d.GoneHosts) != 1 || d.GoneHosts[0].Addresses[0].Addr != "10.0.0.1" {
		t.Fatalf("expected 10.0.0.1 as a gone host, got %+v", d.GoneHosts)
	}
}

// TestDiffStoredFallsBackWithoutRawXML: when either run lacks RawXML (a live streamed scan that
// never captured verbatim output), DiffStored reports exact=false so the caller degrades to the
// approximate stored-rows diff instead of silently returning an empty (wrong) result.
func TestDiffStoredFallsBackWithoutRawXML(t *testing.T) {
	withRaw := storedNmapRun("10.0.0.1", 22)
	noRaw := &scanpb.Run{Scanner: "nmap"} // no RawXML

	if _, exact := DiffStored(withRaw, noRaw); exact {
		t.Error("expected exact=false when the second run has no RawXML")
	}
	if _, exact := DiffStored(noRaw, withRaw); exact {
		t.Error("expected exact=false when the first run has no RawXML")
	}
}

// TestDiffStoredUnknownScannerFallsBack: a run whose Scanner has no registered ingestor cannot be
// re-parsed, so DiffStored must decline (exact=false) rather than guess.
func TestDiffStoredUnknownScannerFallsBack(t *testing.T) {
	a := &scanpb.Run{Scanner: "mystery-tool", RawXML: "{}"}
	b := storedNmapRun("10.0.0.1", 22)

	if _, exact := DiffStored(a, b); exact {
		t.Error("expected exact=false for an unregistered scanner")
	}
}
