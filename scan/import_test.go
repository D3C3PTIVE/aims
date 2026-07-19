package scan_test

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

// This test lives in the external test package because it drives the real import
// parser (scan/nmap), which itself imports the scan root package — an internal
// (package scan) test importing it would form an import cycle.

import (
	"testing"

	"github.com/d3c3ptive/aims/scan"
	xmlnmap "github.com/d3c3ptive/aims/scan/nmap"
)

// TestImportPathIdempotent builds against the import path: parse a fixture nmap XML
// with the real import parser (nmap.FromXML), then fold the same scan twice. The
// result must be idempotent — exactly what re-importing an nmap XML must do.
func TestImportPathIdempotent(t *testing.T) {
	const fixture = `<nmaprun scanner="nmap" args="nmap -sS 10.0.0.1">
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <hostnames><hostname name="web01" type="user"/></hostnames>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack" reason_ttl="64"/>
        <service name="http" product="nginx"/>
      </port>
    </ports>
  </host>
</nmaprun>`

	run1, err := xmlnmap.FromXML([]byte(fixture))
	if err != nil {
		t.Fatalf("FromXML: %v", err)
	}
	if len(run1.Hosts) != 1 {
		t.Fatalf("fixture should parse to 1 host, got %d", len(run1.Hosts))
	}

	r := &scan.Run{}
	r.AddHosts(run1.Hosts...)

	run2, err := xmlnmap.FromXML([]byte(fixture)) // same scan imported again
	if err != nil {
		t.Fatalf("FromXML (2nd): %v", err)
	}
	r.AddHosts(run2.Hosts...)

	if len(r.Hosts) != 1 {
		t.Fatalf("re-importing the same XML must not duplicate the host, got %d", len(r.Hosts))
	}
	h := r.Hosts[0]
	if len(h.Ports) != 1 {
		t.Fatalf("want 1 port, got %d", len(h.Ports))
	}
	port := h.Ports[0]
	if port.Service == nil || port.Service.Name != "http" {
		t.Errorf("want service http preserved across re-import, got %+v", port.Service)
	}
}
