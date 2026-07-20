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
	"bytes"
	"encoding/json"
	"testing"

	nmappb "github.com/d3c3ptive/aims/scan/pb/nmap"

	scandomain "github.com/d3c3ptive/aims/scan"
)

// zgrabFixture is one zgrab2 output record with two modules: http (whose result carries a
// port, so it lands on a Port) and ssh (no port, so it lands as a hostscript). It exercises
// every jsonToScript branch — nested object (headers, server_id), array (tags), scalars.
const zgrabFixture = `{"ip":"10.0.0.5","domain":"host.example.com","data":{` +
	`"http":{"status":"success","protocol":"http","result":{"port":80,"status_code":200,` +
	`"headers":{"server":"nginx","content_type":"text/html"},"tags":["web","proxy"]}},` +
	`"ssh":{"status":"success","protocol":"ssh","result":{"server_id":{"raw":"SSH-2.0-OpenSSH_8.9","version":"2.0"}}}` +
	`}}`

const nmapFixture = `<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sT scanme" start="1">
<host><address addr="1.2.3.4" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
</ports></host>
</nmaprun>`

func TestRegistry(t *testing.T) {
	for _, name := range []string{"nmap", "zgrab2"} {
		if _, ok := Get(name); !ok {
			t.Errorf("expected ingestor %q registered", name)
		}
	}
	if _, err := Ingest("does-not-exist", nil); err == nil {
		t.Error("Ingest with unknown scanner should error")
	}
	names := Names()
	if len(names) < 2 || names[0] > names[len(names)-1] {
		t.Errorf("Names() should be sorted and non-empty, got %v", names)
	}
}

func TestNmapIngest(t *testing.T) {
	run, err := Ingest("nmap", []byte(nmapFixture))
	if err != nil {
		t.Fatalf("Ingest nmap: %v", err)
	}
	if run.Scanner != "nmap" {
		t.Errorf("Scanner = %q, want nmap", run.Scanner)
	}
	if len(run.Hosts) != 1 {
		t.Fatalf("hosts = %d, want 1", len(run.Hosts))
	}
	if len(run.Hosts[0].Ports) != 1 || run.Hosts[0].Ports[0].Number != 22 {
		t.Errorf("expected one port 22, got %+v", run.Hosts[0].Ports)
	}
}

func TestZgrabIngest(t *testing.T) {
	run, err := Ingest("zgrab2", []byte(zgrabFixture))
	if err != nil {
		t.Fatalf("Ingest zgrab2: %v", err)
	}
	if run.Scanner != "zgrab2" {
		t.Errorf("Scanner = %q, want zgrab2", run.Scanner)
	}
	if len(run.Hosts) != 1 {
		t.Fatalf("hosts = %d, want 1 (both modules fold onto one IP)", len(run.Hosts))
	}
	h := run.Hosts[0]

	if len(h.Addresses) != 1 || h.Addresses[0].Addr != "10.0.0.5" || h.Addresses[0].Type != "ipv4" {
		t.Errorf("address = %+v, want 10.0.0.5/ipv4", h.Addresses)
	}
	if len(h.Hostnames) != 1 || h.Hostnames[0].Name != "host.example.com" {
		t.Errorf("hostnames = %+v, want host.example.com", h.Hostnames)
	}

	// http module → port 80 with a zgrab.http script carrying the nested tree.
	if len(h.Ports) != 1 || h.Ports[0].Number != 80 {
		t.Fatalf("ports = %+v, want one port 80", h.Ports)
	}
	if h.Ports[0].Service == nil || h.Ports[0].Service.Name != "http" {
		t.Errorf("port service = %+v, want name http", h.Ports[0].Service)
	}
	httpScript := findScript(h.Ports[0].Scripts, "zgrab.http")
	if httpScript == nil {
		t.Fatalf("missing zgrab.http script on port 80")
	}
	if e := findElement(httpScript.Elements, "status_code"); e == nil || e.Value != "200" {
		t.Errorf("status_code element = %+v, want 200", e)
	}
	headers := findTable(httpScript.Tables, "headers")
	if headers == nil {
		t.Fatalf("missing headers table")
	}
	if e := findElement(headers.Elements, "server"); e == nil || e.Value != "nginx" {
		t.Errorf("headers.server = %+v, want nginx", e)
	}
	tags := findTable(httpScript.Tables, "tags")
	if tags == nil || len(tags.Elements) != 2 || tags.Elements[0].Value != "web" {
		t.Errorf("tags table = %+v, want [web proxy]", tags)
	}

	// ssh module → no port → hostscript.
	sshScript := findScript(h.HostScripts, "zgrab.ssh")
	if sshScript == nil {
		t.Fatalf("missing zgrab.ssh hostscript")
	}
	serverID := findTable(sshScript.Tables, "server_id")
	if serverID == nil || findElement(serverID.Elements, "version") == nil {
		t.Errorf("server_id table = %+v, want nested version element", serverID)
	}
}

// TestIngestFoldIdempotent: folding an ingested Run's hosts into a Run twice must not
// duplicate — ingest output flows through the same host.SameHost/MergeHost fold as every
// other ingest path, so re-applying the same evidence is a no-op on the count.
func TestIngestFoldIdempotent(t *testing.T) {
	run, err := Ingest("zgrab2", []byte(zgrabFixture))
	if err != nil {
		t.Fatalf("Ingest zgrab2: %v", err)
	}

	folded := &scandomain.Run{}
	folded.AddHosts(run.Hosts...)
	first := len(folded.Hosts)
	folded.AddHosts(run.Hosts...)
	second := len(folded.Hosts)

	if first != 1 || second != 1 {
		t.Errorf("host count after 1x/2x fold = %d/%d, want 1/1", first, second)
	}
}

// TestZgrabRunIdentity: zgrab has no nmap-style run metadata, so the ingestor stamps the raw
// output as RawXML — the run identity. Same bytes → same identity (idempotent re-import);
// different bytes → different identity (distinct runs, not collapsed by AreScansIdentical).
func TestZgrabRunIdentity(t *testing.T) {
	a, err := Ingest("zgrab2", []byte(zgrabFixture))
	if err != nil {
		t.Fatal(err)
	}
	if a.RawXML == "" {
		t.Fatal("zgrab run should carry RawXML as its identity")
	}

	same, _ := Ingest("zgrab2", []byte(zgrabFixture))
	if same.RawXML != a.RawXML {
		t.Error("re-ingesting the same bytes must yield the same identity")
	}

	other := `{"ip":"9.9.9.9","data":{"ssh":{"status":"success","protocol":"ssh","result":{"x":1}}}}`
	b, err := Ingest("zgrab2", []byte(other))
	if err != nil {
		t.Fatal(err)
	}
	if b.RawXML == a.RawXML {
		t.Error("different zgrab files must have different RawXML identity")
	}
}

func TestJSONToScriptShapes(t *testing.T) {
	var v any
	dec := json.NewDecoder(bytes.NewReader([]byte(
		`{"scalar":"s","num":7,"obj":{"k":"v"},"arr":[1,2]}`)))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		t.Fatal(err)
	}

	s := jsonToScript("test", v)
	if findElement(s.Elements, "scalar") == nil || findElement(s.Elements, "num") == nil {
		t.Errorf("expected scalar+num elements, got %+v", s.Elements)
	}
	if e := findElement(s.Elements, "num"); e == nil || e.Value != "7" {
		t.Errorf("num element = %+v, want 7 (integral, not 7.0)", e)
	}
	if obj := findTable(s.Tables, "obj"); obj == nil || findElement(obj.Elements, "k") == nil {
		t.Errorf("expected obj table with element k, got %+v", s.Tables)
	}
	if arr := findTable(s.Tables, "arr"); arr == nil || len(arr.Elements) != 2 {
		t.Errorf("expected arr table with 2 indexed elements, got %+v", arr)
	}
	if s.Output == "" {
		t.Error("expected Output to carry a compact JSON summary")
	}
}

func findScript(scripts []*nmappb.Script, name string) *nmappb.Script {
	for _, s := range scripts {
		if s.Name == name {
			return s
		}
	}
	return nil
}

func findTable(tables []*nmappb.Table, key string) *nmappb.Table {
	for _, tb := range tables {
		if tb.Key == key {
			return tb
		}
	}
	return nil
}

func findElement(elements []*nmappb.Element, key string) *nmappb.Element {
	for _, e := range elements {
		if e.Key == key {
			return e
		}
	}
	return nil
}
