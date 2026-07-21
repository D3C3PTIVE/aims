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
	"testing"

	hostpb "github.com/d3c3ptive/aims/host/pb"
	scandomain "github.com/d3c3ptive/aims/scan"
)

// nucleiFixture is three real-shaped nuclei -jsonl findings (captured against a live nuclei v3.11
// run, then extended), one per line:
//   - line 1: an http finding on a bare IP with a port  → lands on 127.0.0.1 port 8000
//   - line 2: an http finding on a NAMED host with a port → lands on example.com/93.184.216.34:443
//   - line 3: a host-scoped finding (no port, type dns) on the same host → a hostscript
// Lines 2 and 3 share an IP so they must fold onto ONE host; line 1 is a distinct host.
const nucleiFixture = `{"template-id":"aims-test-200","info":{"name":"AIMS test - any 200","author":["aims"],"tags":["test","aims"],"severity":"info"},"type":"http","host":"127.0.0.1","port":"8000","scheme":"http","url":"http://127.0.0.1:8000","matched-at":"http://127.0.0.1:8000/","ip":"127.0.0.1","matcher-status":true}
{"template-id":"tls-version","info":{"name":"TLS Version","severity":"high","tags":["ssl","tls"]},"type":"http","host":"example.com","port":"443","scheme":"https","url":"https://example.com:443","matched-at":"https://example.com:443/","ip":"93.184.216.34","matcher-status":true}
{"template-id":"dns-saas-service-detection","info":{"name":"DNS SaaS","severity":"info"},"type":"dns","host":"example.com","ip":"93.184.216.34","matched-at":"example.com","extracted-results":["cname.example.net"]}`

func TestNucleiRegistry(t *testing.T) {
	if _, ok := Get("nuclei"); !ok {
		t.Fatal("expected nuclei ingestor registered")
	}
}

func TestNucleiIngest(t *testing.T) {
	run, err := Ingest("nuclei", []byte(nucleiFixture))
	if err != nil {
		t.Fatalf("Ingest nuclei: %v", err)
	}
	if run.Scanner != "nuclei" {
		t.Errorf("Scanner = %q, want nuclei", run.Scanner)
	}
	if len(run.Hosts) != 2 {
		t.Fatalf("hosts = %d, want 2 (lines 2+3 fold on one IP)", len(run.Hosts))
	}

	// --- host A: bare-IP http finding on port 8000 ---
	a := hostByAddr(run.Hosts, "127.0.0.1")
	if a == nil {
		t.Fatalf("missing host 127.0.0.1; got %+v", run.Hosts)
	}
	if len(a.Hostnames) != 0 {
		t.Errorf("bare-IP finding must not add a hostname, got %+v", a.Hostnames)
	}
	if a.Status == nil || a.Status.State != "up" || a.Status.Reason != "nuclei-response" {
		t.Errorf("host status = %+v, want up/nuclei-response", a.Status)
	}
	if len(a.Ports) != 1 || a.Ports[0].Number != 8000 {
		t.Fatalf("host A ports = %+v, want one port 8000", a.Ports)
	}
	if a.Ports[0].State == nil || a.Ports[0].State.State != "open" {
		t.Errorf("port state = %+v, want open", a.Ports[0].State)
	}
	if a.Ports[0].Service == nil || a.Ports[0].Service.Name != "http" {
		t.Errorf("port service = %+v, want http", a.Ports[0].Service)
	}
	sc := findScript(a.Ports[0].Scripts, "nuclei.aims-test-200")
	if sc == nil {
		t.Fatalf("missing nuclei.aims-test-200 script on port 8000")
	}
	// The finding's severity is preserved structurally in the NSE tree (info object → table).
	if info := findTable(sc.Tables, "info"); info == nil || findElement(info.Elements, "severity") == nil {
		t.Errorf("script info table = %+v, want a severity element", info)
	}

	// --- host B: named host, http:443 + host-scoped dns finding ---
	b := hostByAddr(run.Hosts, "93.184.216.34")
	if b == nil {
		t.Fatalf("missing host 93.184.216.34")
	}
	if len(b.Hostnames) != 1 || b.Hostnames[0].Name != "example.com" {
		t.Errorf("host B hostnames = %+v, want example.com", b.Hostnames)
	}
	if len(b.Ports) != 1 || b.Ports[0].Number != 443 {
		t.Fatalf("host B ports = %+v, want one port 443", b.Ports)
	}
	if findScript(b.Ports[0].Scripts, "nuclei.tls-version") == nil {
		t.Errorf("missing nuclei.tls-version script on port 443")
	}
	// The dns finding had no port → it must be a hostscript, not a fabricated port.
	if findScript(b.HostScripts, "nuclei.dns-saas-service-detection") == nil {
		t.Errorf("host-scoped dns finding should land as a hostscript; got %+v", b.HostScripts)
	}
}

// TestNucleiIngestIdempotent: re-ingesting the same findings must not duplicate — ingest flows
// through the same host.SameHost/MergeHost fold as every other path.
func TestNucleiIngestIdempotent(t *testing.T) {
	run, err := Ingest("nuclei", []byte(nucleiFixture))
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	folded := &scandomain.Run{}
	folded.AddHosts(run.Hosts...)
	first := len(folded.Hosts)
	folded.AddHosts(run.Hosts...)
	if second := len(folded.Hosts); first != second {
		t.Errorf("host count 1x/2x fold = %d/%d, want equal", first, second)
	}
}

// TestNucleiRunIdentity: nuclei has no run metadata, so the raw output is the run identity (RawXML).
func TestNucleiRunIdentity(t *testing.T) {
	a, err := Ingest("nuclei", []byte(nucleiFixture))
	if err != nil {
		t.Fatal(err)
	}
	if a.RawXML == "" {
		t.Fatal("nuclei run should carry RawXML as its identity")
	}
	other := `{"template-id":"x","info":{"severity":"low"},"type":"http","host":"1.1.1.1","port":"80","ip":"1.1.1.1"}`
	b, err := Ingest("nuclei", []byte(other))
	if err != nil {
		t.Fatal(err)
	}
	if b.RawXML == a.RawXML {
		t.Error("different nuclei outputs must have different RawXML identity")
	}
}

// TestFindingToResult covers the shared driver entry point: one JSONL line → one Result, and the
// skip contract for blank/garbage lines (the live stdout stream carries the odd blank line).
func TestFindingToResult(t *testing.T) {
	line := `{"template-id":"t","info":{"severity":"info"},"type":"http","host":"10.0.0.1","port":"80","scheme":"http","ip":"10.0.0.1"}`
	res, ok := FindingToResult([]byte(line))
	if !ok || res == nil {
		t.Fatalf("FindingToResult(valid) = (%v,%v), want a result", res, ok)
	}
	if res.Address == nil || res.Address.Addr != "10.0.0.1" {
		t.Errorf("result address = %+v, want 10.0.0.1", res.Address)
	}
	if res.Port == nil || res.Port.Number != 80 {
		t.Errorf("result port = %+v, want 80", res.Port)
	}
	if findScript(res.Port.Scripts, "nuclei.t") == nil {
		t.Errorf("expected nuclei.t script on the port")
	}

	if _, ok := FindingToResult([]byte("   ")); ok {
		t.Error("blank line must be skipped")
	}
	if _, ok := FindingToResult([]byte("not json")); ok {
		t.Error("unparseable line must be skipped")
	}
}

func hostByAddr(hosts []*hostpb.Host, addr string) *hostpb.Host {
	for _, h := range hosts {
		for _, a := range h.Addresses {
			if a != nil && a.Addr == addr {
				return h
			}
		}
	}
	return nil
}
