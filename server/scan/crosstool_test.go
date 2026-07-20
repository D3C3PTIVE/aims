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

// These tests harden the "many tools contribute to the same objects" promise at the DB level:
// they verify that a non-nmap contributor (represented by a distinct Scanner) folds into the
// SAME host records as nmap — union of ports/scripts, no duplication, evidence preserved — and
// that mutation (Upsert/Delete) cascades correctly with children from more than one tool. Only
// nmap↔nmap was previously proven.

import (
	"context"
	"testing"

	hostpb "github.com/d3c3ptive/aims/host/pb"
	network "github.com/d3c3ptive/aims/network/pb"
	scanpb "github.com/d3c3ptive/aims/scan/pb"
	nmappb "github.com/d3c3ptive/aims/scan/pb/nmap"
	scanrpcpb "github.com/d3c3ptive/aims/scan/pb/rpc"
)

// toolRun builds a run attributed to `scanner`, observing one host at `addr` with the given ports.
func toolRun(scanner, rawXML, addr string, ports ...*hostpb.Port) *scanpb.Run {
	return &scanpb.Run{
		Scanner: scanner,
		RawXML:  rawXML,
		Hosts: []*hostpb.Host{{
			Addresses: []*network.Address{{Addr: addr}},
			Status:    &hostpb.Status{State: "up", Reason: scanner},
			Ports:     ports,
		}},
	}
}

func tcpPort(num uint32, service string) *hostpb.Port {
	return &hostpb.Port{
		Number:   num,
		Protocol: "tcp",
		State:    &hostpb.State{State: "open"},
		Service:  &network.Service{Name: service},
	}
}

func tcpPortScript(num uint32, service, scriptName string) *hostpb.Port {
	p := tcpPort(num, service)
	p.Scripts = []*nmappb.Script{{Name: scriptName, Output: "output-" + scriptName}}
	return p
}

func createRun(t *testing.T, s *server, run *scanpb.Run) *scanpb.Run {
	t.Helper()
	res, err := s.Create(context.Background(), &scanrpcpb.CreateScanRequest{Scans: []*scanpb.Run{run}})
	if err != nil {
		t.Fatalf("create %s run: %v", run.GetScanner(), err)
	}
	if len(res.GetScans()) == 0 {
		return nil // skipped as duplicate
	}
	return res.GetScans()[0]
}

func portByNumber(h *hostpb.Host, num uint32) *hostpb.Port {
	for _, p := range h.GetPorts() {
		if p.GetNumber() == num {
			return p
		}
	}
	return nil
}

// TestCrossToolHostMerge: nmap and zgrab observe the SAME IP on different ports. The result must
// be ONE host row carrying the union of both tools' ports, the zgrab NSE script, and nmap's
// service evidence — not two hosts, not a clobber.
func TestCrossToolHostMerge(t *testing.T) {
	s, gdb, ctx := newTestServer(t)

	nmapPort := tcpPort(22, "ssh")
	nmapPort.Service.Product = "OpenSSH" // nmap-only evidence that must survive the zgrab fold
	createRun(t, s, toolRun("nmap", "<nmap/>", "10.0.0.1", nmapPort))
	createRun(t, s, toolRun("zgrab2", "<zgrab/>", "10.0.0.1", tcpPortScript(80, "http", "zgrab.http")))

	if n := countRows(t, gdb, "hosts"); n != 1 {
		t.Errorf("hosts = %d, want 1 (zgrab host merged into the nmap host)", n)
	}
	if n := countRows(t, gdb, "ports"); n != 2 {
		t.Errorf("ports = %d, want 2 (union of :22 and :80)", n)
	}
	if n := countRows(t, gdb, "scripts"); n != 1 {
		t.Errorf("scripts = %d, want 1 (the zgrab.http script)", n)
	}
	if n := countRows(t, gdb, "runs"); n != 2 {
		t.Errorf("runs = %d, want 2", n)
	}

	// Read back the shared host (both runs point at it) and assert both tools' evidence is intact.
	res, err := s.Read(ctx, &scanrpcpb.ReadScanRequest{
		Scan:    &scanpb.Run{},
		Filters: &scanrpcpb.RunFilters{Hosts: true, Ports: true},
	})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(res.GetScans()) == 0 || len(res.GetScans()[0].GetHosts()) == 0 {
		t.Fatal("expected at least one run with a host")
	}
	h := res.GetScans()[0].GetHosts()[0]
	if len(h.GetPorts()) != 2 {
		t.Fatalf("merged host has %d ports, want 2", len(h.GetPorts()))
	}

	ssh := portByNumber(h, 22)
	if ssh == nil || ssh.GetService().GetProduct() != "OpenSSH" {
		t.Errorf("port 22 nmap evidence lost: %+v", ssh.GetService())
	}
	http := portByNumber(h, 80)
	if http == nil || len(http.GetScripts()) != 1 || http.GetScripts()[0].GetName() != "zgrab.http" {
		t.Errorf("port 80 zgrab script missing: %+v", http.GetScripts())
	}
}

// TestReimportHostTreeIdempotent: two DISTINCT runs (distinct RawXML so run-dedup does not skip)
// that observed the same host/port/script must fold into ONE host tree — the host, port and
// script are deduplicated at the DB level, and both runs link the shared host.
func TestReimportHostTreeIdempotent(t *testing.T) {
	s, gdb, ctx := newTestServer(t)
	_ = ctx

	mk := func(xml string) *scanpb.Run {
		return toolRun("zgrab2", xml, "10.0.0.5", tcpPortScript(80, "http", "zgrab.http"))
	}
	createRun(t, s, mk("<z1/>"))
	createRun(t, s, mk("<z2/>"))

	checks := []struct {
		table string
		want  int64
	}{
		{"runs", 2},       // two distinct runs
		{"hosts", 1},      // one host (deduped across runs)
		{"ports", 1},      // the port is not duplicated
		{"scripts", 1},    // the script is not duplicated (union by content)
		{"run_hosts", 2},  // both runs link the single shared host
	}
	for _, c := range checks {
		if n := countRows(t, gdb, c.table); n != c.want {
			t.Errorf("%s = %d, want %d (re-observed host tree should not duplicate)", c.table, n, c.want)
		}
	}
}

// TestCrossToolDeleteCascade: after nmap (Create) and zgrab (Upsert) both contribute to one
// shared host, deleting the nmap run must unlink only its run_hosts join — the shared host and
// ALL its ports (including nmap's :22) survive because they are owned by the host row, not the
// run, and the zgrab run still references it.
func TestCrossToolDeleteCascade(t *testing.T) {
	s, gdb, ctx := newTestServer(t)

	nmapRun := createRun(t, s, toolRun("nmap", "<nmap/>", "10.0.0.1", tcpPort(22, "ssh")))
	if _, err := s.Upsert(ctx, &scanrpcpb.UpsertScanRequest{
		Scans: []*scanpb.Run{toolRun("zgrab2", "<zgrab/>", "10.0.0.1", tcpPortScript(80, "http", "zgrab.http"))},
	}); err != nil {
		t.Fatalf("upsert zgrab run: %v", err)
	}

	// Pre-delete: 2 runs, 1 shared host, 2 ports, 1 script.
	if n := countRows(t, gdb, "hosts"); n != 1 {
		t.Fatalf("pre-delete hosts = %d, want 1", n)
	}
	if n := countRows(t, gdb, "ports"); n != 2 {
		t.Fatalf("pre-delete ports = %d, want 2", n)
	}

	if _, err := s.Delete(ctx, &scanrpcpb.DeleteScanRequest{
		Scans: []*scanpb.Run{{Id: nmapRun.GetId()}},
	}); err != nil {
		t.Fatalf("delete nmap run: %v", err)
	}

	// Post-delete: the zgrab run + the shared host with BOTH ports survive; only the nmap run
	// and its run_hosts link are gone.
	post := []struct {
		table string
		want  int64
	}{
		{"runs", 1},       // only the zgrab run remains
		{"hosts", 1},      // shared host survives (zgrab still references it)
		{"ports", 2},      // both ports survive (owned by the host, not the run)
		{"scripts", 1},    // zgrab script survives
		{"run_hosts", 1},  // only the zgrab run links the host now
	}
	for _, c := range post {
		if n := countRows(t, gdb, c.table); n != c.want {
			t.Errorf("post-delete %s = %d, want %d", c.table, n, c.want)
		}
	}
}
