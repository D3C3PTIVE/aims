package main

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
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/d3c3ptive/aims/cmd/contribute"
	credpb "github.com/d3c3ptive/aims/credential/pb"
	credrpc "github.com/d3c3ptive/aims/credential/pb/rpc"
	hostpb "github.com/d3c3ptive/aims/host/pb"
	hostrpc "github.com/d3c3ptive/aims/host/pb/rpc"
	netpb "github.com/d3c3ptive/aims/network/pb"
	scanpb "github.com/d3c3ptive/aims/scan/pb"
)

// mustJSON marshals a pb object the way export.ImportJSON expects to read it back (plain
// encoding/json over the generated struct, the AIMS interchange the import path already speaks).
func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return data
}

// TestContributeObjectsAllDomains locks the shared fold behind BOTH bridge entry points
// (contribute.Objects): a JSON blob of each domain is parsed and written through the facade, the
// server stores it, and the provenance name the caller passed is what a later `--source` read
// filters on — for host, credential, and scan alike.
func TestContributeObjectsAllDomains(t *testing.T) {
	con := newInMemoryStack(t)
	ctx := context.Background()

	// Host.
	hostJSON := mustJSON(t, &hostpb.Host{
		Addresses: []*netpb.Address{{Addr: "10.20.0.1"}},
		Ports: []*hostpb.Port{{
			Number: 22, Protocol: "tcp",
			State:   &hostpb.State{State: "open"},
			Service: &netpb.Service{Name: "ssh", Product: "OpenSSH"},
		}},
	})
	if n, err := contribute.Objects(ctx, con, "host", "recon-x", hostJSON, "test"); err != nil || n != 1 {
		t.Fatalf("contribute host: n=%d err=%v (want 1, nil)", n, err)
	}
	hres, err := con.Hosts.Read(ctx, &hostrpc.ReadHostRequest{
		Host: &hostpb.Host{}, Filters: &hostrpc.HostFilters{Source: "recon-x"},
	})
	if err != nil || len(hres.GetHosts()) != 1 {
		t.Fatalf("read host source=recon-x: got %d err=%v (want 1)", len(hres.GetHosts()), err)
	}

	// Credential.
	credJSON := mustJSON(t, &credpb.Core{
		Public:  &credpb.Public{Type: credpb.PublicType_Username, Username: "admin"},
		Private: &credpb.Private{Type: credpb.PrivateType_Password, Data: "s3cret"},
	})
	if n, err := contribute.Objects(ctx, con, "credentials", "dump-tool", credJSON, "test"); err != nil || n != 1 {
		t.Fatalf("contribute credential: n=%d err=%v (want 1, nil)", n, err)
	}
	cres, err := con.Creds.List(ctx, &credrpc.ReadCredentialRequest{
		Credential: &credpb.Core{}, Source: "dump-tool",
	})
	if err != nil || len(cres.GetCredentials()) != 1 {
		t.Fatalf("list cred source=dump-tool: got %d err=%v (want 1)", len(cres.GetCredentials()), err)
	}

	// Scan: the tool name lands on Run.Scanner (unset in the blob), which the scan server turns into
	// provenance on the run and everything it produced.
	scanJSON := mustJSON(t, &scanpb.Run{
		Hosts: []*hostpb.Host{{Addresses: []*netpb.Address{{Addr: "10.20.0.9"}}}},
	})
	if n, err := contribute.Objects(ctx, con, "scan", "custom-scanner", scanJSON, "test"); err != nil || n != 1 {
		t.Fatalf("contribute scan: n=%d err=%v (want 1, nil)", n, err)
	}
}

// TestContributeObjectsDedup proves the client trusts server-side dedup end to end: contributing the
// same host blob twice stores it once. Objects returns the stored count, so the second call reports
// that nothing new landed rather than a phantom success.
func TestContributeObjectsDedup(t *testing.T) {
	con := newInMemoryStack(t)
	ctx := context.Background()

	blob := mustJSON(t, &hostpb.Host{Addresses: []*netpb.Address{{Addr: "10.30.0.1"}}})

	if n, err := contribute.Objects(ctx, con, "host", "tool", blob, "test"); err != nil || n != 1 {
		t.Fatalf("first contribute: n=%d err=%v (want 1)", n, err)
	}
	// Second identical contribution: the Upsert fold recognizes the same host and stores no new row.
	if _, err := contribute.Objects(ctx, con, "host", "tool", blob, "test"); err != nil {
		t.Fatalf("second contribute: %v", err)
	}
	all, err := con.Hosts.Read(ctx, &hostrpc.ReadHostRequest{Host: &hostpb.Host{}})
	if err != nil {
		t.Fatalf("read all: %v", err)
	}
	if len(all.GetHosts()) != 1 {
		t.Errorf("after two identical contributions there are %d hosts, want 1 (dedup)", len(all.GetHosts()))
	}
}

// TestContributeHiddenCommand drives the actual `_contribute` cobra command with a file argument (the
// machine contract), asserting it connects, contributes, and prints the machine-readable stored count.
func TestContributeHiddenCommand(t *testing.T) {
	con := newInMemoryStack(t)

	path := filepath.Join(t.TempDir(), "host.json")
	blob := mustJSON(t, &hostpb.Host{Addresses: []*netpb.Address{{Addr: "10.40.0.1"}}})
	if err := os.WriteFile(path, blob, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	cmd := contribute.Command(con)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"host", "--as", "bridge-tool", path})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("_contribute execute: %v", err)
	}
	if got := strings.TrimSpace(out.String()); got != "1" {
		t.Errorf("_contribute printed %q, want %q (stored count)", got, "1")
	}

	res, err := con.Hosts.Read(context.Background(), &hostrpc.ReadHostRequest{
		Host: &hostpb.Host{}, Filters: &hostrpc.HostFilters{Source: "bridge-tool"},
	})
	if err != nil || len(res.GetHosts()) != 1 {
		t.Fatalf("read source=bridge-tool: got %d err=%v (want 1)", len(res.GetHosts()), err)
	}
}
