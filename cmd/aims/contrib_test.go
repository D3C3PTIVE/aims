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
	"context"
	"testing"

	"github.com/d3c3ptive/aims/client/contrib"
	credpb "github.com/d3c3ptive/aims/credential/pb"
	credrpc "github.com/d3c3ptive/aims/credential/pb/rpc"
	hostpb "github.com/d3c3ptive/aims/host/pb"
	hostrpc "github.com/d3c3ptive/aims/host/pb/rpc"
	netpb "github.com/d3c3ptive/aims/network/pb"
)

// TestContribHostsAddThroughFacade proves the client-side contribution facade closes the loop a
// foreign tool cares about: one As(...).Hosts.Add(...) call reaches the database through the full
// client → teamclient → bufconn → teamserver → server/host → GORM path, the server's own dedup
// fold makes the contribution idempotent (re-adding is a no-op, not a duplicate), and the provenance
// stamp the facade applies is what a later `--source <tool>` read filters on.
func TestContribHostsAddThroughFacade(t *testing.T) {
	con := newInMemoryStack(t)
	db := contrib.New(con).As("recon-x")

	host := &hostpb.Host{
		Addresses: []*netpb.Address{{Addr: "10.10.0.5"}},
		Hostnames: []*hostpb.Hostname{{Name: "target-a"}},
		Ports: []*hostpb.Port{{
			Number:   443,
			Protocol: "tcp",
			State:    &hostpb.State{State: "open"},
			Service:  &netpb.Service{Name: "https", Product: "nginx"},
		}},
	}

	stored, err := db.Hosts.Add(host)
	if err != nil {
		t.Fatalf("Hosts.Add: %v", err)
	}
	if len(stored) != 1 {
		t.Fatalf("Add returned %d hosts, want 1", len(stored))
	}
	if stored[0].GetId() == "" {
		t.Error("stored host has no id (server did not persist it)")
	}

	// The facade trusts server-side dedup: contributing the same host again enriches nothing and
	// adds no row. Create is additive + skip-if-identical, so the second Add returns nothing stored.
	again, err := db.Hosts.Add(&hostpb.Host{
		Addresses: []*netpb.Address{{Addr: "10.10.0.5"}},
		Ports: []*hostpb.Port{{
			Number:   443,
			Protocol: "tcp",
			State:    &hostpb.State{State: "open"},
			Service:  &netpb.Service{Name: "https", Product: "nginx"},
		}},
	})
	if err != nil {
		t.Fatalf("Hosts.Add (repeat): %v", err)
	}
	if len(again) != 0 {
		t.Errorf("re-adding an identical host stored %d hosts, want 0 (dedup)", len(again))
	}

	// Exactly one host in the database.
	all, err := db.Hosts.List(nil)
	if err != nil {
		t.Fatalf("Hosts.List: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("List returned %d hosts, want 1 (no duplicate from the repeat Add)", len(all))
	}

	// The provenance stamp landed: a read scoped to this tool returns the host; a read scoped to a
	// tool that contributed nothing returns none. This is the whole point of As(...).
	mine, err := con.Hosts.Read(context.Background(), &hostrpc.ReadHostRequest{
		Host:    &hostpb.Host{},
		Filters: &hostrpc.HostFilters{Source: "recon-x"},
	})
	if err != nil {
		t.Fatalf("Read source=recon-x: %v", err)
	}
	if n := len(mine.GetHosts()); n != 1 {
		t.Errorf("source=recon-x matched %d hosts, want 1 (provenance stamp)", n)
	}

	other, err := con.Hosts.Read(context.Background(), &hostrpc.ReadHostRequest{
		Host:    &hostpb.Host{},
		Filters: &hostrpc.HostFilters{Source: "some-other-tool"},
	})
	if err != nil {
		t.Fatalf("Read source=some-other-tool: %v", err)
	}
	if n := len(other.GetHosts()); n != 0 {
		t.Errorf("source=some-other-tool matched %d hosts, want 0", n)
	}
}

// TestContribCredsAddThroughFacade mirrors the host proof for the credential domain: a one-line
// Creds.Add reaches the DB, and As(...) stamps a provenance Source the credential read filters on.
func TestContribCredsAddThroughFacade(t *testing.T) {
	con := newInMemoryStack(t)
	db := contrib.New(con).As("hydra")

	stored, err := db.Creds.Add(&credpb.Core{
		Public:  &credpb.Public{Type: credpb.PublicType_Username, Username: "root"},
		Private: &credpb.Private{Type: credpb.PrivateType_Password, Data: "hunter2"},
	})
	if err != nil {
		t.Fatalf("Creds.Add: %v", err)
	}
	if len(stored) != 1 || stored[0].GetId() == "" {
		t.Fatalf("Add returned %d creds (want 1, persisted)", len(stored))
	}

	mine, err := con.Creds.List(context.Background(), &credrpc.ReadCredentialRequest{
		Credential: &credpb.Core{},
		Source:     "hydra",
	})
	if err != nil {
		t.Fatalf("List source=hydra: %v", err)
	}
	if n := len(mine.GetCredentials()); n != 1 {
		t.Errorf("source=hydra matched %d creds, want 1 (provenance stamp)", n)
	}
}
