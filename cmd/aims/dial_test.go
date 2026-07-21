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
	"strings"
	"testing"

	"github.com/d3c3ptive/aims/client"
	"github.com/d3c3ptive/aims/client/contrib"
	"github.com/d3c3ptive/aims/server/transport"
)

// TestClientConnectLibrary proves the plain library Connect() (no cobra, no completion) stands up
// the transport and registers the service clients over the in-memory teamserver — the connect the
// contribution facade's Dial reduces to. A List round-trip after Connect confirms the RPC stack is
// live, not merely dialed.
func TestClientConnectLibrary(t *testing.T) {
	t.Setenv("AIMS_ROOT_DIR", t.TempDir())

	teamserver, handler, err := transport.NewTeamserver()
	if err != nil {
		t.Fatalf("NewTeamserver: %v", err)
	}
	con, err := client.New(transport.InMemoryClientOptions(handler)...)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	if err := teamserver.Serve(con.Teamclient); err != nil {
		t.Fatalf("Serve: %v", err)
	}

	// The library path: no ConnectRun(cmd), no ConnectComplete() — just Connect().
	if err := con.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { _ = con.Disconnect() })

	if _, err := contrib.New(con).Hosts.List(nil); err != nil {
		t.Fatalf("List after Connect (RPC stack not registered?): %v", err)
	}
}

// TestDialNoSystemConfig locks the zero-configuration contract's failure edge: with no system
// teamclient config on disk, Dial does not hang or silently no-op — it returns a clear error naming
// the missing config, so a contributing tool fails loudly with a fixable message.
func TestDialNoSystemConfig(t *testing.T) {
	t.Setenv("AIMS_ROOT_DIR", t.TempDir()) // empty app dir → no system config to discover

	sess, err := contrib.Dial()
	if err == nil {
		if sess != nil {
			_ = sess.Close()
		}
		t.Fatal("Dial with no system config returned nil error, want a 'no config' error")
	}
	if !strings.Contains(err.Error(), "no system teamclient config") {
		t.Errorf("Dial error = %q, want it to name the missing system config", err.Error())
	}
}
