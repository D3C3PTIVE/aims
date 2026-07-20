package agentctx

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

import "testing"

// TestCurrentNone: with no AIMS_AGENT_ID exported, no context is loaded.
func TestCurrentNone(t *testing.T) {
	t.Setenv(EnvID, "")
	if _, ok := Current(); ok {
		t.Fatal("expected no context when AIMS_AGENT_ID is empty")
	}
}

// TestCurrentLoaded: a populated environment parses into the snapshot, depth included.
func TestCurrentLoaded(t *testing.T) {
	t.Setenv(EnvID, "a1b2c3")
	t.Setenv(EnvName, "WORKSTATION-7")
	t.Setenv(EnvTool, "sliver")
	t.Setenv(EnvCwd, "/tmp")
	t.Setenv(EnvRoute, "2 hops · gw")
	t.Setenv(EnvPending, "3")
	t.Setenv(EnvDepth, "2")

	ctx, ok := Current()
	if !ok {
		t.Fatal("expected a loaded context")
	}
	if ctx.ID != "a1b2c3" || ctx.Name != "WORKSTATION-7" || ctx.Tool != "sliver" {
		t.Errorf("identity mismatch: %+v", ctx)
	}
	if ctx.Cwd != "/tmp" || ctx.Route != "2 hops · gw" || ctx.Pending != "3" {
		t.Errorf("snapshot mismatch: %+v", ctx)
	}
	if ctx.Depth != 2 {
		t.Errorf("depth = %d, want 2", ctx.Depth)
	}
}

// TestCurrentBadDepth: a non-numeric depth degrades to 0, not an error.
func TestCurrentBadDepth(t *testing.T) {
	t.Setenv(EnvID, "x")
	t.Setenv(EnvDepth, "not-a-number")
	ctx, ok := Current()
	if !ok || ctx.Depth != 0 {
		t.Errorf("want loaded context with depth 0, got ok=%v depth=%d", ok, ctx.Depth)
	}
}
