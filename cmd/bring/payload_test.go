package bring

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

	"github.com/d3c3ptive/aims/cmd/bring/shell"
)

// TestWritePayloadSanitizesAndFormats checks the wire contract: one key<TAB>value line per field,
// with display values sanitized so nothing shell-active survives.
func TestWritePayloadSanitizesAndFormats(t *testing.T) {
	var b strings.Builder
	err := writePayload(&b, agentContext{
		id:      "1234-uuid",
		name:    "$(touch OWNED)", // hostile name
		tool:    "sliver",
		cwd:     "/root/work",
		route:   "3h·gw01",
		pending: "2",
	})
	if err != nil {
		t.Fatalf("writePayload: %v", err)
	}
	out := b.String()

	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 6 {
		t.Fatalf("payload has %d lines, want 6:\n%q", len(lines), out)
	}

	got := map[string]string{}
	for _, l := range lines {
		kv := strings.SplitN(l, "\t", 2)
		if len(kv) != 2 {
			t.Fatalf("line %q is not key<TAB>value", l)
		}
		got[kv[0]] = kv[1]
	}

	if got[shell.KeyID] != "1234-uuid" {
		t.Errorf("id = %q, want %q", got[shell.KeyID], "1234-uuid")
	}
	if got[shell.KeyName] != "(touch OWNED)" {
		t.Errorf("name = %q, want sanitized %q", got[shell.KeyName], "(touch OWNED)")
	}
	if got[shell.KeyTool] != "sliver" {
		t.Errorf("tool = %q, want %q", got[shell.KeyTool], "sliver")
	}
	if got[shell.KeyRoute] != "3h·gw01" {
		t.Errorf("route = %q, want %q", got[shell.KeyRoute], "3h·gw01")
	}
	if got[shell.KeyPending] != "2" {
		t.Errorf("pending = %q, want %q", got[shell.KeyPending], "2")
	}
	if strings.Contains(out, "$(") || strings.Contains(out, "`") {
		t.Errorf("payload still carries shell-substitution syntax:\n%s", out)
	}
}
