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
	"fmt"
	"io"

	"github.com/d3c3ptive/aims/cmd/bring/shell"
)

// agentContext is the flat, raw view of a c2 agent that a bring payload carries into the shell.
// Only the id is authoritative; the rest is a point-in-time display snapshot (see BRING.md). It is
// intentionally decoupled from the c2 protobuf type so the payload format is stable while the
// agents data model is still settling — only the mapping in generate.go touches the pb type.
type agentContext struct {
	id, name, tool, cwd string
	pending             string // count of not-yet-completed tasks, as a decimal string
	route               string // terse network-path summary (hop distance + last gateway); empty when no trace
}

// writePayload emits the agent context as inert key<TAB>value lines for the trusted bring() shell
// function to parse as data (never eval). Every value — including the id, to keep control bytes out
// of the line format — is run through shell.SanitizeDisplay first; because the shell parses rather
// than evaluates the payload, no shell quoting is applied here.
func writePayload(w io.Writer, c agentContext) error {
	for _, kv := range []struct{ k, v string }{
		{shell.KeyID, shell.SanitizeDisplay(c.id)},
		{shell.KeyName, shell.SanitizeDisplay(c.name)},
		{shell.KeyTool, shell.SanitizeDisplay(c.tool)},
		{shell.KeyCWD, shell.SanitizeDisplay(c.cwd)},
		{shell.KeyRoute, shell.SanitizeDisplay(c.route)},
		{shell.KeyPending, shell.SanitizeDisplay(c.pending)},
	} {
		if _, err := fmt.Fprintf(w, "%s\t%s\n", kv.k, kv.v); err != nil {
			return err
		}
	}
	return nil
}
