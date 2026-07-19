package shell

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
	"embed"
	"fmt"
	"io"
	"text/template"
)

//go:embed templates/*.tmpl
var templatesFS embed.FS

// Init writes the shell integration — the bring()/leave() functions and their helpers — for the
// given shell to w. This is the trusted half of the `bring` feature: the emitted code contains no
// agent data (agent values arrive only later, as inert payload data parsed by bring()). Source it
// once from your shell rc, e.g. `source <(aims init zsh)`.
//
// Only zsh is wired today (P1); bash and fish return a clear not-implemented error so the command
// fails loudly rather than emitting a broken snippet.
func Init(w io.Writer, sh Shell) error {
	var tmpl string
	switch sh {
	case Zsh:
		tmpl = "zsh.tmpl"
	case Bash, Fish:
		return fmt.Errorf("`bring` shell integration for %s is not implemented yet (P1 ships zsh; bash and fish follow)", sh)
	default:
		return fmt.Errorf("unsupported shell %q", sh)
	}

	t, err := template.ParseFS(templatesFS, "templates/"+tmpl)
	if err != nil {
		return err
	}
	return t.Execute(w, initData{ID: KeyID, Name: KeyName, Tool: KeyTool, CWD: KeyCWD, Pending: KeyPending})
}
