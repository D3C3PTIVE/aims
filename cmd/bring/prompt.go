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
	"strconv"

	"github.com/spf13/cobra"

	"github.com/d3c3ptive/aims/client"
	scans "github.com/d3c3ptive/aims/scan/pb/rpc"
)

// PromptCommand returns the hidden `aims prompt` command: the data source for the shell prompt
// integration installed by `aims init`. These are live, server-GLOBAL figures — the server version,
// the number of connected operators, and the running-scan count — that change independently of
// bring/leave, so the shell cannot bake them into $PROMPT and instead re-polls this command from a
// precmd hook. All three are fetched in one invocation so a poll costs a single teamserver connect.
//
// In --terse mode it prints exactly one line, three tab-separated fields — scans<TAB>version<TAB>
// connected — which the zsh hook parses and renders in the right prompt. Every field is numeric or a
// dotted version (never agent-derived), so it is inert under prompt expansion. An empty field means
// "unavailable this poll": the shell keeps its last known value rather than flap the prompt. Run by
// hand (no flag) it prints a short human-readable server summary instead.
//
// Unlike `init`, it needs a live connection — it does NOT opt out of the connect pre-run that
// bindRunners attaches, so the server is reached before RunE.
func PromptCommand(con *client.Client) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "prompt",
		Short:   "Emit server-global prompt data for the `aims init` shell integration",
		GroupID: groupID,
		Hidden:  true,
		RunE: func(command *cobra.Command, args []string) error {
			// Each field is fetched independently and best-effort: one failing call must not blank the
			// others, and a hard connection failure has already surfaced via the connect pre-run (the
			// command then exits non-zero and the shell keeps its cache).
			jobs, scanErr := con.Scans.Jobs(command.Context(), &scans.JobsRequest{})
			ver, verErr := con.VersionServer()
			users, usersErr := con.Users()

			connected := 0
			for _, u := range users {
				if u.Online {
					connected++
				}
			}

			if terse, _ := command.Flags().GetBool("terse"); terse {
				scansField, versionField, connectedField := "", "", ""
				if scanErr == nil {
					scansField = strconv.Itoa(len(jobs.GetJobs()))
				}
				if verErr == nil {
					versionField = fmt.Sprintf("%d.%d.%d", ver.Major, ver.Minor, ver.Patch)
				}
				if usersErr == nil {
					connectedField = strconv.Itoa(connected)
				}
				fmt.Fprintf(command.OutOrStdout(), "%s\t%s\t%s\n", scansField, versionField, connectedField)
				return nil
			}

			// Human-readable default (running `aims prompt` by hand): a short server summary.
			w := command.OutOrStdout()
			if verErr == nil {
				dirty := ""
				if ver.Dirty {
					dirty = " (dirty)"
				}
				fmt.Fprintf(w, "Server:    v%d.%d.%d%s  %s/%s\n", ver.Major, ver.Minor, ver.Patch, dirty, ver.OS, ver.Arch)
			} else {
				fmt.Fprintf(w, "Server:    (version unavailable: %v)\n", verErr)
			}
			if usersErr == nil {
				fmt.Fprintf(w, "Operators: %d connected\n", connected)
			} else {
				fmt.Fprintf(w, "Operators: (unavailable: %v)\n", usersErr)
			}
			if scanErr == nil {
				fmt.Fprintf(w, "Scans:     %d running\n", len(jobs.GetJobs()))
			} else {
				fmt.Fprintf(w, "Scans:     (unavailable: %v)\n", scanErr)
			}
			return nil
		},
	}
	cmd.Flags().Bool("terse", false, "Emit a single tab-separated line (scans<TAB>version<TAB>connected) for the shell prompt")
	return cmd
}
