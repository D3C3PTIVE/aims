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

import (
	"context"
	"fmt"
	"strings"

	"github.com/carapace-sh/carapace"
	"github.com/spf13/cobra"

	"github.com/d3c3ptive/aims/client"
	aims "github.com/d3c3ptive/aims/cmd"
	"github.com/d3c3ptive/aims/cmd/display"
	scans "github.com/d3c3ptive/aims/scan/pb/rpc"
)

// jobsCommand lists the scans currently running server-side (`aims scan jobs`).
func jobsCommand(con *client.Client) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "jobs",
		Short: "List running scan jobs",
		RunE: func(command *cobra.Command, args []string) error {
			res, err := con.Scans.Jobs(command.Context(), &scans.JobsRequest{})
			if err = aims.CheckError(err); err != nil {
				return err
			}
			// --count: emit only the number of running jobs and nothing else. This is the terse,
			// machine-readable mode the shell prompt integration (`aims init`) polls — the zsh
			// precmd hook parses a bare integer, so keep it a single decimal with no decoration.
			if count, _ := command.Flags().GetBool("count"); count {
				fmt.Println(len(res.GetJobs()))
				return nil
			}
			if len(res.GetJobs()) == 0 {
				fmt.Println("No running scan jobs.")
				return nil
			}
			for _, j := range res.GetJobs() {
				fmt.Printf("%s  %-8s  %s  (targets: %d)\n",
					display.FormatSmallID(j.GetId()), j.GetScanner(),
					strings.Join(j.GetArgs(), " "), len(j.GetTargets()))
			}
			return nil
		},
	}
	cmd.Flags().Bool("count", false, "Print only the number of running jobs (for the `aims init` prompt integration)")
	return cmd
}

// attachCommand re-follows a running scan job's stream (`aims scan attach <job-id>`).
func attachCommand(con *client.Client) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "attach <job-id>",
		Short: "Re-attach to a running scan job's live stream",
		Args:  cobra.ExactArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			id, err := resolveJobID(con, command.Context(), args[0])
			if err != nil {
				return err
			}
			stream, err := con.Scans.Attach(command.Context(), &scans.AttachRequest{JobId: id})
			if err = aims.CheckError(err); err != nil {
				return err
			}
			return renderScan(stream, streamOpts{scanner: "attach " + display.FormatSmallID(id)})
		},
	}
	carapace.Gen(cmd).PositionalCompletion(completeJobs(con))
	return cmd
}

// stopCommand cancels a running scan job (`aims scan stop <job-id>`); partial results are still
// stored server-side.
func stopCommand(con *client.Client) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "stop <job-id>",
		Short: "Stop a running scan job (partial results are still stored)",
		Args:  cobra.ExactArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			id, err := resolveJobID(con, command.Context(), args[0])
			if err != nil {
				return err
			}
			res, err := con.Scans.Stop(command.Context(), &scans.StopRequest{JobId: id})
			if err = aims.CheckError(err); err != nil {
				return err
			}
			if res.GetStopped() {
				fmt.Printf("Stopped scan job %s.\n", display.FormatSmallID(id))
			} else {
				fmt.Println("Job not found or already finished.")
			}
			return nil
		},
	}
	carapace.Gen(cmd).PositionalCompletion(completeJobs(con))
	return cmd
}

// resolveJobID turns an id prefix (as shown by `scan jobs`) into the full job id the server keys
// on. Only running jobs are resolvable this way; a full id passed verbatim also matches.
func resolveJobID(con *client.Client, ctx context.Context, arg string) (string, error) {
	res, err := con.Scans.Jobs(ctx, &scans.JobsRequest{})
	if err = aims.CheckError(err); err != nil {
		return "", err
	}
	id := aims.StripANSI(arg)
	for _, j := range res.GetJobs() {
		if strings.HasPrefix(j.GetId(), id) {
			return j.GetId(), nil
		}
	}
	return "", fmt.Errorf("no running scan job matching %q", arg)
}

// completeJobs feeds running job ids (with a scanner+args description) to attach/stop completion.
func completeJobs(con *client.Client) carapace.Action {
	return carapace.ActionCallback(func(c carapace.Context) carapace.Action {
		if msg, err := con.ConnectComplete(); err != nil {
			return msg
		}
		res, err := con.Scans.Jobs(context.Background(), &scans.JobsRequest{})
		if err = aims.CheckError(err); err != nil {
			return carapace.ActionMessage("Error: %s", err)
		}
		if len(res.GetJobs()) == 0 {
			return carapace.ActionMessage("no running scan jobs")
		}
		var pairs []string
		for _, j := range res.GetJobs() {
			desc := strings.TrimSpace(j.GetScanner() + " " + strings.Join(j.GetArgs(), " "))
			// Offer the abbreviated id (as hosts/services/scans do); resolveJobID prefix-matches it
			// back to the full job id, so the short form works as the argument.
			pairs = append(pairs, display.FormatSmallID(j.GetId()), desc)
		}
		return carapace.ActionValuesDescribed(pairs...).Tag("scan jobs")
	})
}
