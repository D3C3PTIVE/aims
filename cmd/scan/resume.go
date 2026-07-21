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
	"github.com/d3c3ptive/aims/scan"
	pb "github.com/d3c3ptive/aims/scan/pb"
	scans "github.com/d3c3ptive/aims/scan/pb/rpc"
)

// resumeCommand wires `aims scan resume <id>`: continue an interrupted (or failed) run over only the
// targets it never completed (.claude/SCAN.md Phase 6). The scan runs server-side and streams back exactly
// like `scan run`; the resumed run links to the original (ResumedFrom) and tombstones it, so the
// resume chain shows in `scan history`. The id is resolved by prefix like `show`/`rm`/`diff`.
func resumeCommand(con *client.Client) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "resume <id>",
		Short: "Resume an interrupted scan over its uncompleted targets",
		Long: "Continue an interrupted or failed scan. AIMS re-invokes the scanner over only the\n" +
			"targets that run never completed (its per-target record), folds the results into a new\n" +
			"run linked to the original, and tombstones the original. A scan whose targets rode inside\n" +
			"its raw arguments (a plain `scan run nmap … 10.0.0.0/24`) has no per-target record, so it\n" +
			"is re-run whole — harmless, as the fold is idempotent.\n\n" +
			"    aims scan resume <id>\n\n" +
			"Streams like `scan run` and blocks to completion: a live dashboard by default; Ctrl-C\n" +
			"detaches (the resumed job keeps running server-side), a shell `&` backgrounds the client.",
		Args:               cobra.ExactArgs(1),
		DisableFlagParsing: false,
		RunE: func(command *cobra.Command, args []string) error {
			id, err := resolveRunID(con, command.Context(), args[0])
			if err != nil {
				return err
			}

			stream, err := con.Scans.Resume(command.Context(), &scans.ResumeScanRequest{Id: id})
			if err = aims.CheckError(err); err != nil {
				return err
			}
			return renderScan(stream, streamOpts{scanner: "resume " + display.FormatSmallID(id)})
		},
	}
	carapace.Gen(cmd).PositionalCompletion(completeResumable(con))
	return cmd
}

// resolveRunID turns an id prefix into a full stored-run id, reaching tombstoned runs too (a failed
// run coalesced under a failure head is still resumable). Mirrors the show/rm/diff prefix match.
func resolveRunID(con *client.Client, ctx context.Context, arg string) (string, error) {
	res, err := con.Scans.Read(ctx, &scans.ReadScanRequest{
		Scan:    &pb.Run{},
		Filters: &scans.RunFilters{IncludeSuperseded: true},
	})
	if err = aims.CheckError(err); err != nil {
		return "", err
	}
	run := findRunByPrefix(res.GetScans(), arg)
	if run == nil {
		return "", fmt.Errorf("no scan matching %q", arg)
	}
	if !scan.IsResumable(run) {
		return "", fmt.Errorf("scan %s is not resumable — only an interrupted or failed run can be resumed",
			display.FormatSmallID(run.GetId()))
	}
	return run.GetId(), nil
}

// completeResumable offers the interrupted scans as completion candidates — the runs with genuine
// partial progress to continue. A failed run can still be resumed by passing its id explicitly (it
// re-runs whole), but it carries no partial work, so it is deliberately kept out of the candidate
// list rather than cluttering it.
func completeResumable(con *client.Client) carapace.Action {
	return carapace.ActionCallback(func(c carapace.Context) carapace.Action {
		if msg, err := con.ConnectComplete(); err != nil {
			return msg
		}
		res, err := con.Scans.Read(context.Background(), &scans.ReadScanRequest{
			Scan:    &pb.Run{},
			Filters: &scans.RunFilters{IncludeSuperseded: true},
		})
		if err = aims.CheckError(err); err != nil {
			return carapace.ActionMessage("Error: %s", err)
		}

		var interrupted []string
		for _, r := range res.GetScans() {
			if !scan.IsInterrupted(r) {
				continue
			}
			desc := strings.TrimSpace(r.GetScanner() + " " + r.GetArgs())
			interrupted = append(interrupted, display.FormatSmallID(r.GetId()), desc)
		}
		if len(interrupted) == 0 {
			return carapace.ActionMessage("no interrupted scans to resume")
		}
		return carapace.ActionValuesDescribed(interrupted...).Tag("interrupted scans")
	})
}
