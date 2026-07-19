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
	"fmt"
	"os"
	"strings"

	"github.com/carapace-sh/carapace"
	"github.com/spf13/cobra"

	nmapscan "github.com/d3c3ptive/nmap"

	"github.com/d3c3ptive/aims/client"
	aims "github.com/d3c3ptive/aims/cmd"
	"github.com/d3c3ptive/aims/cmd/display"
	pb "github.com/d3c3ptive/aims/scan/pb"
	scans "github.com/d3c3ptive/aims/scan/pb/rpc"
)

// runCommand builds the `scan run` subtree: drive native scanners from AIMS and fold
// their results straight into the database. Each scanner is a leaf subcommand.
func runCommand(con *client.Client) *cobra.Command {
	runCmd := &cobra.Command{
		Use:   "run",
		Short: "Run a scanner and store its results in the database",
	}

	runCmd.AddCommand(runNmapCommand(con))

	return runCmd
}

// runNmapCommand wires `aims scan run nmap <nmap args...>` as a raw passthrough to the
// system nmap binary via the AIMS-native nmap fork. DisableFlagParsing hands every token
// after `nmap` to the scanner verbatim (no `--` needed): `aims scan run nmap -sT -p1-1000
// scanme.nmap.org`. The fork forces `-oX -`, parses nmap's XML directly into a *scan.Run,
// and Scans.Create folds it into the DB (dedup/merge). Typed flags + completions are the
// documented follow-on (SCAN.md §D); this is the passthrough-first cut.
func runNmapCommand(con *client.Client) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "nmap [nmap args...]",
		Short: "Run an nmap scan (raw passthrough) and store the results",
		Long: "Run an nmap scan by passing arguments straight through to the nmap binary.\n" +
			"Everything after `nmap` is forwarded verbatim, so no `--` separator is needed:\n\n" +
			"    aims scan run nmap -sT -sV -p1-1000 scanme.nmap.org\n\n" +
			"XML output (-oX -) is added automatically; results are parsed and stored.",
		DisableFlagParsing: true,
		RunE: func(command *cobra.Command, args []string) error {
			return runNmap(command, con, args)
		},
	}

	// DisableFlagParsing turns off cobra's own completion, so all completion is dispatched
	// through one positional-tail callback (targets from the DB, NSE names after --script).
	carapace.Gen(cmd).PositionalAnyCompletion(completeRunNmap(con))

	return cmd
}

func runNmap(command *cobra.Command, con *client.Client, args []string) error {
	// DisableFlagParsing means -h/--help would otherwise be forwarded to nmap; intercept the
	// bare help/no-arg case and show this command's help instead (the least-surprising behaviour).
	if len(args) == 0 || (len(args) == 1 && (args[0] == "-h" || args[0] == "--help")) {
		return command.Help()
	}

	scanner, err := nmapscan.NewScanner(
		nmapscan.WithContext(command.Context()),
		nmapscan.WithCustomArguments(args...),
	)
	if err != nil {
		return err
	}

	fmt.Printf("Running: nmap %s\n", strings.Join(args, " "))

	// Run blocks until nmap exits; the fork parses its XML into a *scan.Run.
	run, warnings, err := scanner.Run()
	for _, w := range warnings {
		fmt.Fprintf(os.Stderr, "nmap warning: %s\n", w)
	}
	if err != nil {
		return fmt.Errorf("nmap run: %w", err)
	}

	// The fork's Run is `type Run scan.Run` over the same scan/pb package, so this is a
	// direct type conversion, not a copy of a foreign type.
	pbRun := (*pb.Run)(run)

	res, err := con.Scans.Create(command.Context(), &scans.CreateScanRequest{
		Scans: []*pb.Run{pbRun},
	})
	if err = aims.CheckError(err); err != nil {
		return fmt.Errorf("store scan: %w", err)
	}

	if len(res.Scans) == 0 {
		fmt.Println("Scan complete; already present in database (skipped)")
		return nil
	}

	saved := res.Scans[0]
	fmt.Printf("Saved %s scan (%s) — %d host(s)\n",
		saved.Scanner, display.FormatSmallID(saved.Id), len(saved.Hosts))

	return nil
}
