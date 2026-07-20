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
	"errors"
	"fmt"
	"io"

	"github.com/carapace-sh/carapace"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/d3c3ptive/aims/client"
	aims "github.com/d3c3ptive/aims/cmd"
	"github.com/d3c3ptive/aims/cmd/display"
	hostpb "github.com/d3c3ptive/aims/host/pb"
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
	runCmd.AddCommand(runMasscanCommand(con))

	return runCmd
}

// runNmapCommand wires `aims scan run nmap <nmap args...>`. The scan runs SERVER-SIDE (on the
// teamserver, via the streaming Run RPC), so it outlives the operator's terminal and is visible
// to every operator; the client just streams progress/hosts and prints the stored result.
// DisableFlagParsing hands every token after `nmap` to the scanner verbatim (no `--` needed):
// `aims scan run nmap -sT -p1-1000 scanme.nmap.org`. The one aims-owned token is `--background`
// (a.k.a. `--detach`): it submits the job and returns immediately with the job id.
func runNmapCommand(con *client.Client) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "nmap [nmap args...]",
		Short: "Run an nmap scan server-side and stream the results",
		Long: "Run an nmap scan by passing arguments straight through to nmap. The scan runs on the\n" +
			"teamserver and streams back; everything after `nmap` is forwarded verbatim (no `--`):\n\n" +
			"    aims scan run nmap -sT -sV -p1-1000 scanme.nmap.org\n\n" +
			"Foreground by default (Ctrl-C detaches; the scan keeps running). Add --background to\n" +
			"submit and return immediately. XML output is added automatically; results are stored.",
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

// runMasscanCommand wires `aims scan run masscan <masscan args...>`, the second server-side scanner.
// It is the same raw-passthrough shape as nmap (DisableFlagParsing, one aims-owned --background),
// driven by the masscan driver which appends XML output automatically and folds the result through
// the shared nmap XML parser. Completion (completeRunMasscan) reuses every value completer — targets,
// ports, interface — behind a masscan-specific dispatch.
func runMasscanCommand(con *client.Client) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "masscan [masscan args...]",
		Short: "Run a masscan scan server-side and stream the results",
		Long: "Run a masscan scan by passing arguments straight through to masscan. The scan runs on\n" +
			"the teamserver and streams back; everything after `masscan` is forwarded verbatim:\n\n" +
			"    aims scan run masscan -p1-65535 --rate 10000 10.0.0.0/24\n\n" +
			"Foreground by default (Ctrl-C detaches; the scan keeps running). Add --background to\n" +
			"submit and return immediately. XML output is added automatically; results are stored.",
		DisableFlagParsing: true,
		RunE: func(command *cobra.Command, args []string) error {
			return runScanner(command, con, "masscan", args)
		},
	}

	carapace.Gen(cmd).PositionalAnyCompletion(completeRunMasscan(con))

	return cmd
}

func runNmap(command *cobra.Command, con *client.Client, args []string) error {
	return runScanner(command, con, "nmap", args)
}

// runScanner is the shared client side of every `scan run <scanner>` leaf: it intercepts the bare
// help case, strips the aims-owned --background/--detach token (DisableFlagParsing leaves no cobra
// flag to bind), forwards the rest verbatim to the server-side driver over the streaming Run RPC, and
// renders the stream. scanner is the driver name the server resolves (see scannerFor).
func runScanner(command *cobra.Command, con *client.Client, scanner string, args []string) error {
	// DisableFlagParsing means -h/--help would otherwise be forwarded to the scanner; intercept the
	// bare help/no-arg case and show this command's help instead (the least-surprising behaviour).
	if len(args) == 0 || (len(args) == 1 && (args[0] == "-h" || args[0] == "--help")) {
		return command.Help()
	}

	// --background/--detach is aims-owned. With DisableFlagParsing on there is no cobra flag to
	// bind, so strip it by hand (long form only — a scanner's -d may mean something else) and
	// forward everything else verbatim.
	background := false
	scanArgs := make([]string, 0, len(args))
	for _, a := range args {
		switch a {
		case "--background", "--detach":
			background = true
		default:
			scanArgs = append(scanArgs, a)
		}
	}

	stream, err := con.Scans.Run(command.Context(), &scans.RunScanRequest{
		Scanner:    scanner,
		Args:       scanArgs,
		Background: background,
	})
	if err = aims.CheckError(err); err != nil {
		return err
	}

	return streamScan(stream, background)
}

// updateReceiver is the common receive side of the Run and Attach client streams, so one
// renderer serves both `scan run` and `scan attach`.
type updateReceiver interface {
	Recv() (*scans.RunUpdate, error)
}

// streamScan renders a running scan's RunUpdate frames. Foreground: progress + hosts as they are
// found, then the stored result. Background: print the job id and return (the server keeps
// running). Ctrl-C cancels the client context, which the server treats as a detach — the scan
// keeps running and can be re-followed with `scan attach`.
func streamScan(stream updateReceiver, background bool) error {
	for {
		update, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			if status.Code(err) == codes.Canceled || errors.Is(err, context.Canceled) {
				fmt.Println("\nDetached; the scan keeps running (see `scan jobs`).")
				return nil
			}
			return aims.CheckError(err)
		}

		switch u := update.GetUpdate().(type) {
		case *scans.RunUpdate_JobId:
			if background {
				fmt.Printf("Scan job %s started (running in background).\n", display.FormatSmallID(u.JobId))
				return nil
			}
			fmt.Printf("Scan job %s — Ctrl-C detaches (the scan keeps running).\n", display.FormatSmallID(u.JobId))
		case *scans.RunUpdate_Progress:
			p := u.Progress
			fmt.Printf("\r  %-28s %5.1f%%   ", p.GetTask(), p.GetPercent())
		case *scans.RunUpdate_Host:
			fmt.Printf("\r[+] %-60s\n", hostLine(u.Host))
		case *scans.RunUpdate_Final:
			saved := u.Final
			fmt.Printf("\nScan complete: %s — %d host(s) stored.\n",
				display.FormatSmallID(saved.GetId()), len(saved.GetHosts()))
			return nil
		case *scans.RunUpdate_Error:
			return fmt.Errorf("scan error: %s", u.Error)
		}
	}
}

func hostLine(h *hostpb.Host) string {
	label := "?"
	if len(h.GetAddresses()) > 0 && h.GetAddresses()[0].GetAddr() != "" {
		label = h.GetAddresses()[0].GetAddr()
	} else if len(h.GetHostnames()) > 0 {
		label = h.GetHostnames()[0].GetName()
	}
	open := 0
	for _, p := range h.GetPorts() {
		if p.GetState().GetState() == "open" {
			open++
		}
	}
	return fmt.Sprintf("%s (%d open port(s))", label, open)
}
