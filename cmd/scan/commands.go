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
	"github.com/spf13/pflag"

	"github.com/d3c3ptive/aims/client"
	aims "github.com/d3c3ptive/aims/cmd"
	"github.com/d3c3ptive/aims/cmd/display"
	"github.com/d3c3ptive/aims/cmd/export"
	"github.com/d3c3ptive/aims/scan"
	"github.com/d3c3ptive/aims/scan/ingest"
	"github.com/d3c3ptive/aims/scan/nmap"
	pb "github.com/d3c3ptive/aims/scan/pb"
	scans "github.com/d3c3ptive/aims/scan/pb/rpc"
)

// Commands returns all scan commands.
func Commands(con *client.Client) *cobra.Command {
	scanCmd := &cobra.Command{
		Use:     "scan",
		Short:   "Manage running and database scans",
		GroupID: "database",
	}

	scanCmd.AddCommand(listCommand(con))
	scanCmd.AddCommand(showCommand(con))
	scanCmd.AddCommand(rmCommand(con))
	scanCmd.AddCommand(runCommand(con))

	// Import
	importCmd := export.ImportCommand(scanCmd, con, importCommand(con))
	scanCmd.AddCommand(importCmd)

	aims.BindFlags(importCmd.Name(), false, importCmd, func(f *pflag.FlagSet) {
		f.BoolP("nmap", "N", false, "Hint (or force) parsing the file(s) as nmap scans (default nmap format used is xml)")
		f.String("scanner", "", "Parse the file(s) with a named ingestor (e.g. zgrab2); overrides format sniffing")
	})

	carapace.Gen(importCmd).FlagCompletion(carapace.ActionMap{
		"scanner": carapace.ActionValues(ingest.Names()...).Usage("scanner ingestor"),
	})

	carapace.Gen(importCmd).PositionalAnyCompletion(carapace.ActionFiles().Usage("scan files to import"))

	// Export
	exportCmd := export.ExportCommand(scanCmd, con, exportCommand(con))
	scanCmd.AddCommand(exportCmd)

	return scanCmd
}

// CompleteByID returns hosts completions with their smallened IDs as keys.
func CompleteByID(client *client.Client) carapace.Action {
	return carapace.ActionCallback(func(c carapace.Context) carapace.Action {
		if msg, err := client.ConnectComplete(); err != nil {
			return msg
		}

		// Request
		res, err := client.Scans.Read(context.Background(), &scans.ReadScanRequest{
			Scan:    &pb.Run{},
			Filters: &scans.RunFilters{},
		})
		if err = aims.CheckError(err); err != nil {
			return carapace.ActionMessage("Error: %s", err)
		}

		options := scan.Completions()
		options = append(options, display.WithCandidateValue("ID", ""))

		results := display.Completions(res.Scans, scan.DisplayFields, options...)

		return carapace.ActionValuesDescribed(results...).Tag("scans").Filter(c.Args...)
	})
}

func listCommand(con *client.Client) *cobra.Command {
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "Display hosts (with filters or styles)",
		RunE: func(command *cobra.Command, args []string) error {
			res, err := con.Scans.Read(command.Context(), &scans.ReadScanRequest{
				Scan: &pb.Run{},
				Filters: &scans.RunFilters{
					Hosts: true,
				},
			})
			err = aims.CheckError(err)
			if err != nil {
				return err
			}

			if len(res.GetScans()) == 0 {
				fmt.Printf("No scans in database.\n")
				return nil
			}

			// Order running scans first (most actionable), then by recency, before rendering.
			scans := res.GetScans()
			scan.SortRuns(scans)

			table := display.Table(scans, scan.DisplayFields, scan.DisplayHeaders()...)
			fmt.Println(table.Render())

			return nil
		},
	}

	return listCmd
}

func rmCommand(con *client.Client) *cobra.Command {
	rmCmd := &cobra.Command{
		Use:   "rm",
		Short: "Remove one or more scans from the database (by ID prefix)",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			force, _ := command.Flags().GetBool("force")

			// Read every scan through the teamclient (never the DB directly), then resolve each
			// ID-prefix argument against them — the same prefix match `show` uses. Only the Id is
			// needed to delete, so hosts are left unpreloaded (a light Delete payload); the
			// unconditional Begin/Progress/Stats preloads are enough for the running-scan guard.
			res, err := con.Scans.Read(command.Context(), &scans.ReadScanRequest{
				Scan:    &pb.Run{},
				Filters: &scans.RunFilters{},
			})
			if err = aims.CheckError(err); err != nil {
				return err
			}

			// A mid-flight run must not be dropped out from under a live scan: deleting its row
			// would not stop the scanner (there is no cancellation path yet) and a later progress
			// write could recreate it. Skip running scans with a warning unless --force. Today no
			// running run is ever persisted, so this only bites once streaming lands (SCAN.md C).
			var matched []*pb.Run
			var skipped int
			for _, r := range res.GetScans() {
				for _, arg := range args {
					if !strings.HasPrefix(r.GetId(), aims.StripANSI(arg)) {
						continue
					}
					if scan.IsRunning(r) && !force {
						fmt.Printf("Skipping running scan %s (use --force to remove it anyway)\n",
							display.FormatSmallID(r.GetId()))
						skipped++
					} else {
						matched = append(matched, r)
					}
					break
				}
			}
			if len(matched) == 0 {
				if skipped > 0 {
					return fmt.Errorf("no scan removed (%d running scan(s) skipped; use --force)", skipped)
				}
				return fmt.Errorf("no matching scan")
			}

			del, err := con.Scans.Delete(command.Context(), &scans.DeleteScanRequest{
				Scans: matched,
			})
			if err = aims.CheckError(err); err != nil {
				return err
			}

			fmt.Printf("Removed %d scan(s).\n", len(del.GetScans()))
			return nil
		},
	}

	aims.BindFlags(rmCmd.Name(), false, rmCmd, func(f *pflag.FlagSet) {
		f.BoolP("force", "f", false, "Remove even running scans (does not stop the scanner)")
	})

	carapace.Gen(rmCmd).PositionalAnyCompletion(CompleteByID(con))

	return rmCmd
}

func showCommand(con *client.Client) *cobra.Command {
	showCmd := &cobra.Command{
		Use:   "show",
		Short: "Show one ore more scan details",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			tasks, _ := command.Flags().GetBool("tasks")
			targets, _ := command.Flags().GetBool("targets")
			showHosts, _ := command.Flags().GetBool("hosts")

			// Request (hosts + ports preloaded so the shared-host insight and --hosts section
			// have data to work with).
			res, err := con.Scans.Read(command.Context(), &scans.ReadScanRequest{
				Scan: &pb.Run{},
				Filters: &scans.RunFilters{
					Hosts: true,
					Ports: true,
				},
			})
			if err = aims.CheckError(err); err != nil {
				return err
			}

			all := res.GetScans()
			opt := scan.DetailOpts{Tasks: tasks, Targets: targets, Hosts: showHosts}

			// Display each matching run through the shared Detail renderer.
			shown := 0
			for _, r := range all {
				matched := false
				for _, arg := range args {
					if strings.HasPrefix(r.Id, aims.StripANSI(arg)) {
						matched = true
						break
					}
				}
				if !matched {
					continue
				}
				if shown > 0 {
					fmt.Println()
				}
				fmt.Println(scan.Detail(r, all, opt).Render(0))
				shown++
			}
			if shown == 0 {
				return fmt.Errorf("no matching scan")
			}

			return nil
		},
	}

	aims.BindFlags(showCmd.Name(), false, showCmd, func(f *pflag.FlagSet) {
		f.BoolP("tasks", "t", false, "Show scan task status/progress (the live view)")
		f.BoolP("targets", "T", false, "Show scan targets' details")
		f.BoolP("hosts", "H", false, "Show scanned hosts as a table")
	})

	carapace.Gen(showCmd).PositionalAnyCompletion(CompleteByID(con))

	return showCmd
}

func importCommand(con *client.Client) func(cmd *cobra.Command, arg string, data []byte) error {
	importRunE := func(command *cobra.Command, arg string, data []byte) (err error) {
		scanList, err := importScan(command, arg, data)
		if err != nil {
			return err
		}

		if len(scanList) > 0 {
			for _, scan := range scanList {
				res, err := con.Scans.Create(command.Context(), &scans.CreateScanRequest{
					Scans: []*pb.Run{scan},
				})

				err = aims.CheckError(err)
				if err != nil {
					fmt.Printf("Import error: %s", err.Error())
					continue
				}

				if len(res.Scans) == 0 {
					fmt.Printf("Skipped %s scan, already existing\n", scan.Scanner)
					continue
				}

				saved := res.Scans[0]

				fmt.Printf("Saved %s scan (%s) in database\n", saved.Scanner, display.FormatSmallID(saved.Id))
				if len(saved.Hosts) < len(scan.Hosts) {
					fmt.Printf("Skipped %d already existing hosts", len(scan.Hosts)-len(saved.Hosts))
				}
			}
		}

		return nil
	}

	return importRunE
}

func importScan(command *cobra.Command, arg string, data []byte) ([]*pb.Run, error) {
	scanList := make([]*pb.Run, 0)

	// If a named ingestor was requested, fold the file through the scanner substrate
	// (SCAN.md Part C): any registered tool's native output — nmap XML, zgrab2 JSON, ... —
	// becomes a scan.Run that Scans.Create dedups/merges into the same objects. This takes
	// precedence over format sniffing and the --nmap hint.
	if scanner, _ := command.Flags().GetString("scanner"); scanner != "" {
		run, err := ingest.Ingest(scanner, data)
		if err != nil {
			return scanList, err
		}
		if run != nil {
			scanList = append(scanList, run)
			fmt.Printf("Importing 1 %s scan from %s\n", scanner, arg)
		}
		return scanList, nil
	}

	// If forced to parse an NMAP XML file.
	if asNmap, _ := command.Flags().GetBool("nmap"); asNmap {
		nmapScans, err := importNmap(data, arg)
		if err != nil {
			return scanList, fmt.Errorf("Nmap: %w", err)
		}
		scanList = append(scanList, nmapScans...)

	} else {
		jsonScans, err := export.ImportJSON[*pb.Run](data, arg)
		if err != nil {
			return scanList, fmt.Errorf("JSON: %w", err)
		}
		scanList = append(scanList, jsonScans...)
	}

	// and monitor the input. Notify the user on the command that we are
	// monitoring the scan file.
	return scanList, nil
}

func importNmap(data []byte, arg string) (scanList []*pb.Run, err error) {
	genericScan, err := nmap.FromXML(data)
	if err != nil || genericScan == nil {
		return nil, fmt.Errorf("Error parsing Nmap scan XML file: %w", err)
	}

	scanList = append(scanList, genericScan.ToPB())
	fmt.Printf("Importing 1 NMAP scan from %s\n", arg)

	return scanList, nil
}

func exportCommand(con *client.Client) func(cmd *cobra.Command, args []string) any {
	// If we have some data, export it according
	// to command flag specifications (format, file, etc)
	exportRunE := func(command *cobra.Command, args []string) (data any) {
		if len(args) == 0 {
			res, err := con.Scans.Read(command.Context(), &scans.ReadScanRequest{
				Scan: &pb.Run{},
				Filters: &scans.RunFilters{
					Hosts: true,
				},
			})
			err = aims.CheckError(err)
			if err != nil {
				return err
			}

			return res.GetScans()
		} else {
			res, err := con.Scans.Read(command.Context(), &scans.ReadScanRequest{
				Scan: &pb.Run{},
				Filters: &scans.RunFilters{
					Hosts: true,
					Ports: true,
				},
			})
			err = aims.CheckError(err)
			if err != nil {
				return err
			}

			scanList := []*pb.Run{}

			// Display
			for _, arg := range args {
				for _, h := range res.GetScans() {
					if strings.HasPrefix(h.Id, aims.StripANSI(arg)) {
						scanList = append(scanList, h)
					}
				}
			}
			return scanList
		}
	}

	return exportRunE
}

