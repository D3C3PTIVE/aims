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
	"regexp"
	"strings"

	"github.com/rsteube/carapace"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/d3c3ptive/aims/client"
	aims "github.com/d3c3ptive/aims/cmd"
	"github.com/d3c3ptive/aims/cmd/display"
	"github.com/d3c3ptive/aims/cmd/export"
	"github.com/d3c3ptive/aims/proto/rpc/scans"
	pb "github.com/d3c3ptive/aims/proto/scan"
	"github.com/d3c3ptive/aims/scan"
	"github.com/d3c3ptive/aims/scan/nmap"
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

	// Import
	importCmd := export.ImportCommand(scanCmd, con, importCommand(con))
	scanCmd.AddCommand(importCmd)

	aims.BindFlags(importCmd.Name(), false, importCmd, func(f *pflag.FlagSet) {
		f.BoolP("nmap", "N", false, "Hint (or force) parsing the file(s) as nmap scans (default nmap format used is xml)")
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

		return carapace.ActionValuesDescribed(results...).Tag("scans").FilterArgs()
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

			// Generate the table of hosts.
			table := display.Table(res.GetScans(), scan.DisplayFields, scan.DisplayHeaders()...)
			fmt.Println(table.Render())

			return nil
		},
	}

	return listCmd
}

func showCommand(con *client.Client) *cobra.Command {
	showCmd := &cobra.Command{
		Use:   "show",
		Short: "Show one ore more scan details",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			targets, _ := command.Flags().GetBool("targets")
			tasks, _ := command.Flags().GetBool("tasks")

			options := scan.DisplayDetails()

			if tasks {
				options = append(options, display.WithHeader("Tasks Details", 3))
			}
			if targets {
				options = append(options, display.WithHeader("Targets Details", 4))
			}

			// Request
			res, err := con.Scans.Read(command.Context(), &scans.ReadScanRequest{
				Scan: &pb.Run{},
				Filters: &scans.RunFilters{
					Hosts: true,
					Ports: true,
				},
			})
			err = aims.CheckError(err)

			// Display
			found := false
			for _, h := range res.GetScans() {
				for _, arg := range args {
					if len(res.GetScans()) > 1 && found {
						fmt.Println()
					}
					if strings.HasPrefix(h.Id, strip(arg)) {
						fmt.Println(display.Details(h, scan.DisplayFields, options...))
					}
					found = true
				}
			}

			return nil
		},
	}

	aims.BindFlags(showCmd.Name(), false, showCmd, func(f *pflag.FlagSet) {
		f.BoolP("targets", "T", false, "Show scan targets' details")
	})
	aims.BindFlags(showCmd.Name(), false, showCmd, func(f *pflag.FlagSet) {
		f.BoolP("tasks", "t", false, "Show all scan tasks status/details")
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
	// If forced to parse an NMAP XML file.
	if asNmap, _ := command.Flags().GetBool("nmap"); asNmap {
		nmapScans, err := importNmap(data, arg)
		if err != nil {
			return scanList, fmt.Errorf("Nmap: %s", err.Error())
		}
		scanList = append(scanList, nmapScans...)

	} else {
		jsonScans, err := export.ImportJSON[*pb.Run](data, arg)
		if err != nil {
			return scanList, fmt.Errorf("JSON: %s", err.Error())
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
		return nil, fmt.Errorf("Error parsing Nmap scan XML file: %s", err)
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
					if strings.HasPrefix(h.Id, strip(arg)) {
						scanList = append(scanList, h)
					}
				}
			}
			return scanList
		}
	}

	return exportRunE
}

const ansi = "[\u001B\u009B][[\\]()#;?]*(?:(?:(?:[a-zA-Z\\d]*(?:;[a-zA-Z\\d]*)*)?\u0007)|(?:(?:\\d{1,4}(?:;\\d{0,4})*)?[\\dA-PRZcf-ntqry=><~]))"

var re = regexp.MustCompile(ansi)

// Strip removes all ANSI escaped color sequences in a string.
func strip(str string) string {
	return re.ReplaceAllString(str, "")
}
