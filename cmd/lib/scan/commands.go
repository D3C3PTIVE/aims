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
	"regexp"
	"strings"

	"github.com/golang/protobuf/proto"
	"github.com/rsteube/carapace"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/maxlandon/aims/client"
	"github.com/maxlandon/aims/cmd/lib/export"
	aims "github.com/maxlandon/aims/cmd/lib/util"
	"github.com/maxlandon/aims/display"
	"github.com/maxlandon/aims/proto/rpc/scans"
	pb "github.com/maxlandon/aims/proto/scan"
	"github.com/maxlandon/aims/scan"
	"github.com/maxlandon/aims/scan/nmap"
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

	aims.Bind(importCmd.Name(), false, importCmd, func(f *pflag.FlagSet) {
		f.BoolP("nmap", "N", false, "Hint (or force) parsing the file(s) as nmap scans (default nmap format used is xml)")
	})

	carapace.Gen(importCmd).PositionalAnyCompletion(carapace.ActionFiles().Usage("scan files to import"))

    // Export
    exportCmd := export.ExportCommand(scanCmd, con, exportCommand(con))
	scanCmd.AddCommand(exportCmd)

	aims.Bind(importCmd.Name(), false, importCmd, func(f *pflag.FlagSet) {
		f.BoolP("xml", "X", false, "Output in XML format")
		f.StringP("file", "f", "", "Output to a file")
	})

	return scanCmd
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
			for _, h := range res.GetScans() {
				if strings.HasPrefix(h.Id, strip(args[0])) {
					fmt.Println(display.Details(h, scan.DisplayFields, options...))
				}
			}

			return nil
		},
	}

	aims.Bind(showCmd.Name(), false, showCmd, func(f *pflag.FlagSet) {
		f.BoolP("targets", "T", false, "Show scan targets' details")
	})
	aims.Bind(showCmd.Name(), false, showCmd, func(f *pflag.FlagSet) {
		f.BoolP("tasks", "t", false, "Show all scan tasks status/details")
	})

    return showCmd
}

func importCommand(con *client.Client) func(cmd *cobra.Command, args []string) error {
    
    importRunE := func(command *cobra.Command, args []string) (err error) {
        for _, arg := range args {
            // Handle XML parsing here if asked to it as an Nmap scan.
			asNmap, _ := command.Flags().GetBool("nmap")

            var genericScan *scan.Run

            if asNmap {
                genericScan, err = nmap.FromXML([]byte(arg))
                if err != nil || genericScan == nil {
                    fmt.Printf("Error parsing Nmap scan XML file: %s", err)
                    return nil
                }
            } else {
                genericScan = &scan.Run{}
            }

            err = proto.UnmarshalText(arg, genericScan.ToPB())
            err = aims.CheckError(err)
            if err != nil {
                return err
            }

            // Determine if scan is running: if yes, watch the file for changes
            // and monitor the input. Notify the user on the command that we are
            // monitoring the scan file.

            // Register all objects to database, with adjustements.
            _, err = con.Scans.Create(command.Context(), &scans.CreateScanRequest{
                Scans: []*pb.Run{genericScan.ToPB()},
            })

            err = aims.CheckError(err)
            if err != nil {
                return err
            }
        }

        return nil
    }

    return importRunE
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

            return scanList
        }
        }

        return nil
    }

   return exportRunE
}

const ansi = "[\u001B\u009B][[\\]()#;?]*(?:(?:(?:[a-zA-Z\\d]*(?:;[a-zA-Z\\d]*)*)?\u0007)|(?:(?:\\d{1,4}(?:;\\d{0,4})*)?[\\dA-PRZcf-ntqry=><~]))"

var re = regexp.MustCompile(ansi)

// Strip removes all ANSI escaped color sequences in a string.
func strip(str string) string {
	return re.ReplaceAllString(str, "")
}

