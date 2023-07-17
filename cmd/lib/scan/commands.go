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

	"github.com/maxlandon/aims/client"
	aims "github.com/maxlandon/aims/cmd/lib/util"
	"github.com/maxlandon/aims/proto/rpc/hosts"
	"github.com/maxlandon/aims/scan/nmap"
	"github.com/rsteube/carapace"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// Commands returns all scan commands.
func Commands(con *client.Client) *cobra.Command {
	scanCmd := &cobra.Command{
		Use:     "scan",
		Short:   "Manage running and database scans",
		GroupID: "database",
	}

	importCmd := &cobra.Command{
		Use:   "import",
		Short: "Import scan data from one or more files",
		RunE: func(command *cobra.Command, args []string) error {
			// For each file,
			for _, arg := range args {
				data, err := os.ReadFile(arg)
				if err != nil {
					fmt.Printf("File read error: %s", err)
					return nil
				}

				genericScan, err := nmap.FromXML(data)
				if err != nil || genericScan == nil {
					fmt.Printf("Error parsing Nmap scan XML file: %s", err)
					return nil
				}

				// Register all objects to database, with adjustements.
				_, err = con.Hosts.Create(command.Context(), &hosts.CreateHostRequest{
					Hosts: genericScan.Hosts,
				})
				err = aims.CheckError(err)

				if err != nil {
					// con.PrintErrorf("Error: %s\n", err)
					return nil
				}
			}

			return nil
		},
	}

	aims.Bind(importCmd.Name(), false, importCmd, func(f *pflag.FlagSet) {
		f.BoolP("nmap", "N", false, "Hint (or force) parsing the file(s) as nmap scans (default nmap format used is xml)")
		f.StringP("format", "F", "xml", "Hint (or force) the file with a specific serialization format")
	})

	carapace.Gen(importCmd).PositionalAnyCompletion(carapace.ActionFiles().Usage("scan files to import"))

	scanCmd.AddCommand(importCmd)

	return scanCmd
}
