package export

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
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/rsteube/carapace"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/maxlandon/aims/client"
	aims "github.com/maxlandon/aims/cmd/lib/util"
)

// ImportCommand returns an "import" subcommand to hook into a parent "object" command, to query/write to DB those objects.
func ImportCommand(parent *cobra.Command, con *client.Client, runE func(cmd *cobra.Command, arg string, data []byte) error) *cobra.Command {
	importCmd := &cobra.Command{
		Use:   "import",
		Short: fmt.Sprintf("Import %s data", parent.Use),
		// GroupID: parent.GroupID,
		RunE: func(cmd *cobra.Command, args []string) error {
			for _, arg := range args {
				// Read contents from source file
				data, err := os.ReadFile(arg)
				if err != nil {
					fmt.Printf("File read error: %s\n", err)
				}

				// And unmarshal with any format handler suitable.
				if err = runE(cmd, arg, data); err != nil {
					return err
				}
			}

			// Handle stdin if required as well
			stdin, _ := cmd.Flags().GetBool("stdin")

			if stdin {
				var stdinData []byte
				stdinData, err := ioutil.ReadAll(os.Stdin)
				if err != nil && err != io.EOF {
					fmt.Printf("Error: %s\n", err)
					return nil
				}

				// And unmarshal with any format handler suitable.
				if err = runE(cmd, "stdin", stdinData); err != nil {
					return err
				}
			}
			return nil
		},
	}
	importCmd.AddGroup(&cobra.Group{ID: "database", Title: "database"})

	aims.Bind(importCmd.Name(), false, importCmd, func(f *pflag.FlagSet) {
		f.StringP("format", "F", "json", "Hint (or force) the file with a specific serialization format")
		f.BoolP("stdin", "i", false, "Read values from stdin")
	})

	argsUsage := fmt.Sprintf("%s files to import", parent.Use)
	carapace.Gen(importCmd).PositionalAnyCompletion(carapace.ActionFiles().Usage(argsUsage))

	return importCmd
}

// ExportCommand returns an "export" subcommand to hook into a parent "object" command, to query/write to DB those objects.
func ExportCommand(parent *cobra.Command, con *client.Client, data func(cmd *cobra.Command, args []string) any) *cobra.Command {
	exportCmd := &cobra.Command{
		Use:   "export",
		Short: fmt.Sprintf("Export %s data", parent.Use),
		// GroupID: parent.GroupID,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Generate an interface to marshal.
			exportData := data(cmd, args)

			// Marshal it according to requirements
			stringData, err := MarshalExport(cmd, exportData)
			err = aims.CheckError(err)
			if err != nil {
				fmt.Printf("Error: %s\n", err)
				return nil
			}

			if len(stringData) == 0 {
				return nil
			}

			// Output it to specified destinations.
			fmt.Fprintln(cmd.OutOrStdout(), string(stringData))
			return nil
		},
	}

	exportCmd.AddGroup(&cobra.Group{ID: "database", Title: "database"})

	aims.Bind(exportCmd.Name(), false, exportCmd, func(f *pflag.FlagSet) {
		f.BoolP("xml", "X", false, "Export data in XML format")
	})

	comps := carapace.Gen(exportCmd)

	comps.FlagCompletion(carapace.ActionMap{
		"file": carapace.ActionFiles().Usage("File to export %s data (can be created)", parent.Use),
	})

	return exportCmd
}

// MarshalExport accepts some arbitrary with the command in which this data
// was created, and marshals it given some command formatting flags.
func MarshalExport(cmd *cobra.Command, data any) (s []byte, err error) {
	buf := new(bytes.Buffer)

	// XML
	if asXml, _ := cmd.Flags().GetBool("xml"); asXml {
		raw, err := xml.MarshalIndent(data, "", "\t")
		if err != nil {
			return nil, err
		}

		buf.Write(raw)

		return buf.Bytes(), nil
	}

	// Default is JSON
	raw, err := json.MarshalIndent(data, "", "\t")
	if err != nil {
		return nil, err
	}

	buf.Write(raw)

	return buf.Bytes(), nil
}

// ImportJSON takes a protobuf message struct and unmarshals data into either this type or a list.
func ImportJSON[out protoreflect.ProtoMessage](data []byte, arg string) (list []out, err error) {
	// Is it an array?
	if bytes.HasPrefix(bytes.TrimSpace(data), []byte{'['}) {
		if err := json.Unmarshal(data, &list); err != nil {
			fmt.Printf("Error unmarshaling as list (in %s): %s", arg, err)
			return nil, err
		}
	} else {
		genericScan := new(out) // In case we must unmar
		if err := json.Unmarshal(data, &genericScan); err != nil {
			fmt.Printf("Error unmarshaling one object (in %s): %s", arg, err)
			return nil, err
		}
		list = append(list, *genericScan)
	}
	return
}
