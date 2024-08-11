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
	"path/filepath"

	"github.com/rsteube/carapace"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/maxlandon/aims/client"
	aims "github.com/maxlandon/aims/cmd/lib/util"
)

// ImportCommand returns an "import" subcommand to hook into a parent "object" command, to query/write to DB those objects.
func ImportCommand(parent *cobra.Command, con *client.Client, runE func(cmd *cobra.Command, args []string) error) *cobra.Command {
	importCmd := &cobra.Command{
		Use:   "import",
		Short: fmt.Sprintf("Import %s data", parent.Use),
		// GroupID: parent.GroupID,
		RunE: func(cmd *cobra.Command, args []string) error {
			data := []string{}

			stdin, _ := cmd.Flags().GetBool("stdin")
			if stdin {
				var stdinData []byte
				stdinData, err := ioutil.ReadAll(os.Stdin)
				if err == io.EOF {
					data = append(data, string(stdinData))
				} else if err != nil {
					fmt.Printf("Error: %s\n", err)
					return nil
				}
			}

			// 1 - Read data from all command available sources (args, flags, etc)
			for _, arg := range args {
				argData, err := os.ReadFile(arg)
				if err != nil {
					fmt.Printf("File read error: %s\n", err)
				}

				data = append(data, string(argData))
			}

			// Marshal the data to a Protobuf string representation, and pass it
			// as arguments of the user-provided handler, for it to marshal and
			// send any objects to the server database.

			// Parse the data with the user-provided function.
			err := runE(cmd, data)

			// Halt on errors if required.
			err = aims.CheckError(err)
			if err != nil {
				fmt.Printf("Error: %s\n", err)
				return nil
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
			stringData, err := marshalExportData(cmd, exportData)
			err = aims.CheckError(err)
			if err != nil {
				fmt.Printf("Error: %s\n", err)
				return nil
			}

			if len(stringData) == 0 {
				return nil
			}

			// Output it to specified destinations.
			return writeToSources(cmd, stringData)
		},
	}

	exportCmd.AddGroup(&cobra.Group{ID: "database", Title: "database"})

	aims.Bind(exportCmd.Name(), false, exportCmd, func(f *pflag.FlagSet) {
		f.StringP("format", "F", "json", "Export to specific serialization format")
		f.BoolP("xml", "X", false, "Export data in XML format")
		f.StringP("file", "f", "", "Export data to a file instead of stdout")
	})

	return exportCmd
}

func marshalExportData(cmd *cobra.Command, data any) (s string, err error) {
	buf := new(bytes.Buffer)

	// XML
	if asXml, _ := cmd.Flags().GetBool("xml"); asXml {
		raw, err := xml.MarshalIndent(data, "", "\t")
		if err != nil {
			return "", err
		}

		buf.Write(raw)

		return buf.String(), nil
	}

	// Default is JSON
	raw, err := json.MarshalIndent(data, "", "\t")
	buf.Write(raw)

	return buf.String(), nil
}

func writeToSources(cmd *cobra.Command, data string) error {
	file, _ := cmd.Flags().GetString("file")

	if len(file) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), data)
		return nil
	}

	filePath, err := filepath.Abs(file)
	if err != nil {
		filePath = file
	}

	_, err = os.Stat(filePath)
	if os.IsNotExist(err) || os.IsExist(err) {
		f, _ := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		f.WriteString(data)
	}

	if err != nil {
		return err
	}

	return nil
}
