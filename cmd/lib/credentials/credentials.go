package credentials

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
	"time"

	"github.com/maxlandon/aims/client"
	aims "github.com/maxlandon/aims/cmd/lib/util"
	"github.com/maxlandon/aims/proto/credential"
	"github.com/maxlandon/aims/proto/rpc/credentials"
	"github.com/spf13/cobra"
)

// Commands returns a command tree to manage and display credentials.
func Commands(con *client.Client) *cobra.Command {
	credentialsCmd := &cobra.Command{
		Use:     "credentials",
		Short:   "Manage database credentials",
		GroupID: "database",
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "Display credentials (with filters or styles)",
		RunE: func(command *cobra.Command, args []string) error {
			ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)

			req := &credentials.ReadCredentialRequest{
				Credential: &credential.Core{},
			}

			res, err := con.Creds.Read(ctx, req)
			err = aims.CheckError(err)

			if len(res.GetCredentials()) == 0 {
				// con.PrintInfof("No credentials in database.\n")
				return nil
			}

			return nil
		},
	}

	credentialsCmd.AddCommand(listCmd)

	rmCmd := &cobra.Command{
		Use:   "rm",
		Short: "Remove one or more credentials from the database",
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}

	credentialsCmd.AddCommand(rmCmd)

	showCmd := &cobra.Command{
		Use:   "show",
		Short: "Show one ore more credentials details",
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}

	credentialsCmd.AddCommand(showCmd)

	return credentialsCmd
}
