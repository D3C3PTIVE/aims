package services

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
	"github.com/maxlandon/aims/client"
	aims "github.com/maxlandon/aims/cmd/lib/util"
	"github.com/maxlandon/aims/proto/host"
	pb "github.com/maxlandon/aims/proto/network"
	"github.com/maxlandon/aims/proto/rpc/network"
	"github.com/spf13/cobra"
)

// Commands returns a command tree to manage and display services.
func Commands(con *client.Client) *cobra.Command {
	servicesCmd := &cobra.Command{
		Use:     "services",
		Short:   "Manage database services",
		GroupID: "database",
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "Display services (with filters or styles)",
		RunE: func(command *cobra.Command, args []string) error {
			res, err := con.Services.ListHost(command.Context(), &network.ReadServiceRequest{
				Service: &pb.Service{},
				Host:    &host.Host{},
			})
			err = aims.CheckError(err)

			if len(res.GetServices()) == 0 {
				// con.PrintInfof("No services in database.\n")
				return nil
			}

			// Generate the table of services (we pass hosts, but we give a list of resolvers/handlers
			// tailored for printing their associated services and ports)
			// table := display.Table[*pb.Host](res.GetHosts(), host.Fields, host.Headers()...)
			// fmt.Println(table.Render())

			return nil
		},
	}

	servicesCmd.AddCommand(listCmd)

	rmCmd := &cobra.Command{
		Use:   "rm",
		Short: "Remove one or more services from the database",
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}

	servicesCmd.AddCommand(rmCmd)

	showCmd := &cobra.Command{
		Use:   "show",
		Short: "Show one ore more services details",
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}

	servicesCmd.AddCommand(showCmd)

	return servicesCmd
}
