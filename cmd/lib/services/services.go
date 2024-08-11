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
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/rsteube/carapace"
	"github.com/spf13/cobra"

	"github.com/maxlandon/aims/client"
	"github.com/maxlandon/aims/cmd/lib/export"
	aims "github.com/maxlandon/aims/cmd/lib/util"
	"github.com/maxlandon/aims/display"
	"github.com/maxlandon/aims/network"
	pb "github.com/maxlandon/aims/proto/host"
	"github.com/maxlandon/aims/proto/rpc/hosts"
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
			res, err := con.Hosts.Read(command.Context(), &hosts.ReadHostRequest{
				Host: &pb.Host{},
				Filters: &hosts.HostFilters{
					Ports: true,
				},
			})
			if err = aims.CheckError(err); err != nil {
				return err
			}

			if len(res.GetHosts()) == 0 {
				return nil
			}

			var ports []*pb.Port
			for _, h := range res.GetHosts() {
				ports = append(ports, h.GetPorts()...)
			}

			table := display.Table(ports, network.DisplayFields, network.Headers()...)
			fmt.Println(table.Render())

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
			options := network.Details()

			// Request
			res, err := con.Hosts.Read(cmd.Context(), &hosts.ReadHostRequest{
				Host: &pb.Host{},
				Filters: &hosts.HostFilters{
					Ports: true,
				},
			})
			err = aims.CheckError(err)
			if err != nil {
				return err
			}

			var ports []*pb.Port
			for _, h := range res.GetHosts() {
				ports = append(ports, h.GetPorts()...)
			}

			// Display
			for _, h := range ports {
				if strings.HasPrefix(h.Id, strip(args[0])) {
					fmt.Println(display.Details(h, network.DisplayFields, options...))
				}
			}
			return nil
		},
	}
	servicesCmd.AddCommand(showCmd)

	showComps := carapace.Gen(showCmd)
	showComps.PositionalAnyCompletion(CompleteByID(con))

	// Export
	exportCmd := export.ExportCommand(servicesCmd, con, exportCommand(con))
	servicesCmd.AddCommand(exportCmd)

	return servicesCmd
}

// CompleteByID returns port/service completions with their smallened IDs as keys.
func CompleteByID(client *client.Client) carapace.Action {
	return carapace.ActionCallback(func(c carapace.Context) carapace.Action {
		if msg, err := client.ConnectComplete(); err != nil {
			return msg
		}
		// Request
		res, err := client.Hosts.Read(context.Background(), &hosts.ReadHostRequest{
			Host: &pb.Host{},
			Filters: &hosts.HostFilters{
				Ports: true,
			},
		})
		if err = aims.CheckError(err); err != nil {
			return carapace.ActionMessage("Error: %s", err)
		}

		options := network.Completions()
		options = append(options, display.WithCandidateValue("ID", ""))

		var ports []*pb.Port
		for _, h := range res.GetHosts() {
			ports = append(ports, h.GetPorts()...)
		}

		results := display.Completions(ports, network.DisplayFields, options...)

		return carapace.ActionValuesDescribed(results...).Tag("hostnames ")
	})
}

func exportCommand(con *client.Client) func(cmd *cobra.Command, args []string) any {
	// If we have some data, export it according
	// to command flag specifications (format, file, etc)
	exportRunE := func(command *cobra.Command, args []string) (data any) {
		if len(args) == 0 {
			res, err := con.Hosts.Read(command.Context(), &hosts.ReadHostRequest{
				Host: &pb.Host{},
				Filters: &hosts.HostFilters{
					Ports: true,
				},
			})
			err = aims.CheckError(err)
			if err != nil {
				return err
			}

			servicesList := []*pb.Port{}
			for _, h := range res.GetHosts() {
				servicesList = append(servicesList, h.Ports...)
			}

			return servicesList
		} else {
			res, err := con.Hosts.Read(command.Context(), &hosts.ReadHostRequest{
				Host: &pb.Host{},
				Filters: &hosts.HostFilters{
					Ports: true,
				},
			})
			err = aims.CheckError(err)
			if err != nil {
				return err
			}

			scanList := []*pb.Host{}
			servicesList := []*pb.Port{}

			// Display
			for _, arg := range args {
				for _, h := range res.GetHosts() {
					if strings.HasPrefix(h.Id, strip(arg)) {
						scanList = append(scanList, h)
					}
				}
			}

			for _, h := range scanList {
				servicesList = append(servicesList, h.Ports...)
			}

			return servicesList
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
