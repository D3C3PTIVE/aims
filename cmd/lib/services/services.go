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

	"github.com/maxlandon/aims/client"
	aims "github.com/maxlandon/aims/cmd/lib/util"
	"github.com/maxlandon/aims/display"
	"github.com/maxlandon/aims/network"
	pb "github.com/maxlandon/aims/proto/host"
	"github.com/maxlandon/aims/proto/rpc/hosts"
	"github.com/rsteube/carapace"
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
			// res, err := con.Services.ListHost(command.Context(), &network.ReadServiceRequest{
			// 	Service: &pb.Service{},
			// 	Host:    &host.Host{},
			// })
			res, err := con.Hosts.List(command.Context(), &hosts.ReadHostRequest{
				Host: &pb.Host{},
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

			table := display.Table(ports, network.Fields, network.Headers()...)
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
			res, err := con.Hosts.List(cmd.Context(), &hosts.ReadHostRequest{
				Host: &pb.Host{},
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
					fmt.Println(display.Details(h, network.Fields, options...))
				}
			}
			return nil
		},
	}

	showComps := carapace.Gen(showCmd)
	showComps.PositionalAnyCompletion(CompleteByID(con))

	servicesCmd.AddCommand(showCmd)

	return servicesCmd
}

// CompleteByID returns port/service completions with their smallened IDs as keys.
func CompleteByID(client *client.Client) carapace.Action {
	return carapace.ActionCallback(func(c carapace.Context) carapace.Action {
		// Request
		res, err := client.Hosts.List(context.Background(), &hosts.ReadHostRequest{
			Host: &pb.Host{},
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

		results := display.Completions(ports, network.Fields, options...)

		return carapace.ActionValuesDescribed(results...).Tag("hostnames ")
	})
}

const ansi = "[\u001B\u009B][[\\]()#;?]*(?:(?:(?:[a-zA-Z\\d]*(?:;[a-zA-Z\\d]*)*)?\u0007)|(?:(?:\\d{1,4}(?:;\\d{0,4})*)?[\\dA-PRZcf-ntqry=><~]))"

var re = regexp.MustCompile(ansi)

// Strip removes all ANSI escaped color sequences in a string.
func strip(str string) string {
	return re.ReplaceAllString(str, "")
}
