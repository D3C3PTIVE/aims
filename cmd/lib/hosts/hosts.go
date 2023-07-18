package hosts

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
	"github.com/maxlandon/aims/host"
	pb "github.com/maxlandon/aims/proto/host"
	"github.com/maxlandon/aims/proto/rpc/hosts"
	"github.com/rsteube/carapace"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// Commands returns a command tree to manage and display hosts.
func Commands(client *client.Client) *cobra.Command {
	hostsCmd := &cobra.Command{
		Use:     "hosts",
		Short:   "Manage database hosts",
		GroupID: "database",
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "Display hosts (with filters or styles)",
		RunE: func(command *cobra.Command, args []string) error {
			res, err := client.Hosts.Read(command.Context(), &hosts.ReadHostRequest{
				Host: &pb.Host{},
			})
			err = aims.CheckError(err)
			if err != nil {
				return err
			}

			if len(res.GetHosts()) == 0 {
				fmt.Printf("No hosts in database.\n")
				// con.PrintInfof("No hosts in database.\n")
				return nil
			}

			// Generate the table of hosts.
			// TODO: Print to command stdout.
			table := display.Table(res.GetHosts(), host.Fields, host.Headers()...)
			fmt.Println(table.Render())

			return nil
		},
	}

	hostsCmd.AddCommand(listCmd)

	addCmd := &cobra.Command{
		Use:   "add",
		Short: "Add hosts to the database",
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}

	aims.Bind(addCmd.Name(), false, addCmd, func(f *pflag.FlagSet) {
		f.StringP("file", "f", "", "Path to file containing hosts data")
	})

	hostsCmd.AddCommand(addCmd)

	rmCmd := &cobra.Command{
		Use:   "rm",
		Short: "Remove one or more hosts from the database",
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}

	rmComps := carapace.Gen(rmCmd)
	rmComps.PositionalAnyCompletion(CompleteByHostnameOrIP(client))

	hostsCmd.AddCommand(rmCmd)

	showCmd := &cobra.Command{
		Use:   "show",
		Short: "Show one ore more hosts details",
		RunE: func(command *cobra.Command, args []string) error {
			traceroute, _ := command.Flags().GetBool("traceroute")

			options := host.Details()

			if traceroute {
				options = append(options, display.WithHeader("Route", 3))
			}

			// Request
			res, err := client.Hosts.Read(command.Context(), &hosts.ReadHostRequest{
				Host: &pb.Host{},
			})
			err = aims.CheckError(err)

			// Display
			for _, h := range res.GetHosts() {
				if strings.HasPrefix(h.Id, strip(args[0])) {
					fmt.Println(display.Details(h, host.Fields, options...))
				}
			}

			return nil
		},
	}
	aims.Bind(showCmd.Name(), false, showCmd, func(f *pflag.FlagSet) {
		f.BoolP("traceroute", "T", false, "Print full network routes to host")
	})

	showComps := carapace.Gen(showCmd)
	showComps.PositionalAnyCompletion(CompleteByID(client))

	hostsCmd.AddCommand(showCmd)

	return hostsCmd
}

// CompleteByID returns hosts completions with their smallened IDs as keys.
func CompleteByID(client *client.Client) carapace.Action {
	return carapace.ActionCallback(func(c carapace.Context) carapace.Action {
		// Request
		res, err := client.Hosts.Read(context.Background(), &hosts.ReadHostRequest{
			Host: &pb.Host{},
		})
		if err = aims.CheckError(err); err != nil {
			return carapace.ActionMessage("Error: %s", err)
		}

		options := host.Completions()
		options = append(options, display.WithCandidateValue("ID", ""))

		results := display.Completions(res.Hosts, host.Fields, options...)

		return carapace.ActionValuesDescribed(results...).Tag("hostnames ")
	})
}

// CompleteByHostnameOrIP returns completions for all hostnames,
// or if not found for some hosts, their corresponding addresses.
func CompleteByHostnameOrIP(client *client.Client) carapace.Action {
	return carapace.ActionCallback(func(c carapace.Context) carapace.Action {
		// Request
		res, err := client.Hosts.Read(context.Background(), &hosts.ReadHostRequest{
			Host: &pb.Host{},
		})
		if err = aims.CheckError(err); err != nil {
			return carapace.ActionMessage("Error: %s", err)
		}

		options := host.Completions()
		options = append(options, display.WithCandidateValue("Hostnames", "Addresses"))
		options = append(options, display.WithSplitCandidate(","))

		results := display.Completions(res.Hosts, host.Fields, options...)

		return carapace.ActionValuesDescribed(results...).Tag("hostnames ")
	})
}

const ansi = "[\u001B\u009B][[\\]()#;?]*(?:(?:(?:[a-zA-Z\\d]*(?:;[a-zA-Z\\d]*)*)?\u0007)|(?:(?:\\d{1,4}(?:;\\d{0,4})*)?[\\dA-PRZcf-ntqry=><~]))"

var re = regexp.MustCompile(ansi)

// Strip removes all ANSI escaped color sequences in a string.
func strip(str string) string {
	return re.ReplaceAllString(str, "")
}
