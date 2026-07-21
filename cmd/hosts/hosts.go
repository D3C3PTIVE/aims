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
	"strings"

	"github.com/carapace-sh/carapace"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/d3c3ptive/aims/client"
	aims "github.com/d3c3ptive/aims/cmd"
	"github.com/d3c3ptive/aims/cmd/completers"
	"github.com/d3c3ptive/aims/cmd/display"
	"github.com/d3c3ptive/aims/cmd/export"
	"github.com/d3c3ptive/aims/host"
	"github.com/d3c3ptive/aims/host/pb"
	hosts "github.com/d3c3ptive/aims/host/pb/rpc"
)

// Commands returns a command tree to manage and cmd/display hosts.
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
				Filters: &hosts.HostFilters{
					Trace: true,
				},
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
			table := display.Table(res.GetHosts(), host.DisplayFields, host.DisplayHeaders()...)
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

	aims.BindFlags(addCmd.Name(), false, addCmd, func(f *pflag.FlagSet) {
		f.StringP("file", "f", "", "Path to file containing hosts data")
	})
	carapace.Gen(addCmd).FlagCompletion(carapace.ActionMap{
		"file": carapace.ActionFiles().Usage("file containing hosts data"),
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

			// Request
			res, err := client.Hosts.Read(command.Context(), &hosts.ReadHostRequest{
				Host: &pb.Host{},
				Filters: &hosts.HostFilters{
					Ports: true,
					Trace: true,
				},
			})
			if err = aims.CheckError(err); err != nil {
				return err
			}

			// Display. With no arguments, show every host; otherwise only
			// those whose ID has one of the given (ANSI-stripped) prefixes.
			// Each host renders through the shared Banner/Panes/Insights/Sections
			// detail layout, identical to the credential and service info views.
			for _, h := range res.GetHosts() {
				if len(args) > 0 && !aims.MatchesAnyPrefix(h.Id, args) {
					continue
				}
				fmt.Println(host.Detail(h, traceroute).Render(0))
				fmt.Println()
			}

			return nil
		},
	}
	aims.BindFlags(showCmd.Name(), false, showCmd, func(f *pflag.FlagSet) {
		f.BoolP("traceroute", "T", false, "Print full network routes to host")
	})
	hostsCmd.AddCommand(showCmd)

	showComps := carapace.Gen(showCmd)
	showComps.PositionalAnyCompletion(CompleteByID(client))

	// Export
	exportCmd := export.ExportCommand(hostsCmd, client, exportCommand(client))
	hostsCmd.AddCommand(exportCmd)

	return hostsCmd
}

// readHostsForCompletion reads every host with the base preloads (OS matches, status, hostnames,
// addresses) the completion descriptions render. A non-nil (even empty) filter is what triggers
// those base preloads server-side — passing nil would load only depth-1 associations and leave the
// OS/status columns thin.
func readHostsForCompletion(client *client.Client) ([]*pb.Host, error) {
	res, err := client.Hosts.Read(context.Background(), &hosts.ReadHostRequest{
		Host:    &pb.Host{},
		Filters: &hosts.HostFilters{},
	})
	return res.GetHosts(), err
}

// CompleteByID returns hosts completions with their smallened IDs as keys.
func CompleteByID(client *client.Client) carapace.Action {
	return completers.CachedList(client, "hosts:id", "hosts:id", "no hosts in database",
		func() ([]*pb.Host, error) { return readHostsForCompletion(client) },
		func(hs []*pb.Host) carapace.Action {
			options := host.Completions()
			options = append(options, display.WithCandidateValue("ID", ""))
			results := display.Completions(hs, host.DisplayFields, options...)
			return carapace.ActionValuesDescribed(results...).Tag("hostnames ")
		},
	)
}

// CompleteByHostnameOrIP returns completions for all hostnames,
// or if not found for some hosts, their corresponding addresses.
func CompleteByHostnameOrIP(client *client.Client) carapace.Action {
	return completers.CachedList(client, "hosts:hostname-or-ip", "hosts:hostname-or-ip", "no hosts in database",
		func() ([]*pb.Host, error) { return readHostsForCompletion(client) },
		func(hs []*pb.Host) carapace.Action {
			options := host.Completions()
			options = append(options, display.WithCandidateValue("Hostnames", "Addresses"))
			options = append(options, display.WithSplitCandidate(","))
			results := display.Completions(hs, host.DisplayFields, options...)
			return carapace.ActionValuesDescribed(results...).Tag("hostnames ")
		},
	)
}

func exportCommand(con *client.Client) func(cmd *cobra.Command, args []string) any {
	// If we have some data, export it according
	// to command flag specifications (format, file, etc)
	exportRunE := func(command *cobra.Command, args []string) (data any) {
		// Same read for both paths (all hosts, ports+trace preloaded); only the post-read
		// filtering differs, so issue it once and branch on whether IDs were given.
		res, err := con.Hosts.Read(command.Context(), &hosts.ReadHostRequest{
			Host: &pb.Host{},
			Filters: &hosts.HostFilters{
				Ports: true,
				Trace: true,
			},
		})
		if err = aims.CheckError(err); err != nil {
			return err
		}

		if len(args) == 0 {
			return res.GetHosts()
		}

		// Keep only the hosts whose ID carries one of the given prefixes.
		scanList := []*pb.Host{}
		for _, arg := range args {
			for _, h := range res.GetHosts() {
				if strings.HasPrefix(h.Id, aims.StripANSI(arg)) {
					scanList = append(scanList, h)
				}
			}
		}
		return scanList
	}

	return exportRunE
}
