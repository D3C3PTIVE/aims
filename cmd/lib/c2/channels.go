package c2

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

	"github.com/rsteube/carapace"
	"github.com/spf13/cobra"

	core "github.com/maxlandon/aims/c2"
	"github.com/maxlandon/aims/client"
	aims "github.com/maxlandon/aims/cmd/lib/util"
	"github.com/maxlandon/aims/display"
	pb "github.com/maxlandon/aims/proto/c2"
	"github.com/maxlandon/aims/proto/rpc/c2"
	"github.com/maxlandon/aims/scan"
)

// ChannelsCommands returns all agent management commands.
func ChannelsCommands(con *client.Client) *cobra.Command {
	scanCmd := &cobra.Command{
		Use:     "channels",
		Short:   "Manage Command-And-Control channels",
		GroupID: "command & control",
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "Display command-&-control Channels (with filters or styles)",
		RunE: func(command *cobra.Command, args []string) error {
			res, err := con.Channels.Read(command.Context(), &c2.ReadChannelRequest{
				Channel: &pb.Channel{},
				Filters: &c2.ChannelFilters{},
			})
			err = aims.CheckError(err)
			if err != nil {
				return err
			}

			if len(res.GetChannels()) == 0 {
				fmt.Printf("No C2 channels in database.\n")
				return nil
			}

			// Generate the table of hosts.
			table := display.Table(res.GetChannels(), nil, scan.DisplayHeaders()...)
			fmt.Println(table.Render())

			return nil
		},
	}

	scanCmd.AddCommand(listCmd)

	showCmd := &cobra.Command{
		Use:   "show",
		Short: "Show one ore more channel details",
		RunE: func(command *cobra.Command, args []string) error {
			tasks, _ := command.Flags().GetBool("tasks")

			options := scan.DisplayDetails()

			if tasks {
				options = append(options, display.WithHeader("Tasks Details", 3))
			}

			// Request
			res, err := con.Channels.Read(command.Context(), &c2.ReadChannelRequest{
				Channel: &pb.Channel{},
				Filters: &c2.ChannelFilters{},
			})
			err = aims.CheckError(err)

			// Display
			for _, h := range res.GetChannels() {
				if strings.HasPrefix(h.Id, strip(args[0])) {
					fmt.Println(display.Details(h, nil, options...))
				}
			}

			return nil
		},
	}
	scanCmd.AddCommand(showCmd)

	showComps := carapace.Gen(showCmd)
	showComps.PositionalAnyCompletion(CompleteByID(con))

	return scanCmd
}

// CompleteByID returns hosts completions with their smallened IDs as keys.
func CompleteChannelByID(client *client.Client) carapace.Action {
	return carapace.ActionCallback(func(c carapace.Context) carapace.Action {
		if msg, err := client.ConnectComplete(); err != nil {
			return msg
		}

		// Request
		res, err := client.Channels.Read(context.Background(), &c2.ReadChannelRequest{
			Channel: &pb.Channel{},
		})
		if err = aims.CheckError(err); err != nil {
			return carapace.ActionMessage("Error: %s", err)
		}

		options := core.Completions()
		options = append(options, display.WithCandidateValue("ID", ""))

		results := display.Completions(res.Channels, core.DisplayFieldsChannel, options...)

		return carapace.ActionValuesDescribed(results...).Tag("agents ")
	})
}
