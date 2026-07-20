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

	"github.com/carapace-sh/carapace"
	"github.com/spf13/cobra"

	core "github.com/d3c3ptive/aims/c2"
	"github.com/d3c3ptive/aims/c2/pb"
	c2 "github.com/d3c3ptive/aims/c2/pb/rpc"
	"github.com/d3c3ptive/aims/client"
	aims "github.com/d3c3ptive/aims/cmd"
	"github.com/d3c3ptive/aims/cmd/display"
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

			// Generate the table of channels.
			table := display.Table(res.GetChannels(), core.DisplayFieldsChannel, core.DisplayHeadersChannel()...)
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

			options := core.DisplayDetailsChannel()

			if tasks {
				options = append(options, display.WithHeader("Tasks Details", 3))
			}

			// Request
			res, err := con.Channels.Read(command.Context(), &c2.ReadChannelRequest{
				Channel: &pb.Channel{},
				Filters: &c2.ChannelFilters{},
			})
			if err = aims.CheckError(err); err != nil {
				return err
			}

			// Display: with no args show every channel, else those whose ID has a given prefix.
			for _, h := range res.GetChannels() {
				if len(args) > 0 && !aims.MatchesAnyPrefix(h.Id, args) {
					continue
				}
				fmt.Println(display.Details(h, core.DisplayFieldsChannel, options...))
			}

			return nil
		},
	}

	scanCmd.AddCommand(showCmd)

	showComps := carapace.Gen(showCmd)
	showComps.PositionalAnyCompletion(CompleteChannelByID(con))

	return scanCmd
}

// CompleteChannelByID returns channel completions with their smallened IDs as keys.
func CompleteChannelByID(client *client.Client) carapace.Action {
	return aims.CacheCompletion(client, "channels:id", carapace.ActionCallback(func(c carapace.Context) carapace.Action {
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

		options := core.CompletionsChannel()
		options = append(options, display.WithCandidateValue("ID", ""))

		results := display.Completions(res.Channels, core.DisplayFieldsChannel, options...)

		return carapace.ActionValuesDescribed(results...).Tag("channels ")
	}))
}
