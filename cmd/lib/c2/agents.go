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
	"regexp"
	"strings"

	"github.com/rsteube/carapace"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	core "github.com/maxlandon/aims/c2"
	"github.com/maxlandon/aims/client"
	aims "github.com/maxlandon/aims/cmd/lib/util"
	"github.com/maxlandon/aims/display"
	pb "github.com/maxlandon/aims/proto/c2"
	"github.com/maxlandon/aims/proto/rpc/c2"
	"github.com/maxlandon/aims/scan"
)

// AgentsCommands returns all agent management commands.
func AgentsCommands(con *client.Client) *cobra.Command {
	scanCmd := &cobra.Command{
		Use:     "agents",
		Short:   "Manage Command-And-Control agents",
		GroupID: "command & control",
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "Display agents (with filters or styles)",
		RunE: func(command *cobra.Command, args []string) error {
			res, err := con.Agents.Read(command.Context(), &c2.ReadAgentRequest{
				Agent:   &pb.Agent{},
				Filters: &c2.AgentFilters{},
			})
			err = aims.CheckError(err)
			if err != nil {
				return err
			}

			if len(res.GetAgents()) == 0 {
				fmt.Printf("No c2 in database.\n")
				return nil
			}

			// Generate the table of hosts.
			table := display.Table(res.GetAgents(), core.DisplayFields, core.DisplayHeaders()...)
			fmt.Println(table.Render())

			return nil
		},
	}

	scanCmd.AddCommand(listCmd)

	showCmd := &cobra.Command{
		Use:   "show",
		Short: "Show one ore more agent details",
		RunE: func(command *cobra.Command, args []string) error {
			tasks, _ := command.Flags().GetBool("tasks")

			options := scan.DisplayDetails()

			if tasks {
				options = append(options, display.WithHeader("Tasks Details", 3))
			}

			// Request
			res, err := con.Agents.Read(command.Context(), &c2.ReadAgentRequest{
				Agent:   &pb.Agent{},
				Filters: &c2.AgentFilters{},
			})
			err = aims.CheckError(err)

			// Display
			for _, h := range res.GetAgents() {
				if strings.HasPrefix(h.Id, strip(args[0])) {
					fmt.Println(display.Details(h, core.DisplayFields, options...))
				}
			}

			return nil
		},
	}

	showComps := carapace.Gen(showCmd)
	showComps.PositionalAnyCompletion(CompleteByID(con))

	aims.Bind(showCmd.Name(), false, showCmd, func(f *pflag.FlagSet) {
		f.BoolP("tasks", "t", false, "Show all agent tasks status/details")
	})

	scanCmd.AddCommand(showCmd)

	return scanCmd
}

// CompleteByID returns hosts completions with their smallened IDs as keys.
func CompleteByID(client *client.Client) carapace.Action {
	return carapace.ActionCallback(func(c carapace.Context) carapace.Action {
		if msg, err := client.ConnectComplete(); err != nil {
			return msg
		}

		// Request
		res, err := client.Agents.Read(context.Background(), &c2.ReadAgentRequest{
			Agent: &pb.Agent{},
		})
		if err = aims.CheckError(err); err != nil {
			return carapace.ActionMessage("Error: %s", err)
		}

		options := core.Completions()
		options = append(options, display.WithCandidateValue("ID", ""))

		results := display.Completions(res.Agents, core.DisplayFields, options...)

		return carapace.ActionValuesDescribed(results...).Tag("agents ")
	})
}

const ansi = "[\u001B\u009B][[\\]()#;?]*(?:(?:(?:[a-zA-Z\\d]*(?:;[a-zA-Z\\d]*)*)?\u0007)|(?:(?:\\d{1,4}(?:;\\d{0,4})*)?[\\dA-PRZcf-ntqry=><~]))"

var re = regexp.MustCompile(ansi)

// Strip removes all ANSI escaped color sequences in a string.
func strip(str string) string {
	return re.ReplaceAllString(str, "")
}
