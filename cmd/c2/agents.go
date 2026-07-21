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
	"github.com/spf13/pflag"

	core "github.com/d3c3ptive/aims/c2"
	pb "github.com/d3c3ptive/aims/c2/pb"
	c2 "github.com/d3c3ptive/aims/c2/pb/rpc"
	"github.com/d3c3ptive/aims/client"
	aims "github.com/d3c3ptive/aims/cmd"
	"github.com/d3c3ptive/aims/cmd/completers"
	"github.com/d3c3ptive/aims/cmd/display"
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
				fmt.Printf("No agents in database.\n")
				return nil
			}

			// Generate the table of agents.
			table := display.Table(res.GetAgents(), core.DisplayFieldsAgent, core.DisplayHeadersAgent()...)
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

			options := core.DisplayDetailsAgent()

			if tasks {
				options = append(options, display.WithHeader("Tasks Details", 3))
			}

			// Request
			res, err := con.Agents.Read(command.Context(), &c2.ReadAgentRequest{
				Agent:   &pb.Agent{},
				Filters: &c2.AgentFilters{},
			})
			if err = aims.CheckError(err); err != nil {
				return err
			}

			// Display: with no args show every agent, else those whose ID has a given prefix.
			for _, h := range res.GetAgents() {
				if len(args) > 0 && !aims.MatchesAnyPrefix(h.Id, args) {
					continue
				}
				fmt.Println(display.Details(h, core.DisplayFieldsAgent, options...))
			}

			return nil
		},
	}

	showComps := carapace.Gen(showCmd)
	showComps.PositionalAnyCompletion(CompleteByID(con))

	aims.BindFlags(showCmd.Name(), false, showCmd, func(f *pflag.FlagSet) {
		f.BoolP("tasks", "t", false, "Show all agent tasks status/details")
	})

	scanCmd.AddCommand(showCmd)

	return scanCmd
}

// CompleteByID returns agent completions with their smallened IDs as keys.
func CompleteByID(client *client.Client) carapace.Action {
	return completers.CachedList(client, "agents:id", "agents:id", "no agents in database",
		func() ([]*pb.Agent, error) {
			res, err := client.Agents.Read(context.Background(), &c2.ReadAgentRequest{Agent: &pb.Agent{}})
			return res.GetAgents(), err
		},
		func(agents []*pb.Agent) carapace.Action {
			options := core.CompletionsAgent()
			options = append(options, display.WithCandidateValue("ID", ""))
			results := display.Completions(agents, core.DisplayFieldsAgent, options...)
			return carapace.ActionValuesDescribed(results...).Tag("agents ")
		},
	)
}
