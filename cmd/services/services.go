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
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/fatih/color"
	"github.com/rsteube/carapace"
	"github.com/rsteube/carapace/pkg/style"
	"github.com/spf13/cobra"

	"github.com/d3c3ptive/aims/client"
	aims "github.com/d3c3ptive/aims/cmd"
	"github.com/d3c3ptive/aims/cmd/display"
	"github.com/d3c3ptive/aims/cmd/export"
	pb "github.com/d3c3ptive/aims/host/pb"
	hosts "github.com/d3c3ptive/aims/host/pb/rpc"
	"github.com/d3c3ptive/aims/network"
)

// Commands returns a command tree to manage and display services.
func Commands(con *client.Client) *cobra.Command {
	servicesCmd := &cobra.Command{
		Use:     "services",
		Short:   "Manage database services",
		GroupID: "database",
	}

	servicesCmd.AddCommand(listCommand(con))
	servicesCmd.AddCommand(showCommand(con))
	servicesCmd.AddCommand(rmCommand(con))
	servicesCmd.AddCommand(export.ExportCommand(servicesCmd, con, exportCommand(con)))

	return servicesCmd
}

// listCommand renders every service grouped by host: one flat, responsive table in which each
// host's identity (name + short ID) is printed once on its first port row and blanked on the
// continuation rows — grouping that costs zero extra header or blank lines.
func listCommand(con *client.Client) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "Display services grouped by host",
		RunE: func(command *cobra.Command, args []string) error {
			hostList, err := readHosts(con, command)
			if err != nil {
				return err
			}

			rows := groupedRows(hostList)
			if len(rows) == 0 {
				fmt.Println("No services in database.")
				return nil
			}

			table := display.Table(rows, groupedFields(), groupedHeaders()...)
			fmt.Println(table.Render())

			return nil
		},
	}
}

// showCommand renders one or more services in detail, resolved by host-ID prefix (all of a host's
// services) or by service-ID prefix (a single service). Each is a Banner + side-by-side info panes
// + derived insights + its NSE scripts.
func showCommand(con *client.Client) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "show",
		Aliases: []string{"info"},
		Short:   "Show one or more services in detail",
		RunE: func(command *cobra.Command, args []string) error {
			if len(args) == 0 {
				return errors.New("provide one or more host or service ID prefixes")
			}

			hostList, err := readHosts(con, command)
			if err != nil {
				return err
			}

			shown := 0
			for _, h := range hostList {
				hostMatch := matchesAny(h.GetId(), args)
				for _, p := range h.GetPorts() {
					if hostMatch || matchesAny(p.GetId(), args) {
						printService(h, p)
						shown++
					}
				}
			}
			if shown == 0 {
				return errors.New("no matching service")
			}

			return nil
		},
	}

	carapace.Gen(cmd).PositionalAnyCompletion(CompleteByID(con))

	return cmd
}

// rmCommand is a placeholder: service deletion is scoped by host ingest and not yet wired.
func rmCommand(con *client.Client) *cobra.Command {
	return &cobra.Command{
		Use:   "rm",
		Short: "Remove one or more services from the database",
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("service removal is not implemented yet")
		},
	}
}

// printService renders a single service's full detail view.
func printService(h *pb.Host, p *pb.Port) {
	fmt.Println(network.Banner(p, hostLabel(h)))
	fmt.Println(display.Columns(0, 4, network.InfoPanes(p)...))

	if ins := network.Insights(p); len(ins) > 0 {
		fmt.Println()
		fmt.Println(display.Bold + "Insights" + display.Reset)
		for _, l := range ins {
			fmt.Println("  " + l)
		}
	}

	if sb := network.ScriptsBlock(p); sb != "" {
		fmt.Println()
		fmt.Println(sb)
	}

	fmt.Println()
}

//
// [ Grouped list rendering ] ---------------------------------------------
//

// svcRow pairs a port with its owning host for the grouped table. firstOfHost marks the first row
// of each host group, on which alone the host identity columns are populated.
type svcRow struct {
	host        *pb.Host
	port        *pb.Port
	firstOfHost bool
}

// groupedRows flattens hosts→ports into grouped rows: ports sorted by number within each host, the
// first row of each host flagged so its identity prints once.
func groupedRows(hostList []*pb.Host) (rows []svcRow) {
	for _, h := range hostList {
		ports := h.GetPorts()
		if len(ports) == 0 {
			continue
		}
		sort.SliceStable(ports, func(i, j int) bool { return ports[i].Number < ports[j].Number })
		for i, p := range ports {
			rows = append(rows, svcRow{host: h, port: p, firstOfHost: i == 0})
		}
	}
	return rows
}

// groupedHeaders are the grouped-list columns: the two host-identity columns, then the port
// columns (with their responsive weights) from the network domain.
func groupedHeaders() []display.Options {
	return append([]display.Options{
		display.WithHeader("Host", 1),
		display.WithHeader("ID", 1),
	}, network.Headers()...)
}

// groupedFields wraps the port-level network.DisplayFields so they apply to an svcRow, and adds the
// host-identity columns (blanked on continuation rows) plus a state-coloured port number.
func groupedFields() map[string]func(svcRow) string {
	fields := map[string]func(svcRow) string{
		"Host": func(r svcRow) string {
			if r.firstOfHost {
				return hostLabel(r.host)
			}
			return ""
		},
		"ID": func(r svcRow) string {
			if r.firstOfHost {
				return color.HiBlackString(display.FormatSmallID(r.host.GetId()))
			}
			return ""
		},
		"Num": func(r svcRow) string { return numColored(r.port) },
	}

	for name, fn := range network.DisplayFields {
		if name == "ID" || name == "Num" { // host ID and coloured Num are overridden above
			continue
		}
		fn := fn
		fields[name] = func(r svcRow) string { return fn(r.port) }
	}

	return fields
}

// numColored renders a port number coloured by its state (open green / filtered yellow / closed
// red), so the list carries the state signal even when the State column is dropped on narrow terms.
func numColored(port *pb.Port) string {
	n := strconv.Itoa(int(port.Number))
	if port.State == nil {
		return n
	}
	switch port.State.State {
	case "open":
		return color.HiGreenString(n)
	case "filtered":
		return color.HiYellowString(n)
	case "closed":
		return color.HiRedString(n)
	}
	return n
}

//
// [ Completions ] --------------------------------------------------------
//

// CompleteByID completes services by their (short) ID, described by host / number / proto /
// product / state, and colours each candidate by port state (open green, filtered yellow, else dim).
func CompleteByID(con *client.Client) carapace.Action {
	return carapace.ActionCallback(func(_ carapace.Context) carapace.Action {
		if msg, err := con.ConnectComplete(); err != nil {
			return msg
		}

		res, err := con.Hosts.Read(context.Background(), &hosts.ReadHostRequest{
			Host:    &pb.Host{},
			Filters: &hosts.HostFilters{Ports: true},
		})
		if err = aims.CheckError(err); err != nil {
			return carapace.ActionMessage("Error: %s", err)
		}

		var rows []svcRow
		for _, h := range res.GetHosts() {
			for _, p := range h.GetPorts() {
				rows = append(rows, svcRow{host: h, port: p})
			}
		}
		if len(rows) == 0 {
			return carapace.ActionMessage("no services in database")
		}

		fields := map[string]func(svcRow) string{
			"ID":   func(r svcRow) string { return display.FormatSmallID(r.port.GetId()) },
			"Host": func(r svcRow) string { return hostLabel(r.host) },
			"Num":  func(r svcRow) string { return strconv.Itoa(int(r.port.Number)) },
		}
		for name, fn := range network.DisplayFields {
			if name == "ID" || name == "Num" {
				continue
			}
			fn := fn
			fields[name] = func(r svcRow) string { return fn(r.port) }
		}

		opts := []display.Options{
			display.WithHeader("ID", 1),
			display.WithHeader("Host", 1),
			display.WithHeader("Num", 1),
			display.WithHeader("Proto", 1),
			display.WithHeader("Product", 2),
			display.WithHeader("State", 2),
			display.WithCandidateValue("ID", ""),
		}

		styleOf := func(r svcRow) string {
			if r.port.State == nil {
				return style.Dim
			}
			switch r.port.State.State {
			case "open":
				return style.Green
			case "filtered":
				return style.Yellow
			default:
				return style.Dim
			}
		}

		results := display.CompletionsStyled(rows, fields, styleOf, opts...)

		return carapace.ActionStyledValuesDescribed(results...).Tag("services (by id)")
	})
}

//
// [ Helpers ] ------------------------------------------------------------
//

// readHosts fetches every host with its ports.
func readHosts(con *client.Client, command *cobra.Command) ([]*pb.Host, error) {
	res, err := con.Hosts.Read(command.Context(), &hosts.ReadHostRequest{
		Host:    &pb.Host{},
		Filters: &hosts.HostFilters{Ports: true},
	})
	if err = aims.CheckError(err); err != nil {
		return nil, err
	}
	return res.GetHosts(), nil
}

// hostLabel is the human name for a host: first hostname, else first address, else its short ID.
func hostLabel(h *pb.Host) string {
	for _, hn := range h.GetHostnames() {
		if hn.GetName() != "" {
			return hn.GetName()
		}
	}
	for _, a := range h.GetAddresses() {
		if a.GetAddr() != "" {
			return a.GetAddr()
		}
	}
	return display.FormatSmallID(h.GetId())
}

// matchesAny reports whether id has any of the (ANSI-stripped) prefixes.
func matchesAny(id string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(id, strip(p)) {
			return true
		}
	}
	return false
}

func exportCommand(con *client.Client) func(cmd *cobra.Command, args []string) any {
	return func(command *cobra.Command, args []string) (data any) {
		hostList, err := readHosts(con, command)
		if err != nil {
			return err
		}

		var services []*pb.Port
		for _, h := range hostList {
			if len(args) > 0 && !matchesAny(h.GetId(), args) {
				continue
			}
			services = append(services, h.GetPorts()...)
		}

		return services
	}
}

// strip removes all ANSI escaped color sequences in a string.
func strip(str string) string {
	return display.StripANSI(str)
}
