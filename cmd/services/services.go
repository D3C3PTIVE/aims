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

	"github.com/carapace-sh/carapace"
	"github.com/carapace-sh/carapace/pkg/style"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/d3c3ptive/aims/client"
	aims "github.com/d3c3ptive/aims/cmd"
	"github.com/d3c3ptive/aims/cmd/agentctx"
	"github.com/d3c3ptive/aims/cmd/completers"
	"github.com/d3c3ptive/aims/cmd/display"
	"github.com/d3c3ptive/aims/cmd/export"
	hostdomain "github.com/d3c3ptive/aims/host"
	pb "github.com/d3c3ptive/aims/host/pb"
	hosts "github.com/d3c3ptive/aims/host/pb/rpc"
	"github.com/d3c3ptive/aims/network"
	netpb "github.com/d3c3ptive/aims/network/pb"
	netrpc "github.com/d3c3ptive/aims/network/pb/rpc"
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
	cmd := &cobra.Command{
		Use:   "list",
		Short: "Display services grouped by host",
		RunE: func(command *cobra.Command, args []string) error {
			hostList, err := readHosts(con, command)
			if err != nil {
				return err
			}

			name, _ := command.Flags().GetString("name")
			rows := filterByName(groupedRows(hostList), name)
			if len(rows) == 0 {
				fmt.Println("No services in database.")
				return nil
			}

			table := display.Table(rows, groupedFields(), groupedHeaders()...)
			fmt.Println(table.Render())

			return nil
		},
	}

	// --name narrows the listing to one service by name (or, for the unnamed ones, by ID prefix).
	// Its completion is the host-scoped, prefix-filtered service list: the candidates are real
	// service names read from the services table, not port UUIDs.
	aims.BindFlags("filters", false, cmd, func(f *pflag.FlagSet) {
		f.StringP("name", "n", "", "Only show services with this name (or ID prefix)")
	})
	aims.CompleteFlags(cmd, func(comp *carapace.ActionMap) {
		(*comp)["name"] = CompleteByName(con)
	})

	return cmd
}

// filterByName narrows grouped rows to the services whose name matches, or — for the services with
// no name, which the completer offers by their short ID — whose service or port ID has it as a
// prefix. An empty name is a no-op, matching the server-side filters' "empty means everything" rule.
func filterByName(rows []svcRow, name string) []svcRow {
	if name == "" {
		return rows
	}
	var out []svcRow
	for _, r := range rows {
		svc := r.port.GetService()
		switch {
		case svc.GetName() != "" && strings.EqualFold(svc.GetName(), name):
		case svc.GetName() == "" && aims.MatchesAnyPrefix(svc.GetId(), []string{name}):
		case aims.MatchesAnyPrefix(r.port.GetId(), []string{name}):
		default:
			continue
		}
		out = append(out, r)
	}
	return out
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
				hostMatch := aims.MatchesAnyPrefix(h.GetId(), args)
				for _, p := range h.GetPorts() {
					if hostMatch || aims.MatchesAnyPrefix(p.GetId(), args) {
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
	fmt.Println(network.Detail(p, hostLabel(h)).Render(0))
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
	}, network.DisplayHeaders()...)
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
	case hostdomain.PortOpen:
		return color.HiGreenString(n)
	case hostdomain.PortFiltered:
		return color.HiYellowString(n)
	case hostdomain.PortClosed:
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
	read := func() ([]svcRow, error) {
		res, err := con.Hosts.Read(context.Background(), &hosts.ReadHostRequest{
			Host:    &pb.Host{},
			Filters: &hosts.HostFilters{Ports: true},
		})
		if err != nil {
			return nil, err
		}
		var rows []svcRow
		for _, h := range res.GetHosts() {
			for _, p := range h.GetPorts() {
				rows = append(rows, svcRow{host: h, port: p})
			}
		}
		return rows, nil
	}

	render := func(rows []svcRow) carapace.Action {
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
			case hostdomain.PortOpen:
				return style.Green
			case hostdomain.PortFiltered:
				return style.Yellow
			default:
				return style.Dim
			}
		}

		results := display.CompletionsStyled(rows, fields, styleOf, opts...)

		return carapace.ActionStyledValuesDescribed(results...).Tag("services (by id)")
	}

	return completers.CachedList(con, "services:id", "services:id", "no services in database", read, render)
}

// CompleteByName completes services by a real service attribute — their name (falling back to the
// short ID for the unnamed ones) — described by product/version/protocol. Unlike CompleteByID, which
// walks hosts and inserts port UUIDs, this reads the services table directly, so the typed word can
// be pushed down to the server as a prefix filter (ReadServiceRequest.Prefix) and a Tab against a
// large store transfers only the candidate rows instead of every host with its ports.
//
// When an agent context is loaded, the read is additionally scoped to that agent's host
// (ReadServiceRequest.Host) — by far the biggest result-set reducer available here, and the right
// default: the services worth completing while operating from a host are that host's. The candidates
// are tagged accordingly so the heading says which set is on screen; with no context loaded it falls
// back to every service in the database.
func CompleteByName(con *client.Client) carapace.Action {
	// Resolving the agent host costs two RPCs, so it is done once outside the per-prefix read.
	agentHost, scoped := agentctx.CurrentHost(con)

	read := func(prefix string) ([]*netpb.Service, error) {
		req := &netrpc.ReadServiceRequest{Service: &netpb.Service{}, Prefix: prefix}
		if scoped {
			req.Host = agentHost
		}
		res, err := con.Services.List(context.Background(), req)
		return res.GetServices(), err
	}

	tag := "services (by name)"
	if scoped {
		tag = "services on " + hostLabel(agentHost)
	}

	render := func(svcs []*netpb.Service) carapace.Action {
		opts := []display.Options{
			display.WithHeader("Name", 1),
			display.WithHeader("Product", 1),
			display.WithHeader("Version", 2),
			display.WithHeader("Proto", 2),
			// The candidate is the service name; the unnamed services fall back to their short ID,
			// which is why the server-side prefix filter carries an id leg too — without it the
			// pushdown would drop candidates the id fallback would otherwise have shown.
			display.WithCandidateValue("Name", "ID"),
		}

		results := display.Completions(svcs, serviceNameFields, opts...)

		return carapace.ActionValuesDescribed(results...).Tag(tag)
	}

	// The cache name carries the scope so a context switch is a distinct entry rather than a stale
	// hit from the unscoped set (cachedCompleter does the same for the agent-scoped completers).
	name := "services:name"
	if scoped {
		name += ":" + agentHost.GetId()
	}

	return completers.CachedListByPrefix(con, name, "services:name", "no services in database", read, render)
}

// serviceNameFields are the value-generators for the service-name completion candidates. They are
// spelled here rather than reused from network.DisplayFields because that map is keyed on *host.Port
// (the port carries the display identity of a service in the table views), whereas this completer
// reads the services table directly and so holds a *netpb.Service.
var serviceNameFields = map[string]func(*netpb.Service) string{
	"ID":      func(s *netpb.Service) string { return display.FormatSmallID(s.GetId()) },
	"Name":    func(s *netpb.Service) string { return s.GetName() },
	"Product": func(s *netpb.Service) string { return s.GetProduct() },
	"Version": func(s *netpb.Service) string { return s.GetVersion() },
	"Proto":   func(s *netpb.Service) string { return s.GetProtocol() },
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

func exportCommand(con *client.Client) func(cmd *cobra.Command, args []string) any {
	return func(command *cobra.Command, args []string) (data any) {
		hostList, err := readHosts(con, command)
		if err != nil {
			return err
		}

		var services []*pb.Port
		for _, h := range hostList {
			if len(args) > 0 && !aims.MatchesAnyPrefix(h.GetId(), args) {
				continue
			}
			services = append(services, h.GetPorts()...)
		}

		return services
	}
}
