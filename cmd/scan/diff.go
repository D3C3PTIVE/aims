package scan

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
	"fmt"
	"strings"

	"github.com/carapace-sh/carapace"
	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/d3c3ptive/aims/client"
	aims "github.com/d3c3ptive/aims/cmd"
	"github.com/d3c3ptive/aims/cmd/display"
	host "github.com/d3c3ptive/aims/host/pb"
	"github.com/d3c3ptive/aims/scan"
	pb "github.com/d3c3ptive/aims/scan/pb"
	scans "github.com/d3c3ptive/aims/scan/pb/rpc"
)

// diffCommand wires `aims scan diff <id-a> <id-b>`: the run-to-run drift view (SCAN.md Part C,
// capability 2). Both runs are read through the teamclient (hosts+ports preloaded), resolved by
// ID prefix like `show`/`rm`, then compared by scan.DiffRuns (which reuses the host identity
// primitives so the diff agrees with the ingest fold). Output is a colored +/-/~ tree.
func diffCommand(con *client.Client) *cobra.Command {
	diffCmd := &cobra.Command{
		Use:   "diff <id-a> <id-b>",
		Short: "Show what changed between two scans (attack-surface drift)",
		Long: "Compare two stored scans and report the drift between them: hosts that appeared or\n" +
			"disappeared, ports that opened or closed, and services whose version changed.\n\n" +
			"    aims scan diff <earlier-id> <later-id>",
		Args: cobra.ExactArgs(2),
		RunE: func(command *cobra.Command, args []string) error {
			res, err := con.Scans.Read(command.Context(), &scans.ReadScanRequest{
				Scan: &pb.Run{},
				Filters: &scans.RunFilters{
					Hosts: true,
					Ports: true,
				},
			})
			if err = aims.CheckError(err); err != nil {
				return err
			}

			all := res.GetScans()
			a := findRunByPrefix(all, args[0])
			if a == nil {
				return fmt.Errorf("no scan matching %q", args[0])
			}
			b := findRunByPrefix(all, args[1])
			if b == nil {
				return fmt.Errorf("no scan matching %q", args[1])
			}

			renderDiff(a, b, scan.DiffRuns(a, b))
			return nil
		},
	}

	carapace.Gen(diffCmd).PositionalCompletion(CompleteByID(con), CompleteByID(con))

	return diffCmd
}

func findRunByPrefix(runs []*pb.Run, arg string) *pb.Run {
	id := aims.StripANSI(arg)
	for _, r := range runs {
		if strings.HasPrefix(r.GetId(), id) {
			return r
		}
	}
	return nil
}

// renderDiff prints the delta as a colored tree: green + for what appeared, red - for what
// disappeared, yellow ~ for what changed in place (with the before → after service string).
func renderDiff(a, b *pb.Run, d *scan.RunDiff) {
	fmt.Printf("%s %s  →  %s %s\n",
		a.GetScanner(), display.FormatSmallID(a.GetId()),
		b.GetScanner(), display.FormatSmallID(b.GetId()))

	if d.Empty() {
		fmt.Println(color.HiBlackString("no changes"))
		return
	}

	for _, h := range d.NewHosts {
		fmt.Println(color.HiGreenString("+ host %s", hostLabel(h)))
		for _, p := range h.Ports {
			fmt.Println(color.HiGreenString("    + %s", portLabel(p)))
		}
	}
	for _, h := range d.GoneHosts {
		fmt.Println(color.HiRedString("- host %s", hostLabel(h)))
	}
	for _, hd := range d.Changed {
		fmt.Println(color.HiYellowString("~ host %s", hostLabel(hd.After)))
		for _, p := range hd.NewPorts {
			fmt.Println(color.HiGreenString("    + %s", portLabel(p)))
		}
		for _, p := range hd.GonePorts {
			fmt.Println(color.HiRedString("    - %s", portLabel(p)))
		}
		for _, pd := range hd.Changed {
			fmt.Println(color.HiYellowString("    ~ %s  %s → %s",
				portLabel(pd.After), svcLabel(pd.Before), svcLabel(pd.After)))
		}
	}
}

func hostLabel(h *host.Host) string {
	if len(h.Addresses) > 0 && h.Addresses[0].Addr != "" {
		return h.Addresses[0].Addr
	}
	if len(h.Hostnames) > 0 && h.Hostnames[0].Name != "" {
		return h.Hostnames[0].Name
	}
	return display.FormatSmallID(h.Id)
}

func portLabel(p *host.Port) string {
	name := ""
	if p.Service != nil && p.Service.Name != "" {
		name = " (" + p.Service.Name + ")"
	}
	return fmt.Sprintf("%d/%s%s", p.Number, p.Protocol, name)
}

func svcLabel(p *host.Port) string {
	if p == nil || p.Service == nil {
		return "?"
	}
	parts := make([]string, 0, 3)
	for _, v := range []string{p.Service.Name, p.Service.Product, p.Service.Version} {
		if v != "" {
			parts = append(parts, v)
		}
	}
	if len(parts) == 0 {
		return "?"
	}
	return strings.Join(parts, " ")
}
