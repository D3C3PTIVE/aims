package network

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
	"strconv"
	"strings"

	"github.com/fatih/color"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/d3c3ptive/aims/cmd/display"
	host "github.com/d3c3ptive/aims/host/pb"
	network "github.com/d3c3ptive/aims/network/pb"
	nmap "github.com/d3c3ptive/aims/scan/pb/nmap"
)

// Service - A service somewhere on a network.
// The type has several categories of fields: general information,
// and Nmap-compliant fields (fingerprints, protocols, banners, versions).
type Service network.Service

//
// General Functions
//

// ToORM - Get the SQL object for the Service.
func (s *Service) ToORM(ctx context.Context) (network.ServiceORM, error) {
	return (*network.Service)(s).ToORM(ctx)
}

// ToPB - Get the Protobuf object for the Service.
func (s *Service) ToPB() *network.Service {
	return (*network.Service)(s)
}

// TableHeaders returns all weighted table headers for a table of services/ports.
func Headers() (headers []display.Options) {
	add := func(n string, w int) {
		headers = append(headers, display.WithHeader(n, w))
	}

	// Weights are the responsive-drop priority (see cmd/display.adaptTableSize): weight-1 columns
	// are the always-kept floor, higher weights drop first on narrow terminals. Extra Info in
	// particular can be very wide (long mod_ssl banners), so it is the first to go — which is what
	// stops it forcing the whole row past the terminal width and triggering the "~~" truncation.
	add("Num", 1)
	add("Proto", 1) // Combined transport/application protocol when possible
	add("Product", 1)
	add("State", 1) // Combined or relevant port/service state

	add("Reason", 2)
	add("Method", 2)

	add("Extra Info", 3)

	return headers
}

// DetailHeaders returns the headers for a detailed service view.
func Details() []display.Options {
	var headers []display.Options
	add := func(n string, w int) {
		headers = append(headers, display.WithHeader(n, w))
	}

	// Core
	add("ID", 1)
	add("Num", 1)
	add("Proto", 1)
	add("Product", 1)
	add("Version", 1)

	add("State", 2)
	add("Reason", 2)
	add("Method", 2)

	// Network
	add("Device type", 2)
	add("Info", 3)
	add("Extra Info", 3)

	// Tools
	add("Scripts", 4)
	add("Fingerprint", 4)

	return headers
}

// Completions returns some columns to be combined into
// completion candidates and/or their descriptions.
func Completions() []display.Options {
	var headers []display.Options
	add := func(n string, w int) {
		headers = append(headers, display.WithHeader(n, w))
	}

	add("ID", 1)
	add("Num", 1)
	add("Proto", 1)
	add("Product", 1)
	add("State", 1)

	return headers
}

// DisplayFields maps field names to their value generators.
var DisplayFields = map[string]func(port *host.Port) string{
	// Table
	"ID": func(port *host.Port) string {
		id := display.FormatSmallID(port.Id)

		if port.State == nil {
			return id
		}

		switch port.State.State {
		case "open":
			return color.HiGreenString(id)
		case "filtered":
			return color.HiYellowString(id)
		case "closed":
			return color.HiRedString(id)
		}

		return id
	},
	"Num": func(port *host.Port) string {
		return strconv.Itoa(int(port.Number))
	},
	"Proto": func(port *host.Port) string {
		proto := color.HiBlackString(port.Protocol)

		if port.Service == nil {
			return proto
		} else {
			proto = ""
		}

		if port.Service.Protocol != "" {
			proto += port.Service.Protocol
		} else if port.Service.Name != "" {
			proto += port.Service.Name
		}

		return proto
	},
	"Product": func(port *host.Port) string {
		if port.Service == nil {
			return ""
		}
		product := port.Service.Product
		if port.Service.Version == "" {
			return product
		}
		product += color.HiBlackString(fmt.Sprintf(" (v%s)", port.Service.Version))
		return product
	},
	"Version": func(port *host.Port) string {
		serv := port.Service
		version := port.Service.Version
		if serv.HighVersion != "" && serv.LowVersion != "" {
			version += color.HiBlackString(" (%s / %s)", serv.LowVersion, serv.HighVersion)
		}
		return version
	},
	"Info": func(port *host.Port) string {
		if len(port.Scripts) == 0 {
			return port.Service.ExtraInfo
		}

		var scripts string
		for _, script := range port.Scripts {
			name := script.Name
			if script.Output == "" && script.Name == "" {
				continue
			}
			scripts += fmt.Sprintf("(%s) %s\n", name, script.Output)
		}

		return strings.TrimSuffix(scripts, "\n")
	},
	"Extra Info": func(port *host.Port) string {
		if port.Service == nil {
			return ""
		}
		return port.Service.ExtraInfo
	},
	"Fingerprint": func(port *host.Port) string {
		if port.Service == nil {
			return ""
		}
		return port.Service.ServiceFP
	},

	"Method": func(port *host.Port) string {
		if port.Service == nil {
			return ""
		}
		return color.HiBlackString(port.Service.Method)
	},
	"State": func(port *host.Port) string {
		if port.State == nil {
			return "unknown"
		}

		switch port.State.State {
		case "open":
			return color.HiGreenString("open")
		case "filtered":
			return color.HiYellowString("filtered")
		case "closed":
			return color.HiRedString("closed")
		}

		return port.State.State
	},
	"Reason": func(port *host.Port) string {
		if port.State == nil {
			return "undefined"
		}
		return port.State.Reason
	},
	"Scripts": func(port *host.Port) string {
		scripts := ""
		for _, script := range port.Scripts {
			scripts += printScript(script, 0)
		}

		return scripts
	},
}

//
// [ Detail View ] --------------------------------------------------------
//

// Banner renders the one-line header for a single service `info` view: "<host>:<num>/<proto>
// <app-proto>" on the left, then a state badge and script count on the right, followed by a rule.
// hostLabel is the owning host's display name (passed in, since a Port doesn't reference its host).
func Banner(port *host.Port, hostLabel string) string {
	title := ""
	if hostLabel != "" {
		title = hostLabel + display.Dim + ":" + display.Reset
	}
	title += display.Bold + strconv.Itoa(int(port.Number)) + display.Reset
	if port.Protocol != "" {
		title += display.Dim + "/" + port.Protocol + display.Reset
	}
	if name := appProto(port); name != "" {
		title += "  " + name
	}

	badges := []string{stateBadge(port)}
	if n := len(port.GetScripts()); n > 0 {
		badges = append(badges, color.HiBlueString("%d script(s)", n))
	}

	head := title + "   " + strings.Join(badges, display.Dim+" · "+display.Reset)
	rule := display.Dim + strings.Repeat("─", 66) + display.Reset
	return head + "\n" + rule
}

// InfoPanes groups a port's detail into titled panes (Service / State / Meta) for side-by-side
// layout via display.Columns, mirroring the credential info view.
func InfoPanes(port *host.Port) []display.Pane {
	svc := port.GetService()

	service := display.KVLines([][2]string{
		{"Port", strconv.Itoa(int(port.Number)) + "/" + port.Protocol},
		{"Name", svcField(svc, func(s *network.Service) string { return s.Name })},
		{"Product", svcField(svc, func(s *network.Service) string { return s.Product })},
		{"Version", svcField(svc, func(s *network.Service) string { return s.Version })},
		{"Extra", svcField(svc, func(s *network.Service) string { return s.ExtraInfo })},
	})

	st := port.GetState()
	state := display.KVLines([][2]string{
		{"State", stateText(port)},
		{"Reason", stateField(st, func(s *host.State) string { return s.Reason })},
		{"TTL", ttlLabel(st)},
		{"Method", svcField(svc, func(s *network.Service) string { return s.Method })},
	})

	meta := display.KVLines([][2]string{
		{"ID", display.FormatSmallID(port.Id)},
		{"Updated", fmtTime(port.GetUpdatedAt())},
	})

	// Drop panes with no content, so an empty section never prints a bare title.
	var panes []display.Pane
	for _, p := range []display.Pane{
		{Title: "Service", Lines: service},
		{Title: "State", Lines: state},
		{Title: "Meta", Lines: meta},
	} {
		if len(p.Lines) > 0 {
			panes = append(panes, p)
		}
	}
	return panes
}

// ScriptsBlock renders a port's NSE scripts as a titled block for the info view, or "" if none.
func ScriptsBlock(port *host.Port) string {
	if len(port.GetScripts()) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(display.Bold + "Scripts" + display.Reset)
	for _, script := range port.GetScripts() {
		b.WriteString(printScript(script, 1))
	}
	return b.String()
}

// Insights returns cross-cutting observations about a single port for the info view: a cleartext
// protocol warning, and a note when the port is filtered (no confirmed service).
func Insights(port *host.Port) (lines []string) {
	if st := port.GetState(); st != nil && st.State == "filtered" {
		lines = append(lines, color.HiYellowString("⚠")+" filtered — service not confirmed (no response)")
	}
	if p := cleartextProtocol(port); p != "" {
		lines = append(lines, color.HiYellowString("⚠")+fmt.Sprintf(" %s is a cleartext protocol — credentials may be sniffable", p))
	}
	return lines
}

//
// [ Detail Formatters ] --------------------------------------------------
//

// appProto returns the application-layer protocol/name of a port's service (e.g. http, ssh).
func appProto(port *host.Port) string {
	svc := port.GetService()
	if svc == nil {
		return ""
	}
	if svc.Protocol != "" {
		return svc.Protocol
	}
	return svc.Name
}

// stateText returns the port state coloured by openness (reuses the table field generator).
func stateText(port *host.Port) string {
	return DisplayFields["State"](port)
}

// stateBadge is the state as a coloured "● <state>" badge for the banner.
func stateBadge(port *host.Port) string {
	st := port.GetState()
	if st == nil {
		return color.HiBlackString("● unknown")
	}
	switch st.State {
	case "open":
		return color.HiGreenString("● open")
	case "filtered":
		return color.HiYellowString("● filtered")
	case "closed":
		return color.HiRedString("● closed")
	default:
		return color.HiBlackString("● " + st.State)
	}
}

// svcField safely extracts a string field from a possibly-nil Service.
func svcField(s *network.Service, get func(*network.Service) string) string {
	if s == nil {
		return ""
	}
	return get(s)
}

// stateField safely extracts a string field from a possibly-nil State.
func stateField(s *host.State, get func(*host.State) string) string {
	if s == nil {
		return ""
	}
	return get(s)
}

// ttlLabel renders the reason TTL of a port state, or "" when unset.
func ttlLabel(s *host.State) string {
	if s == nil || s.ReasonTTL == 0 {
		return ""
	}
	return strconv.Itoa(int(s.ReasonTTL))
}

// cleartextProtocol returns the well-known cleartext protocol name of a port (by app-proto or
// number), or "" if the port isn't a recognised cleartext service.
func cleartextProtocol(port *host.Port) string {
	name := strings.ToLower(appProto(port))
	switch name {
	case "ftp", "telnet", "http", "smtp", "pop3", "imap", "snmp":
		return name
	}
	switch port.Number {
	case 21:
		return "ftp"
	case 23:
		return "telnet"
	case 25:
		return "smtp"
	case 80:
		return "http"
	case 110:
		return "pop3"
	case 143:
		return "imap"
	}
	return ""
}

func fmtTime(t *timestamppb.Timestamp) string {
	if t == nil {
		return ""
	}
	tt := t.AsTime()
	if tt.IsZero() {
		return ""
	}
	return tt.Format("2006-01-02 15:04")
}

// Recursive function to print a ScriptORM object with nested structures
func printScript(script *nmap.Script, indentLevel int) string {
	buf := new(strings.Builder)
	indent := strings.Repeat("  ", indentLevel)

	name := script.Name
	if name == "" {
		name = script.Id
	}
	fmt.Fprintf(buf, "\n%sName: %s\n", indent, color.HiBlueString(name))
	if script.Output != "" {
		fmt.Fprintf(buf, "%sOutput: %s\n", indent, script.Output)
	}

	// Print Elements
	if len(script.Elements) > 0 {
		fmt.Fprintf(buf, "%sElements:\n", indent)
		for _, element := range script.Elements {
			fmt.Fprintf(buf, "%s %s : %s\n", indent, element.Key, element.Value)
		}
	}

	// Print Tables and their rows
	if len(script.Tables) > 0 {
		fmt.Printf("%sTables:\n", indent)
		for _, table := range script.Tables {
			printTable(table, indentLevel+1, buf)
		}
	}

	return buf.String()
}

// Recursive function to print a TableORM object with nested rows
func printTable(table *nmap.Table, indentLevel int, buf *strings.Builder) {
	indent := strings.Repeat("  ", indentLevel)
	fmt.Fprintf(buf, "%s %s\n", indent, table.Key)

	// Print rows
	if len(table.Elements) > 0 {
		for _, element := range table.Elements {
			fmt.Fprintf(buf, "%s %s : %s\n", indent, element.Key, element.Value)
		}
	}

	if len(table.Tables) > 0 {
		printTable(table, indentLevel+1, buf)
	}
}
