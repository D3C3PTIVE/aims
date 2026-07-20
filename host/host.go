package host

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
	"regexp"
	"sort"
	"strings"

	"github.com/fatih/color"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/d3c3ptive/aims/cmd/display"
	"github.com/d3c3ptive/aims/host/pb"
	"github.com/d3c3ptive/aims/provenance"
)

// Host - A physical or virtual computer host.
// The type has several categories of fields: general information,
// and Nmap-compliant fields (ports, status, route, scripts etc).
type Host pb.Host

//
// [ Display Functions ] --------------------------------------------------
//

// DisplayHeaders returns all weighted table headers for a table of hosts.
func DisplayHeaders() []display.Options {
	return display.Headers().
		Add("ID", 1).
		Add("Hostnames", 1).
		Add("OS Name", 1).
		Add("OS Family", 1).
		Add("Addresses", 1).
		Add("Status", 2).
		Add("Hops", 2).
		Add("Arch", 3).
		Add("MAC", 3).
		Add("Purpose", 3).
		Options()
}

// DetailHeaders returns the headers for a detailed host view.
func DisplayDetails() []display.Options {
	return display.Headers().
		// Core
		Add("ID", 1).
		Add("OS Name", 1).
		Add("OS Family", 1).
		Add("Arch", 1).
		Add("Status", 1).
		// Network
		Add("Hostnames", 2).
		Add("Addresses", 2).
		Add("Hops", 2).
		// Hardware
		Add("Extra Ports", 3).
		Add("Purpose", 3).
		Add("MAC", 3).
		Add("Virtual Host", 3).
		// Tools
		Add("Comment", 4).
		Add("Scripts", 4).
		Add("Sources", 4).
		Options()
}

// Completions returns some columns to be combined into
// completion candidates and/or their descriptions.
func Completions() []display.Options {
	return display.Headers().
		Add("ID", 1).
		Add("Hostnames", 1).
		Add("OS Name", 1).
		Add("Addresses", 1).
		Options()
}

// Fields maps field names to their value generators.
var DisplayFields = map[string]func(h *pb.Host) string{
	// Table
	"ID": func(h *pb.Host) string {
		if h.Status.State == "up" {
			return color.HiGreenString(display.FormatSmallID(h.Id))
		}
		return display.FormatSmallID(h.Id)
	},
	"Hostnames": func(h *pb.Host) string {
		var hostnames []string
		for _, hn := range h.Hostnames {
			hostnames = append(hostnames, hn.Name)
		}
		return strings.Join(hostnames, "\n")
	},
	"OS Name": func(h *pb.Host) string {
		osName, _ := GetOperatingSystem(h)
		return osName
	},
	"OS Family": func(h *pb.Host) string {
		_, fam := GetOperatingSystem(h)
		return fam
	},
	"Addresses": func(h *pb.Host) string {
		var addresses []string
		for _, hn := range h.Addresses {
			addresses = append(addresses, hn.Addr)
		}
		return strings.Join(addresses, "\n")
	},
	"Status": func(h *pb.Host) string {
		if h.Status == nil {
			return ""
		}
		switch h.Status.State {
		case "up":
			return color.HiGreenString(h.Status.State)
		case "down":
			return color.HiRedString(h.Status.State)
		default:
			return h.Status.State
		}
	},
	"Hops": func(h *pb.Host) string {
		if h.Trace == nil {
			return ""
		}

		return fmt.Sprint(len(h.Trace.Hops))
	},
	"Extra Ports": func(h *pb.Host) string {
		ports := ""
		for _, port := range h.ExtraPorts {
			ports += printExtraPorts(port, 1)
		}

		return ports
	},
	"Arch": getProbableCPU,
	"MAC":  func(h *pb.Host) string { return h.MAC },
	"Purpose": func(h *pb.Host) string {
		if h.OS == nil {
			return ""
		}
		// Look at OS matches for various types.
		// Don't include them all, just 2/3 more recurring ones.
		if h.Purpose != "" {
			return h.Purpose
		}

		times := map[string]int{}

		for _, m := range h.OS.Matches {
			for _, c := range m.Classes {
				if c.Type != "" {
					times[c.Type]++
				}
			}
		}

		var purposes []string
		for name, times := range times {
			typeStr := name + display.Dim + fmt.Sprintf("(%d)", times)
			purposes = append(purposes, typeStr)
		}

		return strings.Join(purposes, " | ")
	},

	// Details
	"Route": func(h *pb.Host) string {
		if h.Trace == nil {
			return ""
		}

		routes := "\n" + display.Reset

		for i := len(h.Trace.Hops) - 1; i >= 0; i-- {
			hop := h.Trace.Hops[i]
			line := display.Dim + "  |_ "
			rtt := display.Dim + fmt.Sprintf("%*s", 6, hop.RTT) + display.Reset
			ipPad := fmt.Sprintf("%*s  ", 18, hop.IPAddr)
			line += rtt + ipPad + display.Bold + display.FgYellow + hop.Host + display.Reset
			routes += line + "\n"
		}

		return strings.TrimSuffix(routes, "\n")
	},
	"Scripts": func(h *pb.Host) string {
		return ""
	},
	"Sources": func(h *pb.Host) string {
		return provenance.Tools(h.GetSources())
	},
	"Virtual Host": func(h *pb.Host) string {
		return h.VirtualHost
	},
	"Comment": func(h *pb.Host) string {
		return h.Comment
	},
}

//
// [ Detail View ] --------------------------------------------------------
//

// Detail assembles the full `info` view for a single host: the identity banner, the side-by-side
// info panes, the derived insights, and any trailing sections (open ports, extra ports, comment
// and — when showRoute is set — the full traceroute). It hands these to the shared display.Detail
// renderer, so a host's detail view is laid out identically to every other domain's. showRoute
// mirrors the `hosts show --traceroute` flag: the route can be long, so it prints only on request.
func Detail(h *pb.Host, showRoute bool) display.Detail {
	return display.Detail{
		Title:    bannerTitle(h),
		Badges:   bannerBadges(h),
		Panes:    InfoPanes(h),
		Insights: Insights(h),
		Sections: sections(h, showRoute),
	}
}

// bannerTitle is the host identity shown in the banner: its display name (hostname, else address,
// else short id) in bold, followed by the guessed OS when known.
func bannerTitle(h *pb.Host) string {
	title := display.Bold + hostLabel(h) + display.Reset
	if os, _ := GetOperatingSystem(h); os != "" {
		title += "  " + os
	}
	return title
}

// bannerBadges are the host's status badges (liveness + open-port count) for the banner.
func bannerBadges(h *pb.Host) (badges []string) {
	badges = append(badges, statusBadge(h))
	if open := openPorts(h); len(open) > 0 {
		badges = append(badges, color.HiGreenString("%d open", len(open)))
	}
	return badges
}

// InfoPanes groups a host's detail into titled panes (System / Network / Status) for side-by-side
// layout via display.Columns, mirroring the credential and service info views. Empty panes are
// dropped, so a host with no OS/network data never prints a bare title.
func InfoPanes(h *pb.Host) []display.Pane {
	system := display.KVLines([][2]string{
		{"OS Name", DisplayFields["OS Name"](h)},
		{"OS Family", DisplayFields["OS Family"](h)},
		{"Arch", DisplayFields["Arch"](h)},
		{"Purpose", DisplayFields["Purpose"](h)},
	})

	network := display.KVLines([][2]string{
		{"Hostnames", joinNames(h)},
		{"Addresses", joinAddrs(h)},
		{"MAC", h.GetMAC()},
		{"Hops", DisplayFields["Hops"](h)},
	})

	status := display.KVLines([][2]string{
		{"State", DisplayFields["Status"](h)},
		{"Reason", h.GetStatus().GetReason()},
		{"Uptime", uptimeLabel(h)},
		{"ID", display.FormatSmallID(h.GetId())},
		{"Updated", fmtTime(h.GetUpdatedAt())},
	})

	var panes []display.Pane
	for _, p := range []display.Pane{
		{Title: "System", Lines: system},
		{Title: "Network", Lines: network},
		{Title: "Status", Lines: status},
	} {
		if len(p.Lines) > 0 {
			panes = append(panes, p)
		}
	}
	return panes
}

// Insights returns cross-cutting observations about a single host for the info view: a
// down/stale warning, exposed cleartext services, a large-attack-surface note, and a flag when the
// OS is only an nmap guess.
func Insights(h *pb.Host) (lines []string) {
	if st := h.GetStatus(); st != nil && st.State == "down" {
		lines = append(lines, color.HiYellowString("⚠")+" host last reported down — data may be stale")
	}
	if ct := cleartextServices(h); len(ct) > 0 {
		lines = append(lines, color.HiYellowString("⚠")+" cleartext service(s) exposed: "+strings.Join(ct, ", "))
	}
	if open := openPorts(h); len(open) >= 10 {
		lines = append(lines, fmt.Sprintf("large attack surface — %d open ports", len(open)))
	}
	if pct, guessed := osConfidence(h); guessed {
		lines = append(lines, fmt.Sprintf("OS is an nmap guess (best match %d%%)", pct))
	}
	return lines
}

// sections builds the trailing blocks of a host's detail view: its open ports, the full route
// (only when showRoute is set — it can be long), any nmap extra-port summary, and a free-text
// comment. Blank bodies are skipped by the renderer, so a section only prints when it has content.
func sections(h *pb.Host, showRoute bool) (out []display.Section) {
	if body := portsBody(h); body != "" {
		out = append(out, display.Section{Title: "Open Ports", Body: body})
	}
	if showRoute {
		if body := strings.TrimSpace(DisplayFields["Route"](h)); body != "" {
			out = append(out, display.Section{Title: "Route", Body: body})
		}
	}
	if body := strings.TrimSpace(DisplayFields["Extra Ports"](h)); body != "" {
		out = append(out, display.Section{Title: "Extra Ports", Body: body})
	}
	if c := strings.TrimSpace(h.GetComment()); c != "" {
		out = append(out, display.Section{Title: "Comment", Body: c})
	}
	return out
}

//
// [ Detail Formatters ] --------------------------------------------------
//

// hostLabel is the host's best display name: its first hostname, else its first address, else its
// shortened id. Mirrors cmd/services.hostLabel so a host reads the same wherever it is named.
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

// statusBadge renders the host liveness as a coloured "● <state>" badge for the banner.
func statusBadge(h *pb.Host) string {
	st := h.GetStatus()
	if st == nil {
		return color.HiBlackString("● unknown")
	}
	switch st.State {
	case "up":
		return color.HiGreenString("● up")
	case "down":
		return color.HiRedString("● down")
	default:
		return color.HiBlackString("● " + st.State)
	}
}

// openPorts returns the host's ports in the "open" state — the ones an attacker acts on.
func openPorts(h *pb.Host) (open []*pb.Port) {
	for _, p := range h.GetPorts() {
		if st := p.GetState(); st != nil && st.State == "open" {
			open = append(open, p)
		}
	}
	return open
}

// portsBody lists the host's open ports, sorted by number, as "<num>/<proto>  <service>" lines for
// the Open Ports section; "" when the host has no open ports. The full per-service detail lives in
// `services show` — this is the at-a-glance surface.
func portsBody(h *pb.Host) string {
	open := openPorts(h)
	if len(open) == 0 {
		return ""
	}
	sort.SliceStable(open, func(i, j int) bool { return open[i].Number < open[j].Number })

	var b strings.Builder
	for _, p := range open {
		fmt.Fprintf(&b, "  %s", color.HiGreenString("%d/%s", p.Number, p.Protocol))
		if svc := svcLabel(p); svc != "" {
			b.WriteString("  " + svc)
		}
		b.WriteString("\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

// svcLabel is the compact service description for a port line: its name, then its product/version
// dimmed; "" when the port carries no service.
func svcLabel(p *pb.Port) string {
	svc := p.GetService()
	if svc == nil {
		return ""
	}
	var parts []string
	if n := svc.GetName(); n != "" {
		parts = append(parts, n)
	}
	if prod := strings.TrimSpace(svc.GetProduct() + " " + svc.GetVersion()); prod != "" {
		parts = append(parts, display.Dim+prod+display.Reset)
	}
	return strings.Join(parts, "  ")
}

// cleartextServices returns the distinct cleartext application protocols exposed on the host's open
// ports, for the insights block.
func cleartextServices(h *pb.Host) (out []string) {
	seen := map[string]bool{}
	for _, p := range openPorts(h) {
		if name := cleartextProto(p); name != "" && !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	return out
}

// cleartextProto names the well-known cleartext protocol of a port (by service name or number), or
// "" if it is not a recognised cleartext service. Mirrors cmd/services.cleartextProtocol.
func cleartextProto(p *pb.Port) string {
	switch strings.ToLower(p.GetService().GetName()) {
	case "ftp", "telnet", "http", "smtp", "pop3", "imap", "snmp":
		return strings.ToLower(p.GetService().GetName())
	}
	switch p.GetNumber() {
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

// osConfidence reports the best OS-match accuracy and whether the OS is only an nmap guess (no
// authoritative OSName and at least one sub-100% match).
func osConfidence(h *pb.Host) (pct int, guessed bool) {
	if h.GetOSName() != "" {
		return 0, false // known without guessing
	}
	os := h.GetOS()
	if os == nil || len(os.GetMatches()) == 0 {
		return 0, false
	}
	var best int32
	for _, m := range os.GetMatches() {
		if m.GetAccuracy() > best {
			best = m.GetAccuracy()
		}
	}
	if best == 0 || best >= 100 {
		return int(best), false
	}
	return int(best), true
}

// uptimeLabel renders the host's uptime as "<d>d <h>h" (or the raw last-boot string when only that
// is known); "" when no uptime was recorded.
func uptimeLabel(h *pb.Host) string {
	u := h.GetUptime()
	if u == nil {
		return ""
	}
	if s := int(u.GetSeconds()); s > 0 {
		if d := s / 86400; d > 0 {
			return fmt.Sprintf("%dd %dh", d, (s%86400)/3600)
		}
		return fmt.Sprintf("%dh", s/3600)
	}
	return u.GetLastBoot()
}

// joinNames joins the host's non-empty hostnames with commas for a single-line pane value.
func joinNames(h *pb.Host) string {
	var names []string
	for _, hn := range h.GetHostnames() {
		if hn.GetName() != "" {
			names = append(names, hn.GetName())
		}
	}
	return strings.Join(names, ", ")
}

// joinAddrs joins the host's non-empty addresses with commas for a single-line pane value.
func joinAddrs(h *pb.Host) string {
	var addrs []string
	for _, a := range h.GetAddresses() {
		if a.GetAddr() != "" {
			addrs = append(addrs, a.GetAddr())
		}
	}
	return strings.Join(addrs, ", ")
}

// fmtTime renders a timestamp as "YYYY-MM-DD HH:MM", or "" when unset. Mirrors the other domains'
// detail-view time formatting.
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

// GetOperatingSystem returns the operating system of the host based on potential
// OS guess matches, or if none and the information is known without any guessing.
func GetOperatingSystem(h *pb.Host) (osName, osFamily string) {
	// If we have the information without the guesses.
	if h.OSFamily != "" {
		osFamily = h.OSFamily
	}
	if h.OSName != "" {
		osName = h.OSName
	}
	if h.OSFlavor != "" {
		osName += " " + h.OSFlavor
	}

	if osName != "" {
		return
	}

	// Else if we have to use nmap-style guesses.
	if h.OS == nil || len(h.OS.Matches) == 0 {
		return
	}

	var strongest *pb.OSMatch
	var second *pb.OSMatch

	for _, m := range h.OS.Matches {
		if strongest == nil {
			strongest = m
			continue
		}

		if m.Accuracy > strongest.Accuracy {
			second = strongest
			strongest = m
		}
	}

	if strongest.Name != "" {
		exact := "[~"
		if strongest.Accuracy == 100 {
			exact = strings.TrimSuffix(exact, "~")
		}
		osName = color.HiBlackString("%s%d%%|%d] ", exact, strongest.Accuracy, len(h.OS.Matches)) + strongest.Name
	} else if second != nil {
		exact := "[~"
		if second.Accuracy == 100 {
			exact = strings.TrimSuffix(exact, "~")
		}
		osName = color.HiBlackString("%s%d%%|%d] ", exact, second.Accuracy, len(h.OS.Matches)) + second.Name
	}

	return
}

func getProbableCPU(h *pb.Host) string {
	if h.Arch != "" {
		return h.Arch
	}

	if h.OS == nil || h.OS.Matches == nil {
		return ""
	}

	architectures := map[*regexp.Regexp]int{
		regexp.MustCompile("x86"):    0,
		regexp.MustCompile("i386"):   0,
		regexp.MustCompile("x64"):    0,
		regexp.MustCompile("x86_64"): 0,
		regexp.MustCompile("amd64"):  0,
		regexp.MustCompile("arm"):    0,
		regexp.MustCompile("arm64"):  0,
	}

	for _, m := range h.OS.Matches {
		for arch := range architectures {
			if arch.MatchString(m.Name) {
				architectures[arch]++
			}
		}
	}

	var cpuArch string
	most := 0

	for arch, count := range architectures {
		if count > most {
			most = count
			cpuArch = arch.String()
		}
	}

	if most == 0 || cpuArch == "" {
		return ""
	}

	return color.HiBlackString("[%d] ", most) + cpuArch
}

// Recursive function to print a ScriptORM object with nested structures
func printExtraPorts(port *pb.ExtraPort, indentLevel int) string {
	buf := new(strings.Builder)
	indent := strings.Repeat("  ", indentLevel)

	fmt.Fprintf(buf, "\n%s%s: %d", indent, color.HiYellowString(port.State), port.GetCount())

	// Print Elements
	reasons := []string{}
	if len(port.Reasons) > 0 {
		for _, reason := range port.Reasons {
			reasons = append(reasons, fmt.Sprintf("%d %s", reason.Count, reason.Reason))
		}

		fmt.Fprintf(buf, " (%s)", strings.Join(reasons, ", "))
	}

	return buf.String()
}
