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
	"strings"

	"github.com/fatih/color"

	"github.com/d3c3ptive/aims/cmd/display"
	"github.com/d3c3ptive/aims/host/pb"
)

// Host - A physical or virtual computer host.
// The type has several categories of fields: general information,
// and Nmap-compliant fields (ports, status, route, scripts etc).
type Host pb.Host

//
// [ Display Functions ] --------------------------------------------------
//

// DisplayHeaders returns all weighted table headers for a table of hosts.
func DisplayHeaders() (headers []display.Options) {
	add := func(n string, w int) {
		headers = append(headers, display.WithHeader(n, w))
	}

	add("ID", 1)
	add("Hostnames", 1)
	add("OS Name", 1)
	add("OS Family", 1)
	add("Addresses", 1)

	add("Status", 2)
	add("Hops", 2)

	add("Arch", 3)
	add("MAC", 3)
	add("Purpose", 3)

	return headers
}

// DetailHeaders returns the headers for a detailed host view.
func DisplayDetails() []display.Options {
	var headers []display.Options
	add := func(n string, w int) {
		headers = append(headers, display.WithHeader(n, w))
	}

	// Core
	add("ID", 1)
	add("OS Name", 1)
	add("OS Family", 1)
	add("Arch", 1)
	add("Status", 1)

	// Network
	add("Hostnames", 2)
	add("Addresses", 2)
	add("Hops", 2)

	// Hardware
	add("Extra Ports", 3)
	add("Purpose", 3)
	add("MAC", 3)
	add("Virtual Host", 3)

	// Tools
	add("Comment", 4)
	add("Hosts scripts", 4)

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
	add("Hostnames", 1)
	add("OS Name", 1)
	add("Addresses", 1)

	return headers
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
		return ""
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
				println(c.Type)
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
}

// GetOperatingSystem returns the operating system of the host based on potential
// OS guess matches, or if none and the information is known without any guessing.
func GetOperatingSystem(h *pb.Host) (osName, osFamily string) {
	// If we have the information without the guesses.
	if h.OSFamily != "" {
		osFamily = h.OSFamily
	}
	if h.OSName == "" {
		osName = h.OSName
	}
	if h.OSFlavor == "" {
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
