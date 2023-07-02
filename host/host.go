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
	"github.com/maxlandon/aims/display"
	"github.com/maxlandon/aims/proto/host"
)

// Host - A physical or virtual computer host.
// The type has several categories of fields: general information,
// and Nmap-compliant fields (ports, status, route, scripts etc).
type Host host.Host

//
// [ Display Functions ] --------------------------------------------------
//

// TableHeaders returns all weighted table headers for a table of hosts.
func Headers() (headers []display.Options) {
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
func Details() []display.Options {
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
	add("Comment", 1)

	add("Purpose", 3)
	add("MAC", 3)
	add("Virtual Host", 3)

	// Network
	add("Hostnames", 4)
	add("Addresses", 4)
	add("Hops", 4)
	add("Route", 4)

	// Tools
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

// Fields maps field names to their value generators
var Fields = map[string]func(h *host.Host) string{
	// Table
	"ID": func(h *host.Host) string {
		if h.Status.State == "up" {
			return color.HiGreenString(display.FormatSmallID(h.Id))
		}
		return display.FormatSmallID(h.Id)
	},
	"Hostnames": func(h *host.Host) string {
		var hostnames []string
		for _, hn := range h.Hostnames {
			hostnames = append(hostnames, hn.Name)
		}
		return strings.Join(hostnames, "\n")
	},
	"OS Name": func(h *host.Host) string {
		osName, _ := osMatched(h)
		return osName
	},
	"OS Family": func(h *host.Host) string {
		_, fam := osMatched(h)
		return fam
	},
	"Addresses": func(h *host.Host) string {
		var addresses []string
		for _, hn := range h.Addresses {
			addresses = append(addresses, hn.Addr)
		}
		return strings.Join(addresses, "\n")
	},

	"Status": func(h *host.Host) string {
		return ""
	},
	"Hops": func(h *host.Host) string {
		if h.Trace == nil {
			return ""
		}

		return fmt.Sprint(len(h.Trace.Hops))
	},
	"Arch": getProbableCPU,
	"MAC":  func(h *host.Host) string { return h.MAC },
	"Purpose": func(h *host.Host) string {
		// Look at OS matches for various types.
		// Don't include them all, just 2/3 more recurring ones.
		return ""
	},

	// Details
	"Route": func(h *host.Host) string {
		if h.Trace == nil {
			return ""
		}

		var hops []string
		for _, hop := range h.Trace.Hops {
			hopDisplay := color.HiBlackString("| ") + color.YellowString(hop.Host) + " - " + hop.IPAddr
			hops = append(hops, hopDisplay)
		}

		return strings.Join(hops, "\n")
	},
}

func osMatched(h *host.Host) (osName, osFamily string) {
	if len(h.OS.Matches) == 0 {
		return
	}

	var strongest *host.OSMatch
	var second *host.OSMatch

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

func getProbableCPU(h *host.Host) string {
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
