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
	"sync"

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
	add("Purpose", 3)
	add("MAC", 3)
	add("Virtual Host", 3)

	// Tools
	add("Comment", 4)
	add("Hosts scripts", 5)

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
var DisplayFields = map[string]func(h *host.Host) string{
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
	"Route": func(h *host.Host) string {
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
}

// FilterIdentical returns a list of hosts from which have been removed all hosts that are
// already in the database, with a very high degree of certitude. This avoids redundance when
// manipulating new hosts.
func FilterIdenticalHost(raw []host.HostORM, dbHosts []*host.HostORM) (filtered []host.HostORM) {
	// For each host to add:
	for _, newHost := range raw {
		done := new(sync.WaitGroup)

		allMatches := []*host.HostORM{}

		// Check IDs: if non-nil and identical, done checking.

		// Concurrently check all hosts for an identical trace.
		done.Add(1)
		go func() {
			allMatches = append(allMatches, hasIdenticalTrace(newHost, dbHosts))
		}()

		// Concurrently check all hosts for identical user/hostnames
		done.Add(1)
		go func() {
			allMatches = append(allMatches, hasIdenticalHostnames(newHost, dbHosts))
			allMatches = append(allMatches, hasIdenticalUsers(newHost, dbHosts))
		}()

		// Concurrently check all hosts ports
		done.Add(1)
		go func() {
			allMatches = append(allMatches, hasIdenticalPorts(newHost, dbHosts))
		}()

		// Concurrently check all hosts IPs
		done.Add(1)
		go func() {
			allMatches = append(allMatches, hasIdenticalAddresses(newHost, dbHosts))
		}()

		// For now we wait for all queries to finish, but ideally,
		// some filters have more weight than others, but might be
		// longer to check, so when one shows that hosts are identical,
		// all other comparison routines should break.
		done.Wait()

		// If identical, add it to the valid, filtered hosts
		if identical, _ := allHostsIdentical(allMatches); identical {
			filtered = append(filtered, newHost)
		}

	}

	return
}

func osMatched(h *host.Host) (osName, osFamily string) {
	if h.OS == nil || len(h.OS.Matches) == 0 {
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

func hasIdenticalTrace(h host.HostORM, all []*host.HostORM) (found *host.HostORM) {
	return nil
}

func hasIdenticalHostnames(h host.HostORM, all []*host.HostORM) (found *host.HostORM) {
	return nil
}

func hasIdenticalUsers(h host.HostORM, all []*host.HostORM) (found *host.HostORM) {
	return nil
}

func hasIdenticalPorts(h host.HostORM, all []*host.HostORM) (found *host.HostORM) {
	return nil
}

func hasIdenticalAddresses(h host.HostORM, all []*host.HostORM) (found *host.HostORM) {
	return nil
}

func allHostsIdentical(all []*host.HostORM) (yes bool, matches int) {
	return false, 0
}
