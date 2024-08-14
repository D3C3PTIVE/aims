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
	"fmt"
	"strings"
	"time"

	"github.com/d3c3ptive/aims/cmd/display"
	"github.com/d3c3ptive/aims/host"
	"github.com/d3c3ptive/aims/internal/util"
	"github.com/d3c3ptive/aims/proto/c2"
	"github.com/fatih/color"
)

type Agent c2.Agent

//
// [ Display Functions ] --------------------------------------------------
//

// DisplayHeaders returns all weighted table headers for a table of.Agents.
func DisplayHeaders() (headers []display.Options) {
	add := func(n string, w int) {
		headers = append(headers, display.WithHeader(n, w))
	}

	add("ID", 1)
	add("Tool", 1)
	add("Name", 1)
	add("User/Hostname", 1)
	add("OS", 1)
	add("Channels", 1)

	add("Last/Next Check-in", 2)
	add("Tasks", 2)

	return headers
}

// DetailHeaders returns the headers for a detailed.Agent view.
func DisplayDetails() []display.Options {
	var headers []display.Options
	add := func(n string, w int) {
		headers = append(headers, display.WithHeader(n, w))
	}

	// Core
	add("ID", 1)
	add("Tool", 1)
	add("Name", 1)
	add("Host ID", 1)
	add("User/Hostname", 1)
	add("OS", 1)
	add("Process", 1)
	add("Working directory", 1)

	// Tasks
	add("Last/Next Check-in", 2)
	add("Tasks ", 2)

	// Network
	add("Channel Details", 3)

	// Tools
	// add("Task Details", 3)

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
	add("Name", 1)
	add("Tool", 1)
	add("User/Hostname", 1)
	add("Channels", 1)

	return headers
}

// Fields maps field names to their value generators.
var DisplayFields = map[string]func(h *c2.Agent) string{
	"ID": func(h *c2.Agent) string {
		// id := display.FormatSmallID(h.Id)
		// Either up and within checkin, green

		// Or dead and behind checkin, red

		// Or not dead but behind checkin. yellow
		return ""
	},
	"Tool": func(h *c2.Agent) string {
		return h.Tool
	},
	"Name": func(h *c2.Agent) string {
		return h.Name
	},
	"Host ID": func(h *c2.Agent) string {
		if h.Host == nil {
			return "No host"
		}
		return display.FormatSmallID(h.Id)
	},
	"User/Hostname": func(h *c2.Agent) string {
		user, host := "", ""
		if h.User != nil {
			user = h.User.Name
		}
		// Find first host name
		if len(h.Host.Hostnames) > 0 {
			for _, hostname := range h.Host.Hostnames {
				if hostname.Name == "localhost" {
					continue
				}
				host = hostname.Name
				break
			}
		}

		return fmt.Sprintf("%s@%s", color.HiWhiteString(user), color.HiWhiteString(host))
	},
	"OS": func(h *c2.Agent) string {
		name, family := host.GetOperatingSystem(h.Host)

		if name == "" && family == "" {
			return color.HiRedString("Undefined")
		}

		return fmt.Sprintf("%s %s", family, name)
	},
	"Process": func(h *c2.Agent) string {
		if h.Process == nil {
			return "No process information"
		}

		process := fmt.Sprintf("%d", h.Process.Id)
		if h.Process.Owner != nil && h.Process.Owner.Name != "" {
			process += fmt.Sprintf("- %s -", h.Process.Owner)
		}

		if h.Process.Ppid != 0 {
			process += color.HiBlackString(fmt.Sprintf("(P )", h.Process.Ppid))
		}
		if len(h.Process.CmdLine) != 0 {
			process += fmt.Sprintf("[%s]", strings.Join(h.Process.CmdLine, " "))
		}

		return process
	},
	"Working directory": func(h *c2.Agent) string {
		return color.HiBlueString(h.WorkingDirectory)
	},

	"Last/Next Check-in": func(h *c2.Agent) string {
		last := time.Unix(h.LastCheckin, 0)
		next := time.Unix(h.NextCheckin, 0)
		lastTime := util.FormatDateDelta(last, false, false)
		nextTime := util.FormatDateDelta(next, false, true)
		return fmt.Sprintf("%s/%s", lastTime, nextTime)
	},
	"Tasks": func(h *c2.Agent) string {
		tasks := ""
		completed := h.TasksCountCompleted
		if completed < h.TasksCount {
			tasks = color.HiYellowString("%d", completed)
		}
		return fmt.Sprintf("%s/%d", tasks, h.TasksCount)
	},
	"Channel Details": func(h *c2.Agent) string {
		return ""
	},
	// Route should return the pivots graph for this agent.
	"Route": func(h *c2.Agent) string {
		return ""
	},
}
