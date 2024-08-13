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
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/fatih/color"

	"github.com/d3c3ptive/aims/cmd/display"
	"github.com/d3c3ptive/aims/proto/scan"
)

// Run - Represents a scan before, after or while being run.
// This run can be the one of any scanner: fields are not mandatorily used
// by all scanners for all scans, but this type gives a common tree in which
// to store hosts, ports, services, statistics and various other information.
//
// The type provides many convenience methods to process all the output of the
// scan, either at once or continuously, or even to refine the objects based on/
// with those already in a database. Therefore, all the methods of this type
// are meant to be used server-side, and not in an implant.
//
// For having similar functionality from within an implant, use the Protobuf
// scan.Run type, which itself has some convenience methods that do NOT need
// any database or its related libraries.
type Run scan.Run

// NewRun - Create a new scan.Run based on a tool (scanner) name, and with an
// optional Options type holding various settings to be customized for your use.
func NewRun(scanner string, args ...string) *Run {
	return &Run{
		Scanner: scanner,
		Args:    strings.Join(args, " "),
	}
}

// ToPB - Get the Protobuf object for the Result.
func (r *Run) ToPB() *scan.Run {
	return (*scan.Run)(r)
}

// Functionality
//
// Return a concurrent spinner/progress bar / interface for progress
// unction to update progress

// when they are needed by the service probing stack used by the scan.
func (r *Run) AddTarget(t *Target) {
}

// InitResult - Instantiate a new result that has the Run UUID in ref.
// The rest of the object can be populated by the user as he wishes.
func (r *Run) InitResult() *Result {
	return &Result{}
}

// AddResult - Return a Result (which must be created with construtor: has mapped ID)
// This function takes care of matching anything against DB, populates various fields,
// and adds all of those into the Run object tree.
//
// Note that when you call this function, if your scan makes use of the Result.Data field
// (used by custom/specific service scanner), we assume that it is correctly populated.
// You however have access to a few functions to manage the types you can put in this .Data
//
// As for many other objects that you'll find as field in "request option structs", this
// Result can hold a host, service, port, etc. It is always advised to pass objects that
// are themselves coming from other tools/pipes, so as to keep track of them in complex workflows.
func (r *Run) AddResult(res *Result) (err error) {
	// if res.Id == "" || res.Id == uuid.Nil.String() {
	// 	return errors.New("Result is not tied to any scan.Run")
	// }
	return
}

//
//
// Nmap-specific ------------------------------------------------------
//

//
//
//

//
// Zgrab-specific ------------------------------------------------------
//

// DisplayHeaders returns all weighted table headers for a table of scans.
func DisplayHeaders() (headers []display.Options) {
	add := func(n string, w int) {
		headers = append(headers, display.WithHeader(n, w))
	}

	add("ID", 1)
	add("Scanner", 1)
	add("Name", 1)
	add("Info", 1)
	add("Hosts", 1)
	add("Begin/End", 1)
	add("Tasks", 1)
	add("Finished", 1)

	add("Args", 2)
	add("Targets", 2)

	return headers
}

// DetailHeaders returns the headers for a detailed scan view.
func DisplayDetails() []display.Options {
	var headers []display.Options
	add := func(n string, w int) {
		headers = append(headers, display.WithHeader(n, w))
	}

	// Core
	add("ID", 1)
	add("Scanner", 1)
	add("Name", 1)
	add("Info", 1)
	add("Hosts", 1)
	add("Begin/End", 1)
	add("Finished", 1)
	add("Tasks", 1)
	add("Targets", 1)
	add("Args", 1)

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
	add("Scanner", 1)
	add("Name", 1)
	add("Info", 1)
	add("Tasks", 1)
	add("Args", 1)

	return headers
}

// Fields maps field names to their value generators.
var DisplayFields = map[string]func(h *scan.Run) string{
	// Table
	"ID": func(h *scan.Run) string {
		if len(h.Begin) > len(h.End) {
			return color.HiGreenString(display.FormatSmallID(h.Id))
		}
		if len(h.End) == 0 && len(h.Progress) > 0 {
			return color.HiYellowString(display.FormatSmallID(h.Id))
		}

		return display.FormatSmallID(h.Id)
	},
	"Scanner": func(h *scan.Run) string {
		return h.Scanner
	},
	"Name": func(h *scan.Run) string {
		return h.ProfileName
	},
	"Info": func(h *scan.Run) string {
		info := h.Info.Protocol + "/" + h.Info.Type
		return info
	},
	"Args": func(h *scan.Run) string {
		return h.Args
	},
	"Begin/End": func(h *scan.Run) string {
		if h.Stats == nil || h.Stats.Finished == nil {
			return ""
		}
		done := h.Stats.Finished.TimeStr
		return fmt.Sprintf("%s (%s)",
			done,
			time.Duration(int64(h.Stats.Finished.Elapsed)).String())
	},
	"Targets": func(h *scan.Run) string {
		targetsDisplay := new(strings.Builder)

		if h.Info.NumServices > 0 {
			targetsDisplay.WriteString(fmt.Sprintf("Services (%d)   ", h.Info.NumServices))
		}

		if len(h.Targets) > 0 {
			tgtRaw := fmt.Sprintf("Hosts (%d)", len(h.Targets))
			targetsDisplay.WriteString(tgtRaw)
		}

		return strings.TrimSpace(targetsDisplay.String())
	},
	"Targets Details": func(h *scan.Run) string {
		targetsDisplay := new(strings.Builder)

		if h.Info.Services != "" {
			targetsDisplay.WriteString(h.Info.Services)
		}

		for _, tgt := range h.Targets {
			tgtRaw := fmt.Sprintf("%s:%d", tgt.Address, tgt.Port)
			if tgt.Port == 0 {
				tgtRaw = strings.TrimSuffix(tgtRaw, ":0")
			}
			tgtURL, err := url.Parse(tgtRaw)
			if err != nil {
				return tgtRaw
			}

			targetsDisplay.WriteString(fmt.Sprintln(tgtURL.String()))
		}

		return targetsDisplay.String()
	},
	"Finished": func(h *scan.Run) string {
		return ""
	},
	"Hosts": func(h *scan.Run) string {
		var hosts string

		var hostsUp, hostsDown int32

		if h.Stats != nil && h.Stats.Hosts != nil {
			hostsUp = h.Stats.Hosts.Up
			hostsDown = h.Stats.Hosts.Down

		} else {
			for _, h := range h.Hosts {
				if h.Status.State == "up" {
					hostsUp++
				} else {
					hostsDown++
				}
			}
		}

		hosts += color.HiGreenString(fmt.Sprint(hostsUp))
		hosts += "/"
		hosts += color.HiRedString(fmt.Sprint(hostsDown))

		return hosts
	},
	"Tasks": func(h *scan.Run) string {
		tasksDisplay := ""

		running, done := getTasks(h)

		if len(running) > 0 {
			tasksDisplay += color.HiYellowString("%d", len(h.End))
		} else {
			tasksDisplay += fmt.Sprintf("%d", len(done))
		}

		tasksDisplay += fmt.Sprintf("/%d", len(done)+len(running))

		return tasksDisplay
	},
	"Tasks Details": func(h *scan.Run) string {
		return formatTasks(h)
	},
}

func tasksHeaders() []display.Options {
	var headers []display.Options
	add := func(n string, w int) {
		headers = append(headers, display.WithHeader(n, w))
	}
	add("Time", 1)
	add("Name", 1)
	add("Info", 1)

	return headers
}

var tasksFields = map[string]func(h *scan.ScanTask) string{
	"Time": func(taskEnd *scan.ScanTask) string {
		return color.HiBlackString(time.Unix(taskEnd.Time, 0).String())
	},
	"Name": func(h *scan.ScanTask) string {
		return h.Task
	},
	"Info": func(h *scan.ScanTask) string {
		return h.ExtraInfo
	},
}

func tasksProgressHeaders() []display.Options {
	var headers []display.Options
	add := func(n string, w int) {
		headers = append(headers, display.WithHeader(n, w))
	}

	add("Time", 1)
	add("Name", 1)
	add("Percent", 1)

	return headers
}

var tasksProgressFields = map[string]func(h *scan.TaskProgress) string{
	"Name": func(h *scan.TaskProgress) string {
		return h.Task
	},
	"Time": func(taskEnd *scan.TaskProgress) string {
		return color.HiBlackString(time.Unix(taskEnd.Time, 0).String())
	},
	"Percent": func(taskEnd *scan.TaskProgress) string {
		return color.HiYellowString(fmt.Sprintf("%v%%", taskEnd.Percent))
	},
}

func formatTasks(h *scan.Run) string {
	tasksDisplay := ""
	running, done := getTasks(h)

	if len(running) > 0 {
		table := display.Table(running, tasksProgressFields, tasksProgressHeaders()...)
		table.SetTitle("\n" + color.HiYellowString("Running tasks"))
		tasksDisplay += table.Render()
	}

	if len(done) > 0 {

		table := display.Table(done, tasksFields, tasksHeaders()...)
		table.SetTitle("\n" + color.HiYellowString("Done tasks"))
		tasksDisplay += table.Render()
	}

	return tasksDisplay
}

func getTasks(h *scan.Run) (running []*scan.TaskProgress, done []*scan.ScanTask) {
	var runningRemain []*scan.TaskProgress
	nonFinished := true

	if len(h.Begin) > 0 {
		for i := range h.Begin {
			// Find the corresponding end if any.
			// Or check the running tasks progress values.
			if 0 <= i && i <= len(h.End) {
				taskEnd := h.End[i]
				done = append(done, taskEnd)
				nonFinished = false
				continue
			}

			nonFinished = false
		}
	}

	// Filter out duplicates in remain
	if len(h.Progress) > 0 && nonFinished {
		slices.SortFunc(h.Progress, func(a, b *scan.TaskProgress) int {
			switch {
			case a.Percent < b.Percent:
				return -1
			case a.Percent > b.Percent:
				return +1
			default:
				return 0
			}
		})
		var current *scan.TaskProgress
		done := false

		for i := len(h.Progress); i > 0; i-- {
			task := h.Progress[i-1]

			if current == nil {
				runningRemain = append(runningRemain, task)
				current = task
				continue
			}

			if current.Task == task.Task {
				continue
			}

			current = nil
			done = true
		}

		if current != nil && done {
			runningRemain = append(runningRemain, current)
		}
	}
	if len(done) > 0 {
		slices.SortFunc(done, func(a, b *scan.ScanTask) int {
			aTime := time.Unix(a.Time, 0)
			bTime := time.Unix(b.Time, 0)

			return aTime.Compare(bTime)
		})
	}

	if len(runningRemain) > 0 {
		slices.SortFunc(runningRemain, func(a, b *scan.TaskProgress) int {
			aTime := time.Unix(a.Time, 0)
			bTime := time.Unix(b.Time, 0)

			return aTime.Compare(bTime)
		})
		running = append(running, runningRemain...)
	}

	if len(running) > 0 {
		slices.SortFunc(running, func(a, b *scan.TaskProgress) int {
			aTime := time.Unix(a.Time, 0)
			bTime := time.Unix(b.Time, 0)

			return aTime.Compare(bTime)
		})
	}
	return
}
