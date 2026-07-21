package drive

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
	"bufio"
	"context"
	"errors"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	scandomain "github.com/d3c3ptive/aims/scan"
	nmapscan "github.com/d3c3ptive/aims/scan/nmap"
	scanpb "github.com/d3c3ptive/aims/scan/pb"
)

// Masscan drives the masscan port scanner. masscan emits nmap-compatible XML (-oX), so its output
// folds into the model through the very same scan/nmap parser the Nmap driver's hosts flow through —
// the driver just execs masscan, appends `-oX <tmpfile>`, and on exit parses that file into per-host
// Results. Progress is read best-effort from masscan's stderr ("… N.NN% done").
//
// Unlike Nmap (which drives the AIMS-native fork with a live host stream), masscan writes its XML
// only at completion, so hosts surface as one batch when the scan ends; the stderr percent keeps a
// foreground scan's display alive in the meantime.
type Masscan struct {
	// Args are masscan arguments placed before the target specs (e.g. "-p1-65535", "--rate=10000").
	Args []string
	// BinaryPath overrides the masscan binary location; empty uses $PATH.
	BinaryPath string
}

// masscanProgressRE matches the percent in masscan's stderr progress line, e.g.
//
//	rate: 10.00-kpps,  42.13% done,   0:00:12 remaining
var masscanProgressRE = regexp.MustCompile(`([0-9]+\.[0-9]+)%\s+done`)

func (m Masscan) Scan(ctx context.Context, targets []*scanpb.Target, args ...string) (
	<-chan *scanpb.Result, <-chan *scanpb.TaskProgress, <-chan string, <-chan error, error,
) {
	specs := scandomain.TargetSpecs(targets)
	// Reject only when there is nothing at all to scan; in raw-passthrough mode the target is just
	// another token in args (e.g. `scan run masscan -p80 10.0.0.0/24`).
	if len(specs) == 0 && len(args) == 0 && len(m.Args) == 0 {
		return nil, nil, nil, nil, errors.New("drive: no scan targets or arguments")
	}

	// masscan writes XML only at completion; capture it in a temp file we parse when the process
	// exits. The XML flag is added automatically (mirrors the nmap driver), so callers pass targets,
	// ports and flags — not an -oX of their own.
	xmlFile, err := os.CreateTemp("", "aims-masscan-*.xml")
	if err != nil {
		return nil, nil, nil, nil, err
	}
	xmlPath := xmlFile.Name()
	_ = xmlFile.Close()

	binary := m.BinaryPath
	if binary == "" {
		binary = "masscan"
	}

	scanArgs := make([]string, 0, len(m.Args)+len(args)+len(specs)+2)
	scanArgs = append(scanArgs, m.Args...)
	scanArgs = append(scanArgs, args...)
	scanArgs = append(scanArgs, specs...)
	scanArgs = append(scanArgs, "-oX", xmlPath)

	cmd := exec.CommandContext(ctx, binary, scanArgs...)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		os.Remove(xmlPath)
		return nil, nil, nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		os.Remove(xmlPath)
		return nil, nil, nil, nil, err
	}

	results := make(chan *scanpb.Result)
	progress := make(chan *scanpb.TaskProgress)
	warnings := make(chan string, 256)
	errc := make(chan error, 1)
	stderrDone := make(chan struct{})

	// Progress + warnings: masscan's stderr carries both its "N.NN% done" rate line and other
	// notices. A percent line becomes a TaskProgress; any other non-blank line is forwarded as a
	// live warning (best-effort), so a masscan run surfaces the same running commentary the nmap
	// driver does. Ranges until stderr EOF (the process exit), then signals the reaper that all
	// reads are done — the StderrPipe contract forbids calling Wait before the pipe is drained.
	go func() {
		defer close(progress)
		defer close(warnings)
		defer close(stderrDone)
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			line := sc.Text()
			if match := masscanProgressRE.FindStringSubmatch(line); match != nil {
				pct, err := strconv.ParseFloat(match[1], 32)
				if err != nil {
					continue
				}
				select {
				case progress <- &scanpb.TaskProgress{Task: "masscan", Percent: float32(pct)}:
				case <-ctx.Done():
					return
				}
				continue
			}
			if trimmed := strings.TrimSpace(line); trimmed != "" {
				select {
				case warnings <- trimmed:
				case <-ctx.Done():
					return
				default: // never stall the scan on a slow warnings consumer
				}
			}
		}
	}()

	// Results: once stderr is drained and masscan has exited, parse the XML it wrote and emit each
	// host as a Result — the same fold the Nmap driver feeds. The temp file is removed when done.
	// The terminal outcome (masscan's exit status, or an XML parse failure on a clean exit) is
	// reported on errc so a failed masscan run reads as failed, not as a clean empty success — the
	// same fix as the Nmap driver's WaitResult.
	go func() {
		var termErr error
		defer close(results)
		defer func() { errc <- termErr; close(errc) }()
		defer os.Remove(xmlPath)

		<-stderrDone
		termErr = cmd.Wait() // non-zero exit == a real failure (bad args, missing privileges)

		raw, err := os.ReadFile(xmlPath)
		if err != nil || len(raw) == 0 {
			return // masscan found nothing, or failed before writing any output (termErr covers it)
		}
		run, err := nmapscan.FromXML(raw)
		if err != nil {
			if termErr == nil {
				termErr = err // a clean exit but unparseable output is still a failure
			}
			return
		}
		for _, h := range run.ToPB().GetHosts() {
			select {
			case results <- &scanpb.Result{Host: h}:
			case <-ctx.Done():
				return
			}
		}
	}()

	return results, progress, warnings, errc, nil
}
