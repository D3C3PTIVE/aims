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

// Package drive is the target-side plug point of the scanner substrate (SCAN.md Part C, plug
// point B): where ingest.Ingestor folds a foreign tool's *output* into the model, a Scanner
// *runs* a tool against scan Targets (derived from stored hosts via scan.TargetsFromHosts) and
// streams Results + progress back for the fold to consume — closing the query → target → scan →
// fold → store loop.
//
// This package lives outside the scan domain package on purpose: the AIMS-native nmap fork
// imports scan, so the scan package cannot import the fork without a cycle. drive depends on
// both (fork + scan) and nothing depends on drive, keeping the graph acyclic — the same shape
// as scan/ingest.

import (
	"context"
	"errors"

	nmapfork "github.com/d3c3ptive/nmap"

	scandomain "github.com/d3c3ptive/aims/scan"
	scanpb "github.com/d3c3ptive/aims/scan/pb"
)

// Scanner drives a tool against AIMS-selected targets and streams results back. It is the
// in-process form of the substrate; the server-side streaming RPC (SCAN.md Part C, Phase 4)
// puts the same surface behind the teamserver so foreground and detached scans share one path.
type Scanner interface {
	// Scan runs the tool against targets (plus any extra tool arguments) and returns two
	// channels: Results to fold (Run.AddResult) and TaskProgress to display. Both are closed
	// when the scan ends; a nil error means the scan started, not that it succeeded.
	Scan(ctx context.Context, targets []*scanpb.Target, args ...string) (
		results <-chan *scanpb.Result,
		progress <-chan *scanpb.TaskProgress,
		err error,
	)
}

// Nmap is the reference Scanner, driving the AIMS-native nmap fork. Each host nmap reports is
// surfaced as a Result carrying that host (Result.Host) as it is found, so the downstream fold
// enriches the very objects the targets were derived from while the scan is still running.
type Nmap struct {
	// Args are nmap arguments placed before the target specs (e.g. "-sV", "-p1-1000").
	Args []string
	// BinaryPath overrides the nmap binary location; empty uses $PATH.
	BinaryPath string
}

func (n Nmap) Scan(ctx context.Context, targets []*scanpb.Target, args ...string) (
	<-chan *scanpb.Result, <-chan *scanpb.TaskProgress, error,
) {
	specs := scandomain.TargetSpecs(targets)
	if len(specs) == 0 {
		return nil, nil, errors.New("drive: no scan targets")
	}

	nmapArgs := make([]string, 0, len(n.Args)+len(args)+len(specs))
	nmapArgs = append(nmapArgs, n.Args...)
	nmapArgs = append(nmapArgs, args...)
	nmapArgs = append(nmapArgs, specs...)

	opts := []nmapfork.Option{
		nmapfork.WithContext(ctx),
		nmapfork.WithCustomArguments(nmapArgs...),
	}
	if n.BinaryPath != "" {
		opts = append(opts, nmapfork.WithBinaryPath(n.BinaryPath))
	}

	scanner, err := nmapfork.NewScanner(opts...)
	if err != nil {
		return nil, nil, err
	}

	// Start nmap asynchronously and consume its live host/progress streams (the fork's fixed
	// async path: YieldHosts/YieldProgress emit as nmap runs and close on completion). Each host
	// batch becomes per-host Results; progress frames pass through. The channels close when the
	// scan ends so consumers' range loops terminate.
	if err := scanner.RunAsync(); err != nil {
		return nil, nil, err
	}

	results := make(chan *scanpb.Result)
	progress := make(chan *scanpb.TaskProgress)

	go func() {
		defer close(results)
		for batch := range scanner.YieldHosts() {
			for _, h := range batch {
				select {
				case results <- &scanpb.Result{Host: h}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	go func() {
		defer close(progress)
		for tp := range scanner.YieldProgress() {
			select {
			case progress <- tp:
			case <-ctx.Done():
				return
			}
		}
	}()

	// Reap the process once it exits (releases resources; the yield channels already signal
	// completion to consumers by closing).
	go func() { _ = scanner.Wait() }()

	return results, progress, nil
}
