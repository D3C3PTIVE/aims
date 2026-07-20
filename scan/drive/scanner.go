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
	"os"
	"os/exec"
	"strings"

	nmapfork "github.com/d3c3ptive/nmap"

	scandomain "github.com/d3c3ptive/aims/scan"
	scanpb "github.com/d3c3ptive/aims/scan/pb"
)

// Scanner drives a tool against AIMS-selected targets and streams results back. It is the
// in-process form of the substrate; the server-side streaming RPC (SCAN.md Part C, Phase 4)
// puts the same surface behind the teamserver so foreground and detached scans share one path.
type Scanner interface {
	// Scan runs the tool against targets (plus any extra tool arguments) and returns three
	// channels plus a launch error:
	//   - results:  Results to fold (Run.AddResult), closed when the scan ends;
	//   - progress: TaskProgress to display, closed when the scan ends;
	//   - errc:     the scan's TERMINAL outcome — at most one value then closed. nil means the
	//               tool completed cleanly; a non-nil error is a failure the tool signalled AFTER
	//               launch (e.g. nmap "requires root privileges. QUITTING!", a resolve failure, a
	//               non-zero exit). Drain it AFTER results/progress close.
	//   - err:      a synchronous LAUNCH error (bad args, binary missing) — the scan never started,
	//               and results/progress/errc are all nil.
	//
	// Splitting launch (err) from terminal (errc) is the whole point: a tool that starts and then
	// dies mid-flight had, until now, nowhere to report that — so the run was misread as a success.
	Scan(ctx context.Context, targets []*scanpb.Target, args ...string) (
		results <-chan *scanpb.Result,
		progress <-chan *scanpb.TaskProgress,
		errc <-chan error,
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
	<-chan *scanpb.Result, <-chan *scanpb.TaskProgress, <-chan error, error,
) {
	specs := scandomain.TargetSpecs(targets)
	// Reject only when there is nothing at all to scan. In raw-passthrough mode the target is
	// just another token in args (e.g. `scan run nmap -sT 127.0.0.1`), so a non-empty args set
	// is a valid invocation even with no structured Targets.
	if len(specs) == 0 && len(args) == 0 && len(n.Args) == 0 {
		return nil, nil, nil, errors.New("drive: no scan targets or arguments")
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
	// nmap's own guard aborts a raw-packet scan (-sS/-sU/-sO/-O) whenever euid != 0 — even when the
	// binary carries CAP_NET_RAW (as `aims init caps` grants). When nmap is genuinely privilege-capable
	// (we are root, or the binary has the cap), pass NMAP_PRIVILEGED=1 so nmap proceeds and uses those
	// caps. When it is NOT, leave it unset on purpose: an unprivileged nmap then keeps its connect-scan
	// fallback and reports the honest "requires root privileges" error for raw scans, rather than
	// picking a privileged default it cannot carry out.
	if nmapPrivileged(n.BinaryPath) {
		opts = append(opts, nmapfork.WithCustomEnv("NMAP_PRIVILEGED=1"))
	}

	scanner, err := nmapfork.NewScanner(opts...)
	if err != nil {
		return nil, nil, nil, err
	}

	// Start nmap asynchronously and consume its live host/progress streams (the fork's fixed
	// async path: YieldHosts/YieldProgress emit as nmap runs and close on completion). Each host
	// batch becomes per-host Results; progress frames pass through. The channels close when the
	// scan ends so consumers' range loops terminate.
	if err := scanner.RunAsync(); err != nil {
		return nil, nil, nil, err
	}

	results := make(chan *scanpb.Result)
	progress := make(chan *scanpb.TaskProgress)
	errc := make(chan error, 1)

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

	// Reap the process once it exits and surface its terminal outcome. WaitResult folds nmap's
	// three error channels (stderr warnings, XML runstats errormsg, process exit status) into one
	// error — the signal Wait alone discarded, which is why a scan that failed after launch (e.g.
	// "requires root privileges. QUITTING!") was misread as a clean, empty success. Buffered so this
	// send never blocks even if the consumer drains errc only after results/progress close.
	go func() {
		_, werr := scanner.WaitResult()
		errc <- werr
		close(errc)
	}()

	return results, progress, errc, nil
}

// nmapPrivileged reports whether nmap can perform raw-packet scans without being launched as root:
// either the process is already root, or the nmap binary carries CAP_NET_RAW (e.g. granted by `aims
// init caps`). binaryPath is the configured nmap path; empty resolves via $PATH. Detection is
// best-effort — an absent or unreadable getcap reads as "not privileged", the safe default that
// leaves nmap its unprivileged connect-scan fallback and honest raw-scan error.
func nmapPrivileged(binaryPath string) bool {
	if os.Geteuid() == 0 {
		return true
	}
	path := binaryPath
	if path == "" {
		if resolved, err := exec.LookPath("nmap"); err == nil {
			path = resolved
		}
	}
	if path == "" {
		return false
	}
	out, err := exec.Command("getcap", path).Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "cap_net_raw")
}
