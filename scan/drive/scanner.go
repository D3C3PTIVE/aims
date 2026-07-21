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
	// Scan runs the tool against targets (plus any extra tool arguments) and returns four
	// channels plus a launch error:
	//   - results:  Results to fold (Run.AddResult), closed when the scan ends;
	//   - progress: TaskProgress to display, closed when the scan ends;
	//   - warnings: the tool's live, non-fatal notices (nmap stderr lines such as "giving up on
	//               port ... retransmission cap hit") as they are emitted, closed when the scan ends.
	//               Best-effort and raw: classification/typing is the caller's concern (a long scan
	//               that is plainly busy should not look silent). A driver with no live notice stream
	//               returns an already-closed channel.
	//   - errc:     the scan's TERMINAL outcome — at most one value then closed. nil means the
	//               tool completed cleanly; a non-nil error is a failure the tool signalled AFTER
	//               launch (e.g. nmap "requires root privileges. QUITTING!", a resolve failure, a
	//               non-zero exit). Drain it AFTER results/progress close.
	//   - err:      a synchronous LAUNCH error (bad args, binary missing) — the scan never started,
	//               and results/progress/warnings/errc are all nil.
	//
	// Splitting launch (err) from terminal (errc) is the whole point: a tool that starts and then
	// dies mid-flight had, until now, nowhere to report that — so the run was misread as a success.
	Scan(ctx context.Context, targets []*scanpb.Target, args ...string) (
		results <-chan *scanpb.Result,
		progress <-chan *scanpb.TaskProgress,
		warnings <-chan string,
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
	<-chan *scanpb.Result, <-chan *scanpb.TaskProgress, <-chan string, <-chan error, error,
) {
	specs := scandomain.TargetSpecs(targets)
	// Reject only when there is nothing at all to scan. In raw-passthrough mode the target is
	// just another token in args (e.g. `scan run nmap -sT 127.0.0.1`), so a non-empty args set
	// is a valid invocation even with no structured Targets.
	if len(specs) == 0 && len(args) == 0 && len(n.Args) == 0 {
		return nil, nil, nil, nil, errors.New("drive: no scan targets or arguments")
	}

	// The driver owns nmap's XML output: it forces `-oX -` (XML to stdout) so it can parse the live
	// stream. A user's own `-oX <file>`/`-oA <base>` would then be a SECOND -oX and its behaviour is
	// version-dependent (last-wins here, so the user's file is silently never written). Extract the
	// user's requested XML file, drop the conflicting flag, and honour the file ourselves via
	// SaveToFile after the run — so `scan run nmap ... -oX out.xml` writes out.xml as the operator
	// expects, and aims still gets its stdout stream.
	userArgs, xmlSaveFile := extractXMLOutput(args)

	nmapArgs := make([]string, 0, len(n.Args)+len(userArgs)+len(specs))
	nmapArgs = append(nmapArgs, n.Args...)
	nmapArgs = append(nmapArgs, userArgs...)
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
		return nil, nil, nil, nil, err
	}
	// Honour the user's requested XML file: the fork writes its captured stdout XML to this path on
	// completion, so the operator's `-oX out.xml` is produced even though nmap streamed to stdout.
	if xmlSaveFile != "" {
		scanner.SaveToFile(xmlSaveFile)
	}

	// Start nmap asynchronously and consume its live host/progress streams (the fork's fixed
	// async path: YieldHosts/YieldProgress emit as nmap runs and close on completion). Each host
	// batch becomes per-host Results; progress frames pass through. The channels close when the
	// scan ends so consumers' range loops terminate.
	if err := scanner.RunAsync(); err != nil {
		return nil, nil, nil, nil, err
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

	// Forward nmap's live stderr notices as they arrive, so a long scan that is plainly busy (e.g.
	// "giving up on port ... retransmission cap hit") is not shown as silent. The fork closes its
	// channel on completion; relay through a driver-owned channel that also honours cancellation.
	warnings := make(chan string, 256)
	go func() {
		defer close(warnings)
		for w := range scanner.YieldWarnings() {
			select {
			case warnings <- w:
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

	return results, progress, warnings, errc, nil
}

// extractXMLOutput pulls a user-requested XML output file out of the raw nmap arguments so the
// driver can honour it without a double `-oX` (the driver always adds its own `-oX -` for the live
// stream). It returns the args with the conflicting XML flag removed and the file path to write:
//   - `-oX <file>`: drop both tokens, return <file>;
//   - `-oA <base>`: keep .nmap/.gnmap (rewrite to `-oN <base>.nmap -oG <base>.gnmap`, which do not
//     conflict with -oX -), drop the implied XML, and return <base>.xml.
//
// Other output flags (-oN/-oG/-oJ/-oS) target different formats than XML and coexist with -oX -, so
// they pass through untouched.
func extractXMLOutput(args []string) (cleaned []string, xmlFile string) {
	cleaned = make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-oX":
			if i+1 < len(args) {
				xmlFile = args[i+1]
				i++ // skip the filename too
			}
		case "-oA":
			if i+1 < len(args) {
				base := args[i+1]
				xmlFile = base + ".xml"
				cleaned = append(cleaned, "-oN", base+".nmap", "-oG", base+".gnmap")
				i++ // skip the base too
			}
		default:
			cleaned = append(cleaned, args[i])
		}
	}
	return cleaned, xmlFile
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
