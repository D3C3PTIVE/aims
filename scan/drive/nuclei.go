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
	"encoding/json"
	"errors"
	"os/exec"
	"strconv"
	"strings"

	scandomain "github.com/d3c3ptive/aims/scan"
	"github.com/d3c3ptive/aims/scan/ingest"
	scanpb "github.com/d3c3ptive/aims/scan/pb"
)

// Nuclei drives the nuclei vulnerability scanner (github.com/projectdiscovery/nuclei). Unlike masscan
// (which writes XML only at completion), nuclei streams one JSON finding per line to stdout as it
// runs, so this driver emits Results LIVE — each finding folds into the host tree while the scan is
// still going, the same shape as the nmap driver's live host stream but from a plain exec (no fork).
//
// Each finding is mapped by ingest.FindingToResult — the exact same code the nuclei Ingestor uses for
// `scan import` — so a streamed scan and an imported file fold byte-identically (as the masscan driver
// reuses the nmap XML parser). nuclei is a finding scanner, not a port scanner: results enrich
// existing hosts with severity-tagged NSE-style evidence rather than discovering new hosts.
type Nuclei struct {
	// Args are nuclei arguments placed before the target specs (e.g. "-severity", "high").
	Args []string
	// BinaryPath overrides the nuclei binary location; empty uses $PATH.
	BinaryPath string
}

// nucleiForcedFlags are injected on every run for a reliable, headless, lean stream:
//   - -jsonl              findings as JSONL to stdout (the live Result stream this driver parses)
//   - -disable-update-check  skip nuclei's startup update-check network call
//   - -no-color           plain output (no ANSI in the JSON/stderr we parse)
//   - -omit-raw -omit-template  drop the multi-KB request/response bodies and base64 template from each
//                         finding, keeping stored evidence lean (the structured finding is preserved)
//   - -stats -stats-json -stats-interval 1  emit progress as JSON on stderr, one tick per second
//
// NOTE: interactsh (OOB) is intentionally left ENABLED — an operator may want OAST templates; without
// it nuclei still exits cleanly offline (OAST templates simply do not match). Also: the FIRST nuclei
// run on a host builds a ~13k-template metadata cache (~60-90s, one-time) — this looks like a hang but
// is not per-scan, so the driver relies on ctx cancellation, never a hard deadline.
var nucleiForcedFlags = []string{
	"-jsonl",
	"-disable-update-check",
	"-no-color",
	"-omit-raw",
	"-omit-template",
	"-stats", "-stats-json", "-stats-interval", "1",
}

func (n Nuclei) Scan(ctx context.Context, targets []*scanpb.Target, args ...string) (
	<-chan *scanpb.Result, <-chan *scanpb.TaskProgress, <-chan string, <-chan error, error,
) {
	specs := scandomain.TargetSpecs(targets)
	// Reject only when there is nothing at all to scan; in raw-passthrough mode a target is just
	// another token in args (e.g. `scan run nuclei -u example.com -t http/cves`).
	if len(specs) == 0 && len(args) == 0 && len(n.Args) == 0 {
		return nil, nil, nil, nil, errors.New("drive: no scan targets or arguments")
	}

	binary := n.BinaryPath
	if binary == "" {
		binary = scandomain.ScannerNuclei
	}

	// Assemble args: forced flags first, then the caller's flags with output-redirect and duplicate
	// forced flags removed (a user `-o file`/`-jsonl-export file` would steal findings off stdout and
	// silence the live stream), then targets as `-u <spec>` — nuclei takes URLs/hosts via -u.
	userArgs := sanitizeNucleiArgs(append(append([]string{}, n.Args...), args...))
	scanArgs := make([]string, 0, len(nucleiForcedFlags)+len(userArgs)+2*len(specs))
	scanArgs = append(scanArgs, nucleiForcedFlags...)
	scanArgs = append(scanArgs, userArgs...)
	for _, spec := range specs {
		scanArgs = append(scanArgs, "-u", spec)
	}

	cmd := exec.CommandContext(ctx, binary, scanArgs...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, nil, nil, nil, err
	}

	results := make(chan *scanpb.Result)
	progress := make(chan *scanpb.TaskProgress)
	warnings := make(chan string, 256)
	errc := make(chan error, 1)
	stdoutDone := make(chan struct{})
	stderrDone := make(chan struct{})

	// Findings: one JSON object per stdout line, parsed live into Results through the SAME mapping the
	// ingestor uses. The buffer is enlarged because a finding can be large if an operator disabled the
	// forced -omit-raw upstream; the default 64K scanner cap would truncate and drop it.
	go func() {
		defer close(results)
		defer close(stdoutDone)
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		for sc.Scan() {
			res, ok := ingest.FindingToResult(sc.Bytes())
			if !ok {
				continue
			}
			select {
			case results <- res.ToPB():
			case <-ctx.Done():
				return
			}
		}
	}()

	// Progress + warnings: nuclei's stderr carries the -stats-json ticks (JSON with a "percent" field)
	// and its human log lines. A stats line becomes a TaskProgress; a genuine notice ([WRN]/[ERR]/[FTL]
	// or a bare non-log line) is forwarded as a live warning. Routine [INF]/[VER] banner noise is
	// dropped so the dashboard's notice area stays signal, not spam.
	go func() {
		defer close(progress)
		defer close(warnings)
		defer close(stderrDone)
		sc := bufio.NewScanner(stderr)
		sc.Buffer(make([]byte, 0, 64*1024), 1*1024*1024)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			if tp := nucleiProgress(line); tp != nil {
				select {
				case progress <- tp:
				case <-ctx.Done():
					return
				}
				continue
			}
			if w := nucleiWarning(line); w != "" {
				select {
				case warnings <- w:
				case <-ctx.Done():
					return
				default: // never stall the scan on a slow warnings consumer
				}
			}
		}
	}()

	// Terminal outcome: wait for both pipes to drain (the StdoutPipe/StderrPipe contract forbids Wait
	// before the pipes are read), then reap. A non-zero exit is a real failure (bad args, missing
	// binary surfaced late) reported on errc — so a failed nuclei run reads as failed, not as a clean
	// empty success, the same discipline as the nmap/masscan drivers.
	go func() {
		defer close(errc)
		<-stdoutDone
		<-stderrDone
		errc <- cmd.Wait()
	}()

	return results, progress, warnings, errc, nil
}

// nucleiProgress parses a -stats-json stderr tick into a TaskProgress, or nil when the line is not a
// stats object. nuclei encodes every stat value as a STRING (e.g. "percent":"20"), so the percent is
// parsed from a string, not a JSON number.
func nucleiProgress(line string) *scanpb.TaskProgress {
	if !strings.HasPrefix(line, "{") {
		return nil
	}
	var stats map[string]any
	if err := json.Unmarshal([]byte(line), &stats); err != nil {
		return nil
	}
	raw, ok := stats["percent"]
	if !ok {
		return nil
	}
	pct := 0.0
	switch v := raw.(type) {
	case string:
		pct, _ = strconv.ParseFloat(v, 64)
	case float64:
		pct = v
	}
	return &scanpb.TaskProgress{Task: scandomain.ScannerNuclei, Percent: float32(pct)}
}

// nucleiWarning returns the line to forward as a live notice, or "" to drop it. nuclei's stderr is
// noisy with routine [INF]/[VER] banner lines; only real warnings/errors ([WRN]/[ERR]/[FTL]/[FATAL])
// and non-log lines are worth surfacing to the operator.
func nucleiWarning(line string) string {
	switch {
	case strings.Contains(line, "[INF]"), strings.Contains(line, "[VER]"), strings.Contains(line, "[DBG]"):
		return ""
	default:
		return line
	}
}

// sanitizeNucleiArgs drops output-redirect flags that would divert findings off stdout (silencing the
// live stream) and any duplicates of the flags the driver already forces. Value-taking output flags
// consume their following token too.
func sanitizeNucleiArgs(args []string) []string {
	// Flags that redirect findings away from stdout: drop the flag AND its value.
	valueDrops := map[string]bool{
		"-o": true, "-output": true,
		"-je": true, "-jsonl-export": true, "-jle": true, "-json-export": true,
	}
	// Boolean flags the driver already forces: drop the bare flag (a duplicate is harmless to nuclei
	// but keeps our argv clean and predictable).
	boolDrops := map[string]bool{
		"-jsonl": true, "-j": true,
		"-disable-update-check": true, "-duc": true,
		"-no-color": true, "-nc": true,
		"-omit-raw": true, "-or": true, "-omit-template": true, "-ot": true,
		"-stats": true, "-stats-json": true, "-sj": true,
	}
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		switch {
		case valueDrops[args[i]]:
			i++ // skip the value token too
		case boolDrops[args[i]]:
			// drop the bare flag
		default:
			out = append(out, args[i])
		}
	}
	return out
}
