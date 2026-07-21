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
	"context"
	"os"
	"strings"
	"testing"
	"time"

	scan "github.com/d3c3ptive/aims/scan/pb"
)

// Nuclei must satisfy the Scanner interface.
var _ Scanner = Nuclei{}

// TestNucleiScanNoTargets asserts the empty-invocation guard fires before any exec.
func TestNucleiScanNoTargets(t *testing.T) {
	if _, _, _, _, err := (Nuclei{}).Scan(context.Background(), nil); err == nil {
		t.Error("Scan with no targets or args should error")
	}
	if _, _, _, _, err := (Nuclei{}).Scan(context.Background(), []*scan.Target{{}}); err == nil {
		t.Error("Scan with only empty targets should error")
	}
}

// TestNucleiProgress covers the -stats-json parse: every nuclei stat value is a STRING, so percent
// must be read from "20" not 20. Non-stats lines yield no progress.
func TestNucleiProgress(t *testing.T) {
	line := `{"duration":"0:00:01","matched":"0","percent":"37","requests":"3","total":"10"}`
	tp := nucleiProgress(line)
	if tp == nil {
		t.Fatalf("expected a progress frame from a stats line")
	}
	if tp.Percent < 36.9 || tp.Percent > 37.1 {
		t.Errorf("percent = %v, want ~37", tp.Percent)
	}
	if tp.Task != "nuclei" {
		t.Errorf("task = %q, want nuclei", tp.Task)
	}
	if nucleiProgress("[INF] Templates loaded for current scan: 1") != nil {
		t.Error("a log line must not parse as progress")
	}
	if nucleiProgress(`{"no":"percent"}`) != nil {
		t.Error("a JSON object without percent must not parse as progress")
	}
}

// TestNucleiWarning covers stderr classification: real notices are forwarded, banner noise dropped.
func TestNucleiWarning(t *testing.T) {
	drop := []string{
		"[INF] Templates loaded for current scan: 1",
		"[VER] Started metrics server at localhost:9092",
		"[DBG] something verbose",
	}
	for _, l := range drop {
		if nucleiWarning(l) != "" {
			t.Errorf("line %q should be dropped", l)
		}
	}
	keep := []string{
		"[WRN] Loading 1 unsigned templates for scan.",
		"[ERR] could not resolve host",
		"[FTL] fatal thing",
		"some bare stderr line",
	}
	for _, l := range keep {
		if nucleiWarning(l) != l {
			t.Errorf("line %q should be forwarded as a warning", l)
		}
	}
}

// TestSanitizeNucleiArgs proves output-redirect flags (which would steal findings off stdout and
// silence the live stream) and duplicate forced flags are dropped, while real args pass through.
func TestSanitizeNucleiArgs(t *testing.T) {
	in := []string{
		"-severity", "high", // real, passes through (value kept)
		"-o", "out.jsonl", // output redirect → dropped with its value
		"-jsonl",              // duplicate forced bool → dropped
		"-jsonl-export", "x.j", // export redirect → dropped with its value
		"-tags", "cve", // real, passes through
		"-duc", // duplicate forced bool → dropped
	}
	got := strings.Join(sanitizeNucleiArgs(in), " ")
	want := "-severity high -tags cve"
	if got != want {
		t.Errorf("sanitized = %q, want %q", got, want)
	}
}

// TestNucleiScanLive drives real nuclei against a local target and asserts the live streaming path:
// both display channels must CLOSE and errc must deliver a clean terminal outcome. It needs the nuclei
// binary and a reachable http service; guarded by AIMS_NUCLEI_IT=1 and AIMS_NUCLEI_TARGET (a URL the
// operator is authorized to scan, e.g. a local http server). Note the ~60-90s first-run template
// cache build, hence the generous timeout.
func TestNucleiScanLive(t *testing.T) {
	if os.Getenv("AIMS_NUCLEI_IT") == "" {
		t.Skip("set AIMS_NUCLEI_IT=1 to run (requires the nuclei binary)")
	}
	target := os.Getenv("AIMS_NUCLEI_TARGET")
	if target == "" {
		t.Skip("set AIMS_NUCLEI_TARGET to a URL you are authorized to scan")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()

	// A broad, fast template set so at least one finding is likely (tech detection almost always fires).
	results, progress, warnings, errc, err := (Nuclei{Args: []string{"-t", "http/technologies/"}}).
		Scan(ctx, []*scan.Target{{Address: target}})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	go func() {
		for range warnings {
		}
	}()

	closed := make(chan string, 2)
	findings := 0
	go func() {
		for range progress {
		}
		closed <- "progress"
	}()
	go func() {
		for range results {
			findings++
		}
		closed <- "results"
	}()

	<-closed
	<-closed

	if scanErr := <-errc; scanErr != nil {
		t.Errorf("errc reported a failure for a nuclei scan of %s: %v", target, scanErr)
	}
	t.Logf("streamed %d finding(s); channels closed, errc clean", findings)
}
