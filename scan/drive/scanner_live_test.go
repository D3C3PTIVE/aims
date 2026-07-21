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

// TestNmapScanLive drives real nmap against localhost and asserts the fixed async streaming
// path (nmap fork RunAsync/YieldHosts/YieldProgress + Wait): both channels must CLOSE (the crux
// of the fork fix — previously the yield goroutines never terminated) and at least one host
// result must arrive. If the fix regressed, the drain loops would block and the test would hang
// until the deadline. Guarded like run_integration_test: set AIMS_NMAP_IT=1 (needs nmap).
func TestNmapScanLive(t *testing.T) {
	if os.Getenv("AIMS_NMAP_IT") == "" {
		t.Skip("set AIMS_NMAP_IT=1 to run (requires the nmap binary)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	results, progress, warnings, errc, err := (Nmap{Args: []string{"-sT", "-p", "22,80,443"}}).
		Scan(ctx, []*scan.Target{{Address: "127.0.0.1"}})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	go func() {
		for range warnings { // drain live notices so the channel is consumed
		}
	}()

	hosts := 0
	frames := 0
	closed := make(chan string, 2)
	go func() {
		for range progress {
			frames++
		}
		closed <- "progress"
	}()
	go func() {
		for r := range results {
			if r.GetHost() != nil {
				hosts++
			}
		}
		closed <- "results"
	}()

	// Both channels must close (goroutines return) — this is what proves the streams terminate.
	<-closed
	<-closed

	if hosts == 0 {
		t.Error("expected at least one host result from 127.0.0.1")
	}

	// The terminal outcome: a -sT (connect) scan of localhost needs no privileges, so errc must
	// carry a nil error (a clean completion), and it must be closed after the single value.
	if scanErr := <-errc; scanErr != nil {
		t.Errorf("errc reported a failure for a clean -sT localhost scan: %v", scanErr)
	}
	if _, ok := <-errc; ok {
		t.Error("errc must deliver at most one value then close")
	}
	t.Logf("streamed %d host batch(es), %d progress frame(s); both channels closed, errc clean", hosts, frames)
}

// TestNmapScanLiveUDP proves the whole raw-packet privilege chain end to end: a -sU (UDP) scan needs
// CAP_NET_RAW, which nmap ignores unless NMAP_PRIVILEGED=1 is set — and the driver sets it (via the
// fork's WithCustomEnv) exactly when nmapPrivileged detects the cap. So on a host where nmap carries
// the cap (as `aims init caps` grants), an unprivileged -sU scan must complete with a NIL terminal
// error rather than the "requires root privileges. QUITTING!" failure. Guarded by AIMS_NMAP_IT=1 and
// requires nmap to actually be capped (or the process root); otherwise errc correctly reports the
// privilege failure and this test is not applicable.
func TestNmapScanLiveUDP(t *testing.T) {
	if os.Getenv("AIMS_NMAP_IT") == "" {
		t.Skip("set AIMS_NMAP_IT=1 to run (requires nmap with CAP_NET_RAW, e.g. `aims init caps`)")
	}
	if !nmapPrivileged("") {
		t.Skip("nmap is not capability-privileged here (run `aims init caps`); -sU cannot run")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	results, progress, warnings, errc, err := (Nmap{Args: []string{"-sU", "-p", "53,123"}}).
		Scan(ctx, []*scan.Target{{Address: "127.0.0.1"}})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	go func() {
		for range warnings { // drain live notices so the channel is consumed
		}
	}()

	hosts := 0
	done := make(chan struct{}, 2)
	go func() {
		for range progress {
		}
		done <- struct{}{}
	}()
	go func() {
		for r := range results {
			if r.GetHost() != nil {
				hosts++
			}
		}
		done <- struct{}{}
	}()
	<-done
	<-done

	// The payoff: a -sU scan that would have died with "requires root privileges" now completes clean.
	if scanErr := <-errc; scanErr != nil {
		t.Fatalf("UDP scan reported a terminal error (privilege chain broken?): %v", scanErr)
	}
	if hosts == 0 {
		t.Error("expected at least one host result from a -sU scan of 127.0.0.1")
	}
}

// TestNmapDriverHonorsOutputFile is the end-to-end proof for the -oX handling (#2b): driving nmap
// through the driver with a raw `-oX <file>` must (a) still stream results (the driver's own -oX -
// wins the live stream) AND (b) write the operator's requested file with the scan XML — which the
// old double-oX silently dropped. Guarded (needs nmap).
func TestNmapDriverHonorsOutputFile(t *testing.T) {
	if os.Getenv("AIMS_NMAP_IT") == "" {
		t.Skip("set AIMS_NMAP_IT=1 to run (requires the nmap binary)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	out := t.TempDir() + "/operator.xml"
	results, progress, warnings, errc, err := (Nmap{}).Scan(ctx,
		[]*scan.Target{{Address: "127.0.0.1"}}, "-sT", "-p", "22,80", "-oX", out)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	go func() {
		for range progress {
		}
	}()
	go func() {
		for range warnings {
		}
	}()
	hosts := 0
	for r := range results {
		if r.GetHost() != nil {
			hosts++
		}
	}
	if scanErr := <-errc; scanErr != nil {
		t.Fatalf("errc: %v", scanErr)
	}
	if hosts == 0 {
		t.Error("expected a streamed host from 127.0.0.1 (driver's -oX - must still feed the stream)")
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("operator's -oX file was not written: %v", err)
	}
	if !strings.Contains(string(data), "<nmaprun") {
		t.Errorf("operator's -oX file lacks nmap XML:\n%s", string(data))
	}
}
