package bring

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
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	scandomain "github.com/d3c3ptive/aims/scan"
)

// rawScanCaps are the file capabilities a scanner needs for raw-packet work: CAP_NET_RAW (craft/read
// raw packets — SYN/UDP/OS-detection scans), CAP_NET_ADMIN (some probe modes), CAP_NET_BIND_SERVICE
// (bind low ports). +eip = effective, inheritable, permitted, so the binary carries them itself.
const rawScanCaps = "cap_net_raw,cap_net_admin,cap_net_bind_service+eip"

// capableScanners are the scanner binaries whose raw-packet scan modes need elevated capabilities.
// masscan is included when present; a missing scanner is skipped, not an error.
var capableScanners = []string{scandomain.ScannerNmap, scandomain.ScannerMasscan}

// capsCommand returns `aims init caps`: the one-time privileged step that lets raw-packet scans
// (-sU/-sS/-sO/-O) run WITHOUT sudo on every scan or a root teamserver. It file-caps the scanner
// binaries (nmap/masscan) so the kernel grants them raw sockets directly; every `aims scan run`
// afterward is transparent. Idempotent — a binary that already has the caps is left alone.
func capsCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "caps",
		Short: "Grant scanner binaries the raw-packet capabilities their scans need (one-time, uses sudo)",
		Long: `Grant nmap (and masscan, if installed) the Linux file capabilities their raw-packet scan
modes require — SYN (-sS), UDP (-sU), IP-protocol (-sO) and OS detection (-O) all need CAP_NET_RAW,
which the kernel will not give an unprivileged process. Without this, those scans fail with "requires
root privileges. QUITTING!".

This is the one-time setup: it runs 'setcap' via sudo (a single password prompt), after which every
'aims scan run nmap -sU ...' works with no further sudo and no root teamserver. It is idempotent — a
scanner that already carries the capabilities is skipped. Re-run it after upgrading nmap/masscan, as a
package update replaces the binary and drops the capabilities.

Use --print to only show the setcap command(s) instead of running them (e.g. to apply them yourself
or in a provisioning script).`,
		Args:    cobra.NoArgs,
		PreRunE: func(*cobra.Command, []string) error { return nil }, // offline: no server connection
		RunE: func(command *cobra.Command, args []string) error {
			printOnly, _ := command.Flags().GetBool("print")
			return grantScannerCaps(command.OutOrStdout(), printOnly)
		},
	}
	cmd.Flags().Bool("print", false, "Print the setcap command(s) instead of running them")

	return cmd
}

// grantScannerCaps file-caps every installed scanner that lacks raw-packet capabilities, running
// setcap via sudo (or, with printOnly, emitting the commands). It reports what it did and is safe to
// re-run: scanners that already have the caps are skipped.
func grantScannerCaps(w io.Writer, printOnly bool) error {
	setcap, ok := lookToolPath("setcap")
	if !ok {
		return fmt.Errorf("setcap not found in $PATH or the standard sbin dirs — install libcap (Debian/Ubuntu: libcap2-bin) and re-run")
	}

	// Resolve installed scanners, skipping those that already carry the capabilities.
	var needy []string
	for _, name := range capableScanners {
		path, err := exec.LookPath(name)
		if err != nil {
			continue // not installed — nothing to cap
		}
		if hasRawCap(path) {
			fmt.Fprintf(w, "✓ %s already has raw-packet capabilities (%s)\n", name, path)
			continue
		}
		needy = append(needy, path)
	}
	if len(needy) == 0 {
		fmt.Fprintln(w, "Nothing to do — every installed scanner already has the capabilities it needs.")
		return nil
	}

	// setcap needs root. When already root (a root teamserver, or `sudo aims init caps`) run it
	// directly — no needless sudo wrapper or prompt. Otherwise go through sudo (one prompt); and if we
	// are neither root nor have sudo, fall back to printing the commands for the operator to run.
	root := os.Geteuid() == 0
	sudo, sudoErr := exec.LookPath("sudo")
	emitOnly := printOnly || (!root && sudoErr != nil)
	if !root && sudoErr != nil && !printOnly {
		fmt.Fprintln(w, "Not root and sudo not found — run the following as root:")
	}

	for _, path := range needy {
		if emitOnly {
			fmt.Fprintf(w, "%s %s %s\n", setcap, rawScanCaps, path)
			continue
		}
		var c *exec.Cmd
		if root {
			fmt.Fprintf(w, "Granting raw-packet capabilities to %s...\n", path)
			c = exec.Command(setcap, rawScanCaps, path)
		} else {
			fmt.Fprintf(w, "Granting raw-packet capabilities to %s (via sudo)...\n", path)
			c = exec.Command(sudo, setcap, rawScanCaps, path)
		}
		c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
		if err := c.Run(); err != nil {
			return fmt.Errorf("setcap on %s failed: %w (run `aims init caps --print` and apply it yourself)", path, err)
		}
	}

	if !emitOnly {
		fmt.Fprintln(w, "Done. Raw-packet scans (-sU/-sS/-sO/-O) now run without sudo or a root teamserver.")
		fmt.Fprintln(w, "Re-run `aims init caps` after upgrading a scanner — a package update drops the caps.")
	}
	return nil
}

// hasRawCap reports whether a binary already carries CAP_NET_RAW, so re-runs skip it. A missing or
// unreadable getcap is treated as "no caps" — setcap is idempotent, so re-applying is harmless.
func hasRawCap(path string) bool {
	getcap, ok := lookToolPath("getcap")
	if !ok {
		return false
	}
	out, err := exec.Command(getcap, path).Output()
	if err != nil {
		return false
	}
	return capsOutputHasRaw(string(out))
}

// lookToolPath resolves a system tool by name with a fallback to the standard sbin directories that
// are commonly absent from a non-root $PATH — setcap/getcap live in /usr/sbin (and /sbin), so a plain
// exec.LookPath fails on many desktops even when libcap is installed. It tries $PATH first, then those
// well-known sbin dirs, returning the path of the first executable found.
func lookToolPath(name string) (string, bool) {
	if p, err := exec.LookPath(name); err == nil {
		return p, true
	}
	for _, dir := range []string{"/usr/sbin", "/sbin", "/usr/local/sbin"} {
		p := filepath.Join(dir, name)
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0 {
			return p, true
		}
	}
	return "", false
}

// capsOutputHasRaw parses getcap output for CAP_NET_RAW across its format variants (e.g.
// "/usr/bin/nmap cap_net_admin,cap_net_raw=eip" on newer libcap, "/usr/bin/nmap = cap_net_raw+eip" on
// older). Empty output means no capabilities are set.
func capsOutputHasRaw(getcapOutput string) bool {
	return strings.Contains(getcapOutput, "cap_net_raw")
}
