package contribute

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

// Package contribute is the CLI front-end of the contribution facade: it turns a blob of JSON on
// stdin (or in a file) into database objects, contributed through the client/contrib facade. It
// backs two entry points over ONE fold:
//
//   - the hidden `aims _contribute <domain> --as <tool>` command — the machine contract, the
//     carapace-bridge analogue: any tool that can run a subprocess pipes objects in the same way the
//     `_carapace` command streams completions out. Exec-once, auto-connecting, kept out of help.
//   - `--as` on the visible per-domain `import` verbs — the human path (`aims hosts import --as x`).
//
// Both reduce to Objects(), which parses with export.ImportJSON and writes through contrib — so
// identity, dedup, merge, and the provenance stamp all stay in the one place they already live
// (the server-side fold, named by the facade), never re-implemented here.

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/d3c3ptive/aims/client"
	"github.com/d3c3ptive/aims/client/contrib"
	aims "github.com/d3c3ptive/aims/cmd"
	"github.com/d3c3ptive/aims/cmd/export"
	credpb "github.com/d3c3ptive/aims/credential/pb"
	hostpb "github.com/d3c3ptive/aims/host/pb"
	scanpb "github.com/d3c3ptive/aims/scan/pb"
)

// Domains lists the object classes a tool can contribute, in the spellings Objects accepts (the
// canonical singular; the plural and the CLI command name resolve to the same via normalizeDomain).
var Domains = []string{"host", "credential", "scan"}

// Objects parses data as JSON object(s) of the named domain and contributes them through the client
// facade under provenance name `source`. It returns how many objects the server actually stored —
// which can be fewer than were submitted, because the server dedups (a byte-identical re-contribution
// stores nothing). arg is a human label for the data's origin (a filename, or "stdin"), used only in
// parse-error messages.
//
// Each domain is mapped to its ENRICHING write, matching what the existing import verbs already do:
// host and credential go through Upsert (merge a re-observed object in place), scan through Add
// (Create, which folds the run's host tree and dedups the run). A contributor thus never has to know
// whether its object is new — handing it over always does the right, idempotent thing.
func Objects(ctx context.Context, con *client.Client, domain, source string, data []byte, arg string) (int, error) {
	db := contrib.New(con).As(source)

	switch normalizeDomain(domain) {
	case "host":
		objs, err := export.ImportJSON[*hostpb.Host](data, arg)
		if err != nil {
			return 0, fmt.Errorf("JSON: %w", err)
		}
		if len(objs) == 0 {
			return 0, nil
		}
		stored, err := db.Hosts.Upsert(objs...)
		return len(stored), aims.CheckError(err)

	case "credential":
		objs, err := export.ImportJSON[*credpb.Core](data, arg)
		if err != nil {
			return 0, fmt.Errorf("JSON: %w", err)
		}
		if len(objs) == 0 {
			return 0, nil
		}
		stored, err := db.Creds.Upsert(objs...)
		return len(stored), aims.CheckError(err)

	case "scan":
		objs, err := export.ImportJSON[*scanpb.Run](data, arg)
		if err != nil {
			return 0, fmt.Errorf("JSON: %w", err)
		}
		if len(objs) == 0 {
			return 0, nil
		}
		// One Add sends every run in a single Create so the ingest fold shares one host-candidate
		// set across the batch (avoiding the O(runs) reload amplifier) — the same batching the
		// scan import verb already relies on.
		stored, err := db.Scans.Add(objs...)
		return len(stored), aims.CheckError(err)

	default:
		return 0, fmt.Errorf("unknown contribution domain %q (want one of: %s)", domain, strings.Join(Domains, ", "))
	}
}

// normalizeDomain folds the accepted spellings of a domain (plural, command-name) onto the canonical
// singular Objects switches on.
func normalizeDomain(domain string) string {
	switch strings.ToLower(strings.TrimSpace(domain)) {
	case "host", "hosts":
		return "host"
	case "credential", "credentials", "cred", "creds":
		return "credential"
	case "scan", "scans", "run", "runs":
		return "scan"
	default:
		return domain
	}
}

// Command returns the hidden `_contribute` command — the machine-facing bridge ingest endpoint. A
// tool contributes by exec-ing it and piping JSON:
//
//	echo '{"addresses":[{"addr":"10.0.0.1"}]}' | aims _contribute host --as recon-x
//
// It reads every file argument, then stdin (so a pipe with no args Just Works), contributing each
// blob. Hidden because it is a wire format for other programs, not an operator command; the visible
// `import` verbs are the human equivalent. The connect pre-run bound to every leaf command has
// already connected `con` by the time RunE fires.
func Command(con *client.Client) *cobra.Command {
	contributeCmd := &cobra.Command{
		Use:    "_contribute <domain> [files...]",
		Short:  "Contribute objects to the database from JSON (stdin or files)",
		Args:   cobra.MinimumNArgs(1),
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			domain := args[0]
			files := args[1:]
			source, _ := cmd.Flags().GetString("as")
			if source == "" {
				source = os.Getenv("AIMS_TOOL") // env fallback for pipelines that can't pass a flag
			}

			total := 0
			for _, path := range files {
				data, err := os.ReadFile(path)
				if err != nil {
					return fmt.Errorf("read %s: %w", path, err)
				}
				n, err := Objects(cmd.Context(), con, domain, source, data, path)
				if err != nil {
					return err
				}
				total += n
			}

			// Read stdin when it is piped (not a terminal), so `... | aims _contribute host` needs no
			// flag. With no file args and a terminal stdin, there is simply nothing to contribute.
			if hasPipedStdin() {
				data, err := io.ReadAll(os.Stdin)
				if err != nil && err != io.EOF {
					return fmt.Errorf("read stdin: %w", err)
				}
				if len(strings.TrimSpace(string(data))) > 0 {
					n, err := Objects(cmd.Context(), con, domain, source, data, "stdin")
					if err != nil {
						return err
					}
					total += n
				}
			}

			fmt.Fprintf(cmd.OutOrStdout(), "%d\n", total) // machine-readable: stored-object count
			return nil
		},
	}

	aims.BindFlags(contributeCmd.Name(), false, contributeCmd, func(f *pflag.FlagSet) {
		f.String("as", "", "provenance name to attribute the contributed objects to (else $AIMS_TOOL)")
	})

	return contributeCmd
}

// ImportRunE returns the file/stdin handler an `import` verb hands to export.ImportCommand for the
// given domain: it contributes each blob through Objects, reading the provenance name from the verb's
// `--as` flag (which BindImportFlags registers). This is the human path sharing the machine path's
// fold. It prints a short per-source summary rather than the raw count the hidden command emits.
func ImportRunE(con *client.Client, domain string) func(cmd *cobra.Command, arg string, data []byte) error {
	return func(cmd *cobra.Command, arg string, data []byte) error {
		source, _ := cmd.Flags().GetString("as")
		if source == "" {
			source = os.Getenv("AIMS_TOOL")
		}
		n, err := Objects(cmd.Context(), con, domain, source, data, arg)
		if err != nil {
			return err
		}
		aims.InvalidateCompletionCache() // the object set changed: next Tab re-queries
		attributed := ""
		if source != "" {
			attributed = fmt.Sprintf(" as %q", source)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Contributed %d %s(s)%s from %s.\n", n, normalizeDomain(domain), attributed, arg)
		return nil
	}
}

// hasPipedStdin reports whether stdin is a pipe/redirect (data to read) rather than an interactive
// terminal — so the hidden command reads piped input automatically but never blocks on a TTY.
func hasPipedStdin() bool {
	info, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) == 0
}
