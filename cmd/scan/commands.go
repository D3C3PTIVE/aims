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
	"context"
	"fmt"
	"strings"

	"github.com/carapace-sh/carapace"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/d3c3ptive/aims/client"
	aims "github.com/d3c3ptive/aims/cmd"
	"github.com/d3c3ptive/aims/cmd/completers"
	"github.com/d3c3ptive/aims/cmd/display"
	"github.com/d3c3ptive/aims/cmd/export"
	"github.com/d3c3ptive/aims/scan"
	"github.com/d3c3ptive/aims/scan/ingest"
	"github.com/d3c3ptive/aims/scan/nmap"
	pb "github.com/d3c3ptive/aims/scan/pb"
	scans "github.com/d3c3ptive/aims/scan/pb/rpc"
)

// Commands returns all scan commands.
func Commands(con *client.Client) *cobra.Command {
	scanCmd := &cobra.Command{
		Use:     "scan",
		Short:   "Manage running and database scans",
		GroupID: "database",
	}

	scanCmd.AddCommand(listCommand(con))
	scanCmd.AddCommand(showCommand(con))
	scanCmd.AddCommand(rmCommand(con))
	scanCmd.AddCommand(cleanupCommand(con))
	scanCmd.AddCommand(historyCommand(con))
	scanCmd.AddCommand(runCommand(con))
	scanCmd.AddCommand(diffCommand(con))
	scanCmd.AddCommand(jobsCommand(con))
	scanCmd.AddCommand(attachCommand(con))
	scanCmd.AddCommand(stopCommand(con))
	scanCmd.AddCommand(resumeCommand(con))

	// Import
	importCmd := export.ImportCommand(scanCmd, con, importCommand(con))
	scanCmd.AddCommand(importCmd)

	aims.BindFlags(importCmd.Name(), false, importCmd, func(f *pflag.FlagSet) {
		f.BoolP("nmap", "N", false, "Hint (or force) parsing the file(s) as nmap scans (default nmap format used is xml)")
		f.String("scanner", "", "Parse the file(s) with a named ingestor (e.g. zgrab2); overrides format sniffing")
	})

	carapace.Gen(importCmd).FlagCompletion(carapace.ActionMap{
		"scanner": carapace.ActionValues(ingest.Names()...).Usage("scanner ingestor"),
	})

	carapace.Gen(importCmd).PositionalAnyCompletion(carapace.ActionFiles().Usage("scan files to import"))

	// Export
	exportCmd := export.ExportCommand(scanCmd, con, exportCommand(con))
	scanCmd.AddCommand(exportCmd)

	return scanCmd
}

// CompleteByID returns scan completions with their smallened IDs as keys. The live-DB read is
// wrapped in CacheCompletion (once, filter many); the per-invocation Filter(c.Args...) that drops
// already-selected IDs is applied OUTSIDE the cache, since the cache key is static.
func CompleteByID(client *client.Client) carapace.Action {
	cached := completers.CachedList(client, "scans:id", "scans:id", "no scans in database",
		func() ([]*pb.Run, error) {
			res, err := client.Scans.Read(context.Background(), &scans.ReadScanRequest{
				Scan:    &pb.Run{},
				Filters: &scans.RunFilters{},
			})
			return res.GetScans(), err
		},
		func(scanList []*pb.Run) carapace.Action {
			options := scan.Completions()
			options = append(options, display.WithCandidateValue("ID", ""))

			// The server's default read already returns only surviving heads — a tombstoned run is
			// browsed via `scan history`, not offered as a first-class completion target. Order them
			// like `scan list` (running first, then newest-first) so the list matches the table.
			scan.SortRuns(scanList)

			// Surface running scans as their own group above the rest: a live scan is the most likely
			// completion target (attach/stop/show it), so it should not be buried among historical
			// runs. Both slices keep the SortRuns order (newest-first within each group).
			var running, others []*pb.Run
			for _, r := range scanList {
				if scan.IsRunning(r) {
					running = append(running, r)
				} else {
					others = append(others, r)
				}
			}
			describe := func(runs []*pb.Run, tag string) carapace.Action {
				return carapace.ActionValuesDescribed(
					display.Completions(runs, scan.DisplayFields, options...)...).Tag(tag)
			}
			if len(running) == 0 {
				return describe(others, "scans")
			}
			if len(others) == 0 {
				return describe(running, "running scans")
			}
			return carapace.Batch(
				describe(running, "running scans"),
				describe(others, "scans"),
			).ToA()
		},
	)

	return completers.FilterSelected(cached)
}

// CompleteSeriesHead completes only scans that head a collapsed series (FormerRuns > 0) — the
// meaningful arguments to `scan history`, since a run with no series has nothing to browse.
func CompleteSeriesHead(client *client.Client) carapace.Action {
	cached := completers.CachedList(client, "scans:series", "scans:series", "no collapsed scan series yet",
		func() ([]*pb.Run, error) {
			res, err := client.Scans.Read(context.Background(), &scans.ReadScanRequest{
				Scan:    &pb.Run{},
				Filters: &scans.RunFilters{},
			})
			if err != nil {
				return nil, err
			}
			var heads []*pb.Run
			for _, r := range res.GetScans() {
				if r.GetFormerRuns() > 0 {
					heads = append(heads, r)
				}
			}
			return heads, nil
		},
		func(heads []*pb.Run) carapace.Action {
			scan.SortRuns(heads) // newest-first, matching the `scan list`/`scan history` table order

			options := scan.Completions()
			options = append(options, display.WithCandidateValue("ID", ""))
			results := display.Completions(heads, scan.DisplayFields, options...)

			return carapace.ActionValuesDescribed(results...).Tag("scan series")
		},
	)

	return completers.FilterSelected(cached)
}

func listCommand(con *client.Client) *cobra.Command {
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "Display hosts (with filters or styles)",
		RunE: func(command *cobra.Command, args []string) error {
			// The server hides tombstoned runs by default (a collapsed series shows only its
			// surviving head, which advertises the count it absorbed via Series); --all lifts that.
			all, _ := command.Flags().GetBool("all")
			res, err := con.Scans.Read(command.Context(), &scans.ReadScanRequest{
				Scan: &pb.Run{},
				Filters: &scans.RunFilters{
					Hosts:             true,
					IncludeSuperseded: all,
				},
			})
			err = aims.CheckError(err)
			if err != nil {
				return err
			}

			scans := res.GetScans()
			if len(scans) == 0 {
				if all {
					fmt.Printf("No scans in database.\n")
				} else {
					fmt.Printf("No scans in database (superseded runs hidden; use --all).\n")
				}
				return nil
			}

			// Order running scans first (most actionable), then by recency, before rendering.
			scan.SortRuns(scans)

			table := display.Table(scans, scan.DisplayFields, scan.DisplayHeaders()...)
			fmt.Println(table.Render())

			return nil
		},
	}

	aims.BindFlags(listCmd.Name(), false, listCmd, func(f *pflag.FlagSet) {
		f.BoolP("all", "a", false, "Include superseded (tombstoned) runs, not just series heads")
	})

	return listCmd
}

func rmCommand(con *client.Client) *cobra.Command {
	rmCmd := &cobra.Command{
		Use:   "rm",
		Short: "Remove one or more scans from the database (by ID prefix)",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			force, _ := command.Flags().GetBool("force")

			// Read every scan through the teamclient (never the DB directly), then resolve each
			// ID-prefix argument against them — the same prefix match `show` uses. Only the Id is
			// needed to delete, so hosts are left unpreloaded (a light Delete payload); the
			// unconditional Begin/Progress/Stats preloads are enough for the running-scan guard.
			// Resolve against every run, tombstoned included — `rm` is id-addressed and must be able
			// to remove a superseded run, not just a visible head.
			res, err := con.Scans.Read(command.Context(), &scans.ReadScanRequest{
				Scan:    &pb.Run{},
				Filters: &scans.RunFilters{IncludeSuperseded: true},
			})
			if err = aims.CheckError(err); err != nil {
				return err
			}

			// A mid-flight run must not be dropped out from under a live scan: deleting its row
			// would not stop the scanner (there is no cancellation path yet) and a later progress
			// write could recreate it. Skip running scans with a warning unless --force. Today no
			// running run is ever persisted, so this only bites once streaming lands (SCAN.md C).
			var matched []*pb.Run
			var skipped int
			for _, r := range res.GetScans() {
				for _, arg := range args {
					if !strings.HasPrefix(r.GetId(), aims.StripANSI(arg)) {
						continue
					}
					if scan.IsRunning(r) && !force {
						fmt.Printf("Skipping running scan %s (use --force to remove it anyway)\n",
							display.FormatSmallID(r.GetId()))
						skipped++
					} else {
						matched = append(matched, r)
					}
					break
				}
			}
			if len(matched) == 0 {
				if skipped > 0 {
					return fmt.Errorf("no scan removed (%d running scan(s) skipped; use --force)", skipped)
				}
				return fmt.Errorf("no matching scan")
			}

			del, err := con.Scans.Delete(command.Context(), &scans.DeleteScanRequest{
				Scans: matched,
			})
			if err = aims.CheckError(err); err != nil {
				return err
			}

			fmt.Printf("Removed %d scan(s).\n", len(del.GetScans()))
			return nil
		},
	}

	aims.BindFlags(rmCmd.Name(), false, rmCmd, func(f *pflag.FlagSet) {
		f.BoolP("force", "f", false, "Remove even running scans (does not stop the scanner)")
	})

	carapace.Gen(rmCmd).PositionalAnyCompletion(CompleteByID(con))

	return rmCmd
}

func cleanupCommand(con *client.Client) *cobra.Command {
	cleanupCmd := &cobra.Command{
		Use:   "cleanup",
		Short: "Collapse repeated runs of the same scan definition into one head per series",
		Long: `Collapse a scan series — repeated runs of the same definition (same scanner + args +
targets, e.g. a cron scan of the same hosts) — down to a single visible head, tombstoning the older
siblings. Tombstoning keeps the rows (and their host links) so 'scan history' and 'scan diff' still
reach every instance; only the drift-free, byte-identical re-imports are hard-deletable with --prune.

The default is a dry run: it prints the plan without changing anything. Re-run with --yes to apply.`,
		RunE: func(command *cobra.Command, args []string) error {
			prune, _ := command.Flags().GetBool("prune")
			yes, _ := command.Flags().GetBool("yes")

			res, err := con.Scans.Cleanup(command.Context(), &scans.CleanupScanRequest{
				DryRun: !yes,
				Prune:  prune,
			})
			if err = aims.CheckError(err); err != nil {
				return err
			}

			if res.GetTombstoned() == 0 && res.GetPruned() == 0 {
				fmt.Println("Nothing to clean up — every scan series already has a single head.")
				return nil
			}

			verb := "Would collapse"
			if yes {
				verb = "Collapsed"
			}
			fmt.Printf("%s %d run(s) into %d series head(s)", verb, res.GetTombstoned(), len(res.GetHeads()))
			if prune {
				fmt.Printf("; %d byte-identical run(s) %s", res.GetPruned(), pastOrFuture(yes, "pruned", "to prune"))
			}
			fmt.Println(".")
			for _, h := range res.GetHeads() {
				fmt.Printf("  head %s  %-8s  former runs: %d\n",
					display.FormatSmallID(h.GetId()), h.GetScanner(), h.GetFormerRuns())
			}
			if !yes {
				fmt.Println("\nRe-run with --yes to apply (add --prune to also hard-delete byte-identical dupes).")
			}
			return nil
		},
	}

	aims.BindFlags(cleanupCmd.Name(), false, cleanupCmd, func(f *pflag.FlagSet) {
		f.Bool("prune", false, "Hard-delete byte-identical re-imports instead of tombstoning them")
		f.BoolP("yes", "y", false, "Apply the plan (the default is a dry run)")
	})

	return cleanupCmd
}

// pastOrFuture picks the applied vs planned wording for the dry-run/apply cleanup summary.
func pastOrFuture(applied bool, past, future string) string {
	if applied {
		return past
	}
	return future
}

func historyCommand(con *client.Client) *cobra.Command {
	historyCmd := &cobra.Command{
		Use:   "history [id]",
		Short: "Show a collapsed scan series: the surviving head and every run it superseded",
		Long: `Browse the runs a 'scan cleanup' collapsed. With no argument it lists every series head
that has absorbed at least one run; given a run's ID prefix it resolves that run's series head and
shows the head together with all the (tombstoned) runs superseded under it — the instances hidden
from the default 'scan list'.`,
		RunE: func(command *cobra.Command, args []string) error {
			// Read every run (superseded included, no host tree — light) so an id argument can name ANY
			// member of a series, not just its surviving head, and still resolve to the head.
			allRes, err := con.Scans.Read(command.Context(), &scans.ReadScanRequest{
				Scan:    &pb.Run{},
				Filters: &scans.RunFilters{IncludeSuperseded: true},
			})
			if err = aims.CheckError(err); err != nil {
				return err
			}
			allRuns := allRes.GetScans()

			// No argument: list every visible head that has collapsed at least one sibling.
			if len(args) == 0 {
				var collapsed []*pb.Run
				for _, r := range scan.VisibleRuns(allRuns) {
					if r.GetFormerRuns() > 0 {
						collapsed = append(collapsed, r)
					}
				}
				if len(collapsed) == 0 {
					fmt.Println("No collapsed scan series yet (run `scan cleanup`).")
					return nil
				}
				scan.SortRuns(collapsed)
				table := display.Table(collapsed, scan.DisplayFields, scan.DisplayHeaders()...)
				fmt.Println(table.Render())
				return nil
			}

			// Argument(s): resolve each ID prefix to any run, walk to its series head, then fetch that
			// head's series WITH hosts+ports (scoped) for the drift/stability analysis.
			shown := 0
			for _, arg := range args {
				var target *pb.Run
				for _, r := range allRuns {
					if strings.HasPrefix(r.GetId(), aims.StripANSI(arg)) {
						target = r
						break
					}
				}
				if target == nil {
					continue
				}
				head := scan.HeadOf(allRuns, target)

				// Fetch the whole series WITH hosts+ports (the drift timeline and stability panel diff
				// them): the head by id, and its superseded children, both host-loaded.
				hostFilter := func(f *scans.RunFilters) *scans.RunFilters {
					f.Hosts, f.Ports = true, true
					return f
				}
				headRes, err := con.Scans.Read(command.Context(), &scans.ReadScanRequest{
					Scan:    &pb.Run{Id: head.GetId()},
					Filters: hostFilter(&scans.RunFilters{IncludeSuperseded: true}),
				})
				if err = aims.CheckError(err); err != nil {
					return err
				}
				childRes, err := con.Scans.Read(command.Context(), &scans.ReadScanRequest{
					Scan:    &pb.Run{},
					Filters: hostFilter(&scans.RunFilters{SupersededBy: head.GetId(), IncludeSuperseded: true}),
				})
				if err = aims.CheckError(err); err != nil {
					return err
				}
				series := append(headRes.GetScans(), childRes.GetScans()...)

				if shown > 0 {
					fmt.Println()
				}
				fmt.Println(renderSeriesHistory(scan.BuildHistory(series)))
				shown++
			}
			if shown == 0 {
				return fmt.Errorf("no matching series head (pass a head shown in `scan list`)")
			}
			return nil
		},
	}

	carapace.Gen(historyCmd).PositionalAnyCompletion(CompleteSeriesHead(con))

	return historyCmd
}

func showCommand(con *client.Client) *cobra.Command {
	showCmd := &cobra.Command{
		Use:   "show",
		Short: "Show one ore more scan details",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			tasks, _ := command.Flags().GetBool("tasks")
			targets, _ := command.Flags().GetBool("targets")
			showHosts, _ := command.Flags().GetBool("hosts")

			// Request (hosts + ports preloaded so the shared-host insight and --hosts section
			// have data to work with).
			res, err := con.Scans.Read(command.Context(), &scans.ReadScanRequest{
				Scan: &pb.Run{},
				Filters: &scans.RunFilters{
					Hosts:             true,
					Ports:             true,
					IncludeSuperseded: true, // `show` is id-addressed — a tombstoned run must still be viewable
				},
			})
			if err = aims.CheckError(err); err != nil {
				return err
			}

			all := res.GetScans()
			opt := scan.DetailOpts{Tasks: tasks, Targets: targets, Hosts: showHosts}

			// Display each matching run through the shared Detail renderer.
			shown := 0
			for _, r := range all {
				matched := false
				for _, arg := range args {
					if strings.HasPrefix(r.Id, aims.StripANSI(arg)) {
						matched = true
						break
					}
				}
				if !matched {
					continue
				}
				if shown > 0 {
					fmt.Println()
				}
				fmt.Println(scan.Detail(r, all, opt).Render(0))
				shown++
			}
			if shown == 0 {
				return fmt.Errorf("no matching scan")
			}

			return nil
		},
	}

	aims.BindFlags(showCmd.Name(), false, showCmd, func(f *pflag.FlagSet) {
		f.BoolP("tasks", "t", false, "Show scan task status/progress (the live view)")
		f.BoolP("targets", "T", false, "Show scan targets' details")
		f.BoolP("hosts", "H", false, "Show scanned hosts as a table")
	})

	carapace.Gen(showCmd).PositionalAnyCompletion(CompleteByID(con))

	return showCmd
}

func importCommand(con *client.Client) func(cmd *cobra.Command, arg string, data []byte) error {
	importRunE := func(command *cobra.Command, arg string, data []byte) (err error) {
		scanList, err := importScan(command, arg, data)
		if err != nil {
			return err
		}

		if len(scanList) > 0 {
			// Send the whole file's runs in one Create so the ingest fold shares a single
			// host-candidate set across every run instead of reloading the host table per run
			// (the O(runs) amplifier). Trade-off: Create is all-or-nothing, so one malformed run
			// aborts the import rather than being skipped as the old per-run loop did — chosen
			// deliberately for the shared-candidate speed win on multi-run imports.
			res, err := con.Scans.Create(command.Context(), &scans.CreateScanRequest{
				Scans: scanList,
			})
			if err = aims.CheckError(err); err != nil {
				return fmt.Errorf("import error: %w", err)
			}

			// Create returns only the runs it actually persisted; exact-duplicate re-imports are
			// silently dropped, so anything in scanList missing from the response was skipped.
			for _, saved := range res.Scans {
				fmt.Printf("Saved %s scan (%s) in database\n", saved.Scanner, display.FormatSmallID(saved.Id))
			}
			if skipped := len(scanList) - len(res.Scans); skipped > 0 {
				fmt.Printf("Skipped %d already-existing scan(s)\n", skipped)
			}
		}

		return nil
	}

	return importRunE
}

func importScan(command *cobra.Command, arg string, data []byte) ([]*pb.Run, error) {
	scanList := make([]*pb.Run, 0)

	// If a named ingestor was requested, fold the file through the scanner substrate
	// (SCAN.md Part C): any registered tool's native output — nmap XML, zgrab2 JSON, ... —
	// becomes a scan.Run that Scans.Create dedups/merges into the same objects. This takes
	// precedence over format sniffing and the --nmap hint.
	if scanner, _ := command.Flags().GetString("scanner"); scanner != "" {
		run, err := ingest.Ingest(scanner, data)
		if err != nil {
			return scanList, err
		}
		if run != nil {
			scanList = append(scanList, run)
			fmt.Printf("Importing 1 %s scan from %s\n", scanner, arg)
		}
		return scanList, nil
	}

	// If forced to parse an NMAP XML file.
	if asNmap, _ := command.Flags().GetBool("nmap"); asNmap {
		nmapScans, err := importNmap(data, arg)
		if err != nil {
			return scanList, fmt.Errorf("Nmap: %w", err)
		}
		scanList = append(scanList, nmapScans...)

	} else {
		jsonScans, err := export.ImportJSON[*pb.Run](data, arg)
		if err != nil {
			return scanList, fmt.Errorf("JSON: %w", err)
		}
		scanList = append(scanList, jsonScans...)
	}

	// and monitor the input. Notify the user on the command that we are
	// monitoring the scan file.
	return scanList, nil
}

func importNmap(data []byte, arg string) (scanList []*pb.Run, err error) {
	genericScan, err := nmap.FromXML(data)
	if err != nil || genericScan == nil {
		return nil, fmt.Errorf("Error parsing Nmap scan XML file: %w", err)
	}

	scanList = append(scanList, genericScan.ToPB())
	fmt.Printf("Importing 1 NMAP scan from %s\n", arg)

	return scanList, nil
}

func exportCommand(con *client.Client) func(cmd *cobra.Command, args []string) any {
	// If we have some data, export it according
	// to command flag specifications (format, file, etc)
	exportRunE := func(command *cobra.Command, args []string) (data any) {
		if len(args) == 0 {
			res, err := con.Scans.Read(command.Context(), &scans.ReadScanRequest{
				Scan: &pb.Run{},
				Filters: &scans.RunFilters{
					Hosts: true,
				},
			})
			err = aims.CheckError(err)
			if err != nil {
				return err
			}

			return res.GetScans()
		} else {
			res, err := con.Scans.Read(command.Context(), &scans.ReadScanRequest{
				Scan: &pb.Run{},
				Filters: &scans.RunFilters{
					Hosts: true,
					Ports: true,
				},
			})
			err = aims.CheckError(err)
			if err != nil {
				return err
			}

			scanList := []*pb.Run{}

			// Display
			for _, arg := range args {
				for _, h := range res.GetScans() {
					if strings.HasPrefix(h.Id, aims.StripANSI(arg)) {
						scanList = append(scanList, h)
					}
				}
			}
			return scanList
		}
	}

	return exportRunE
}
