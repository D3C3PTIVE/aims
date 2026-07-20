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
	"testing"

	hostpb "github.com/d3c3ptive/aims/host/pb"
	network "github.com/d3c3ptive/aims/network/pb"
	scanpb "github.com/d3c3ptive/aims/scan/pb"
	scanrpcpb "github.com/d3c3ptive/aims/scan/pb/rpc"
)

// seriesRun builds a finished-clean run of one definition (scanner "nmap" + the given args). A
// finished Stats block is essential: without it a freshly-persisted run's fresh UpdatedAt would read
// as a live heartbeat (running) and cleanup would leave it alone. Distinct rawXML keeps Create from
// deduping same-definition instances so they persist as a drifting series.
func seriesRun(rawXML, args string, finished int64, addr string) *scanpb.Run {
	return &scanpb.Run{
		Scanner: "nmap",
		Args:    args,
		RawXML:  rawXML,
		Stats:   &scanpb.Stats{Finished: &scanpb.Finished{Time: finished, Exit: "success"}},
		Hosts: []*hostpb.Host{{
			Addresses: []*network.Address{{Addr: addr}},
			Ports: []*hostpb.Port{{
				Number:   22,
				Protocol: "tcp",
				State:    &hostpb.State{State: "open"},
				Service:  &network.Service{Name: "ssh"},
			}},
		}},
	}
}

func readRuns(t *testing.T, s *server, ctx context.Context, f *scanrpcpb.RunFilters) []*scanpb.Run {
	t.Helper()
	res, err := s.Read(ctx, &scanrpcpb.ReadScanRequest{Scan: &scanpb.Run{}, Filters: f})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return res.GetScans()
}

// TestCleanupCollapsesSeries drives three instances of one scan definition through Cleanup and
// asserts the tombstone contract end to end: the newest is kept as head, the others are persisted as
// superseded (hidden from the default read, reachable via the SupersededBy / IncludeSuperseded
// filters), FormerRuns records the depth, the shared host survives, and a second pass is a no-op.
func TestCleanupCollapsesSeries(t *testing.T) {
	s, gdb, ctx := newTestServer(t)

	// Same args + same target host, drifting output -> one series of three instances.
	runs := []*scanpb.Run{
		seriesRun("<xml>A</xml>", "-sT -p1-100", 100, "10.0.0.1"),
		seriesRun("<xml>B</xml>", "-sT -p1-100", 200, "10.0.0.1"),
		seriesRun("<xml>C</xml>", "-sT -p1-100", 300, "10.0.0.1"), // newest -> head
	}
	if _, err := s.Create(ctx, &scanrpcpb.CreateScanRequest{Scans: runs}); err != nil {
		t.Fatalf("create series: %v", err)
	}
	if n := countRows(t, gdb, "runs"); n != 3 {
		t.Fatalf("expected 3 persisted runs, got %d", n)
	}

	// Dry run: reports the plan, writes nothing.
	dry, err := s.Cleanup(ctx, &scanrpcpb.CleanupScanRequest{DryRun: true})
	if err != nil {
		t.Fatalf("cleanup dry-run: %v", err)
	}
	if dry.GetTombstoned() != 2 || len(dry.GetHeads()) != 1 || dry.GetHeads()[0].GetFormerRuns() != 2 {
		t.Fatalf("dry plan = tombstoned %d / heads %d / former %d; want 2 / 1 / 2",
			dry.GetTombstoned(), len(dry.GetHeads()), headFormer(dry.GetHeads()))
	}
	if got := readRuns(t, s, ctx, &scanrpcpb.RunFilters{}); len(got) != 3 {
		t.Fatalf("dry-run must not tombstone anything; default read = %d, want 3", len(got))
	}

	// Capture a soon-to-be-tombstoned run's heartbeat so we can assert the tombstone write leaves it
	// untouched (a tombstone is bookkeeping, not scanner liveness).
	var beforeUpdated string
	if err := gdb.Table("runs").Where("raw_xml = ?", "<xml>A</xml>").Select("updated_at").Scan(&beforeUpdated).Error; err != nil {
		t.Fatalf("read pre-tombstone updated_at: %v", err)
	}

	// Apply.
	if _, err := s.Cleanup(ctx, &scanrpcpb.CleanupScanRequest{}); err != nil {
		t.Fatalf("cleanup apply: %v", err)
	}

	// Tombstoning must not bump the liveness heartbeat (UpdatedAt), or a stale interrupted run would
	// masquerade as running afterward.
	var afterUpdated string
	if err := gdb.Table("runs").Where("raw_xml = ?", "<xml>A</xml>").Select("updated_at").Scan(&afterUpdated).Error; err != nil {
		t.Fatalf("read post-tombstone updated_at: %v", err)
	}
	if afterUpdated != beforeUpdated {
		t.Errorf("tombstone bumped UpdatedAt (%q -> %q); it must leave the heartbeat untouched", beforeUpdated, afterUpdated)
	}

	// Default read now shows one head only, and it is the newest (rawXML C) with FormerRuns 2.
	heads := readRuns(t, s, ctx, &scanrpcpb.RunFilters{})
	if len(heads) != 1 {
		t.Fatalf("default read after cleanup = %d runs, want 1 head", len(heads))
	}
	if heads[0].GetRawXML() != "<xml>C</xml>" {
		t.Errorf("head rawXML = %q, want the newest (<xml>C</xml>)", heads[0].GetRawXML())
	}
	if heads[0].GetFormerRuns() != 2 {
		t.Errorf("head FormerRuns = %d, want 2", heads[0].GetFormerRuns())
	}
	headID := heads[0].GetId()

	// The two tombstoned siblings are reachable via the history filter and via IncludeSuperseded.
	if children := readRuns(t, s, ctx, &scanrpcpb.RunFilters{SupersededBy: headID}); len(children) != 2 {
		t.Errorf("SupersededBy(head) = %d runs, want 2 tombstoned children", len(children))
	}
	if all := readRuns(t, s, ctx, &scanrpcpb.RunFilters{IncludeSuperseded: true}); len(all) != 3 {
		t.Errorf("IncludeSuperseded read = %d runs, want all 3", len(all))
	}

	// Tombstoning kept the rows and the shared host — nothing was deleted.
	if n := countRows(t, gdb, "runs"); n != 3 {
		t.Errorf("tombstone must not delete rows; runs = %d, want 3", n)
	}
	if n := countRows(t, gdb, "hosts"); n != 1 {
		t.Errorf("hosts = %d, want the single shared host", n)
	}

	// Idempotent: a second pass over the collapsed set proposes nothing new.
	again, err := s.Cleanup(ctx, &scanrpcpb.CleanupScanRequest{})
	if err != nil {
		t.Fatalf("cleanup second pass: %v", err)
	}
	if again.GetTombstoned() != 0 {
		t.Errorf("second cleanup pass tombstoned %d, want 0 (idempotent)", again.GetTombstoned())
	}
}

// TestCleanupPruneHardDeletesByteIdentical asserts --prune hard-deletes a byte-identical re-import
// (same RawXML) instead of tombstoning it, unlinking its run_hosts share so the host survives, while
// the head's FormerRuns still records the pruned instance.
func TestCleanupPruneHardDeletesByteIdentical(t *testing.T) {
	s, gdb, ctx := newTestServer(t)

	// One run via Create, then a byte-identical twin inserted directly through persistRun (which
	// bypasses Create's dedup) so two identical-output rows coexist and share the host.
	if _, err := s.Create(ctx, &scanrpcpb.CreateScanRequest{Scans: []*scanpb.Run{seriesRun("<xml>DUP</xml>", "-sT", 100, "10.0.0.1")}}); err != nil {
		t.Fatalf("create run: %v", err)
	}
	if _, err := s.persistRun(ctx, seriesRun("<xml>DUP</xml>", "-sT", 200, "10.0.0.1")); err != nil {
		t.Fatalf("persist twin: %v", err)
	}
	if n := countRows(t, gdb, "runs"); n != 2 {
		t.Fatalf("expected 2 byte-identical runs, got %d", n)
	}
	if n := countRows(t, gdb, "hosts"); n != 1 {
		t.Fatalf("the two runs should share one host, got %d hosts", n)
	}
	if n := countRows(t, gdb, "run_hosts"); n != 2 {
		t.Fatalf("both runs should link the shared host, got %d run_hosts links", n)
	}

	report, err := s.Cleanup(ctx, &scanrpcpb.CleanupScanRequest{Prune: true})
	if err != nil {
		t.Fatalf("cleanup --prune: %v", err)
	}
	if report.GetPruned() != 1 {
		t.Fatalf("pruned = %d, want 1 byte-identical run", report.GetPruned())
	}

	// The prunable twin is gone; the head and the shared host survive.
	if n := countRows(t, gdb, "runs"); n != 1 {
		t.Errorf("runs after prune = %d, want 1 (the head)", n)
	}
	if n := countRows(t, gdb, "hosts"); n != 1 {
		t.Errorf("shared host must survive a prune; hosts = %d, want 1", n)
	}
	if n := countRows(t, gdb, "run_hosts"); n != 1 {
		t.Errorf("pruned run's host link must be removed; run_hosts = %d, want 1", n)
	}

	// The head remembers the pruned instance in its FormerRuns trace.
	heads := readRuns(t, s, ctx, &scanrpcpb.RunFilters{})
	if len(heads) != 1 || heads[0].GetFormerRuns() != 1 {
		t.Errorf("head FormerRuns = %d, want 1 (the pruned instance is still traced)", headFormer(heads))
	}
}

func headFormer(heads []*scanpb.Run) int32 {
	if len(heads) == 0 {
		return -1
	}
	return heads[0].GetFormerRuns()
}
