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

// This file implements server-side scan jobs and their streaming (SCAN.md Part C, Phase 4). A
// scan runs on the teamserver so it outlives the operator's terminal and is visible to every
// operator: the job owns its own cancellable context (independent of any client stream), folds
// hosts as they arrive, fans RunUpdate frames out to the foreground stream and any later Attach
// streams, and persists the completed run through the same fold as Create (host unification via
// host.IngestHosts). Blocking vs. detached is purely a client presentation choice over the one
// server-side job.

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/gofrs/uuid"

	hostpb "github.com/d3c3ptive/aims/host/pb"
	"github.com/d3c3ptive/aims/scan"
	"github.com/d3c3ptive/aims/scan/drive"
	scanpb "github.com/d3c3ptive/aims/scan/pb"
	scanrpcpb "github.com/d3c3ptive/aims/scan/pb/rpc"
)

// updateStream is the part of the generated Run/Attach server streams this file needs, so one
// forward loop serves both RPCs.
type updateStream interface {
	Send(*scanrpcpb.RunUpdate) error
	Context() context.Context
}

// scanJob is one running (or recently finished) server-side scan. It fans RunUpdate frames out
// to any number of subscribers and replays the terminal frame to subscribers that attach late.
type scanJob struct {
	id      string
	scanner string
	args    []string
	targets []*scanpb.Target
	started int64

	cancel context.CancelFunc

	mu    sync.Mutex
	subs  map[chan *scanrpcpb.RunUpdate]struct{}
	done  bool
	final *scanrpcpb.RunUpdate // terminal frame (Final or Error), replayed to late subscribers
}

func newScanJob(req *scanrpcpb.RunScanRequest, id string, cancel context.CancelFunc, started int64) *scanJob {
	return &scanJob{
		id:      id,
		scanner: req.GetScanner(),
		args:    req.GetArgs(),
		targets: req.GetTargets(),
		started: started,
		cancel:  cancel,
		subs:    make(map[chan *scanrpcpb.RunUpdate]struct{}),
	}
}

// subscribe registers a stream consumer. If the job already finished, the terminal frame is
// delivered immediately and the channel closed, so a late Attach still gets the result.
func (j *scanJob) subscribe() chan *scanrpcpb.RunUpdate {
	ch := make(chan *scanrpcpb.RunUpdate, 256)
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.done {
		if j.final != nil {
			ch <- j.final
		}
		close(ch)
		return ch
	}
	j.subs[ch] = struct{}{}
	return ch
}

func (j *scanJob) unsubscribe(ch chan *scanrpcpb.RunUpdate) {
	j.mu.Lock()
	defer j.mu.Unlock()
	delete(j.subs, ch)
}

// broadcast fans a frame out to all current subscribers. A subscriber whose buffer is full is
// skipped for that frame rather than stalling the whole job — live progress is best-effort.
func (j *scanJob) broadcast(u *scanrpcpb.RunUpdate) {
	j.mu.Lock()
	defer j.mu.Unlock()
	for ch := range j.subs {
		select {
		case ch <- u:
		default:
		}
	}
}

// finish records the terminal frame, delivers it to all subscribers, closes their channels, and
// marks the job done so future subscribers get the replay.
func (j *scanJob) finish(u *scanrpcpb.RunUpdate) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.done = true
	j.final = u
	for ch := range j.subs {
		select {
		case ch <- u:
		default:
		}
		close(ch)
	}
	j.subs = make(map[chan *scanrpcpb.RunUpdate]struct{})
}

func (j *scanJob) isDone() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.done
}

func (s *server) addJob(j *scanJob)   { s.jobsMu.Lock(); s.jobs[j.id] = j; s.jobsMu.Unlock() }
func (s *server) removeJob(id string) { s.jobsMu.Lock(); delete(s.jobs, id); s.jobsMu.Unlock() }
func (s *server) getJob(id string) *scanJob {
	s.jobsMu.Lock()
	defer s.jobsMu.Unlock()
	return s.jobs[id]
}

// Run executes a scanner server-side against the request's targets and streams RunUpdate frames.
// The job runs under its own context so it survives the client detaching (Ctrl-C on a foreground
// scan just stops forwarding — the scan keeps running); Stop cancels it explicitly.
func (s *server) Run(req *scanrpcpb.RunScanRequest, stream scanrpcpb.Scans_RunServer) error {
	scanner, err := scannerFor(req.GetScanner())
	if err != nil {
		return err
	}

	jobCtx, cancel := context.WithCancel(context.Background())
	id := uuid.Must(uuid.NewV4()).String()
	job := newScanJob(req, id, cancel, time.Now().Unix())
	s.addJob(job)

	results, progress, err := scanner.Scan(jobCtx, req.GetTargets(), req.GetArgs()...)
	if err != nil {
		cancel()
		s.removeJob(id)
		return err
	}

	// Consume the scan independently of any client: fold + broadcast + persist on completion.
	go s.consume(job, results, progress)

	// First frame is the job id, so a foreground client can print it (and Ctrl-C to detach).
	if err := stream.Send(jobIDUpdate(id)); err != nil {
		return err
	}
	if req.GetBackground() {
		return nil // detached: the job keeps running server-side
	}

	return s.forward(stream, job)
}

// forward subscribes to a job and relays its frames to the client until the job finishes or the
// client disconnects (detach — the job keeps running).
func (s *server) forward(stream updateStream, job *scanJob) error {
	sub := job.subscribe()
	defer job.unsubscribe(sub)

	ctx := stream.Context()
	for {
		select {
		case <-ctx.Done():
			return nil // client detached; job continues server-side
		case u, ok := <-sub:
			if !ok {
				return nil // job finished (terminal frame already forwarded)
			}
			if err := stream.Send(u); err != nil {
				return err
			}
		}
	}
}

// consume drains the scanner's result/progress channels, folding hosts into a Run and
// broadcasting each host/progress frame live, then persists the completed run through the same
// host-unifying fold as Create and broadcasts the stored run as the terminal Final frame.
func (s *server) consume(job *scanJob, results <-chan *scanpb.Result, progress <-chan *scanpb.TaskProgress) {
	run := &scan.Run{}
	run.Scanner = job.scanner
	// Carry the invocation onto the persisted run so `scan list`/`show` (and a cross-process
	// `scan jobs`) reflect what is running, not a bare scanner name. Args is the joined command; the
	// structured Targets (present on a --from-db scan; empty when targets ride inside Args) get stable
	// Ids up front so re-persisting the snapshot each heartbeat is idempotent — BeforeCreate only mints
	// when Id=="", so pre-assigning avoids inserting duplicate target rows on every tick.
	run.Args = strings.Join(job.args, " ")
	for _, t := range job.targets {
		if t.GetId() == "" {
			t.Id = uuid.Must(uuid.NewV4()).String()
		}
	}
	run.Targets = job.targets

	// snapshot upserts the accumulating run under the JOB id, so `scan show <job-id>` and
	// `watch scan show` reflect live state as hosts arrive (persistRun upserts by Id — see
	// scan.go). Snapshots skip provenance stamping (done once at the final persist so the Source
	// rows aren't re-minted each tick) and are throttled so a fast scan doesn't hammer the DB.
	snapshot := func() {
		pbRun := run.ToPB()
		pbRun.Id = job.id
		pbRun.Scanner = job.scanner
		_, _ = s.persistRun(context.Background(), pbRun)
	}

	// Persist an initial snapshot immediately so the run is visible as soon as it starts.
	snapshot()

	// Heartbeat: re-snapshot on a fixed interval regardless of frame arrival. Each snapshot upserts
	// the run (bumping UpdatedAt), which is the liveness signal stateOf reads — so a live scan stays
	// "running" even through quiet phases (a single-host scan emits its host only at the end), and a
	// scan whose owning process is killed stops heartbeating and is judged "interrupted" once the
	// timestamp goes stale (see scan.runStaleAfter). Kept well below that staleness bound.
	beat := time.NewTicker(5 * time.Second)
	defer beat.Stop()

	for results != nil || progress != nil {
		select {
		case r, ok := <-results:
			if !ok {
				results = nil
				continue
			}
			_ = run.AddResult((*scan.Result)(r))
			if r.GetHost() != nil {
				job.broadcast(hostUpdate(r.GetHost()))
				snapshot() // a new host is worth persisting immediately (live `scan show`)
			}
		case p, ok := <-progress:
			if !ok {
				progress = nil
				continue
			}
			if p != nil {
				job.broadcast(progressUpdate(p))
			}
		case <-beat.C:
			snapshot()
		}
	}

	// Final persist (fresh context so a cancelled/Stopped scan still saves its partial results):
	// stamp provenance once, then upsert the authoritative stored run under the same job Id.
	// Mark it finished so stateOf reads "done" (a streamed run carries no nmap runstats, so
	// without this the completed run would linger as "queued"). Set once, on the final write.
	pbRun := run.ToPB()
	pbRun.Id = job.id
	pbRun.Scanner = job.scanner
	now := time.Now().Unix()
	pbRun.Stats = &scanpb.Stats{Finished: &scanpb.Finished{
		Time:    now,
		Exit:    "success",
		Elapsed: float32(now - job.started), // measured duration, so the Info column can show it
	}}
	stampScanProvenance(pbRun)

	stored, err := s.persistRun(context.Background(), pbRun)
	if err != nil {
		job.finish(errorUpdate(err.Error()))
		return
	}
	// A completed scan supersedes older runs of the same definition, so `scan list` self-collapses.
	s.autoSupersede(context.Background(), stored.GetId())
	job.finish(finalUpdate(stored))
}

// Jobs lists the scans currently running. It reports this process's in-memory jobs AND — because the
// all-in-one binary boots a fresh ephemeral teamserver per command, so a scan running in another
// process is absent from this registry — every run the shared DB shows as running (fresh heartbeat).
// That makes `scan jobs`/`attach` see a foreground scan started in a different terminal, not just
// jobs owned by the current process.
func (s *server) Jobs(ctx context.Context, req *scanrpcpb.JobsRequest) (*scanrpcpb.JobsResponse, error) {
	s.jobsMu.Lock()
	seen := map[string]bool{}
	var jobs []*scanrpcpb.ScanJob
	for _, j := range s.jobs {
		if j.isDone() {
			continue
		}
		seen[j.id] = true
		jobs = append(jobs, &scanrpcpb.ScanJob{
			Id:        j.id,
			Scanner:   j.scanner,
			Args:      j.args,
			StartedAt: j.started,
			Targets:   j.targets,
		})
	}
	s.jobsMu.Unlock()

	// Cross-process running scans, surfaced from the shared DB (stateOf judges liveness by heartbeat).
	dbRuns, err := s.loadRuns(ctx)
	if err != nil {
		return nil, err
	}
	for _, r := range dbRuns {
		if seen[r.GetId()] || !scan.IsRunning(r) {
			continue
		}
		jobs = append(jobs, &scanrpcpb.ScanJob{
			Id:        r.GetId(),
			Scanner:   r.GetScanner(),
			Args:      strings.Fields(r.GetArgs()),
			StartedAt: startedAt(r),
			Targets:   r.GetTargets(),
		})
	}
	return &scanrpcpb.JobsResponse{Jobs: jobs}, nil
}

// Attach re-subscribes to a running (or just-finished) job's stream. If the job is not in this
// process's registry it may be a scan running in another aims process; fall back to streaming its
// persisted state from the shared DB (hosts as they appear, then the terminal run) by polling.
func (s *server) Attach(req *scanrpcpb.AttachRequest, stream scanrpcpb.Scans_AttachServer) error {
	if job := s.getJob(req.GetJobId()); job != nil {
		return s.forward(stream, job)
	}
	return s.attachFromDB(stream.Context(), req.GetJobId(), stream)
}

// attachFromDB streams a cross-process run's live state from the DB: it emits each newly-observed
// host as the owning process persists it, then the terminal run once the run stops being running
// (finished, or heartbeat-stale/interrupted). Progress frames are not available — the snapshot does
// not persist the task stream — so this is a coarser view than an in-process attach (host-level, not
// a live progress bar), but it works across processes with no shared server.
func (s *server) attachFromDB(ctx context.Context, id string, stream updateStream) error {
	sent := map[string]bool{}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	// An initial job-id frame so the client's live view renders its header immediately (the poll
	// loop below then feeds it hosts) rather than showing a blank screen until the first host lands.
	if err := stream.Send(jobIDUpdate(id)); err != nil {
		return err
	}

	for {
		run, err := s.readRun(ctx, id)
		if err != nil {
			return err
		}
		if run == nil {
			return fmt.Errorf("no scan job %q", id)
		}
		for _, h := range run.GetHosts() {
			if hid := h.GetId(); hid != "" {
				if sent[hid] {
					continue
				}
				sent[hid] = true
			}
			if err := stream.Send(hostUpdate(h)); err != nil {
				return err
			}
		}
		if !scan.IsRunning(run) {
			return stream.Send(finalUpdate(run)) // finished or interrupted: terminal frame
		}
		select {
		case <-ctx.Done():
			return nil // client detached
		case <-ticker.C:
		}
	}
}

// startedAt is a run's best start timestamp for the jobs list: its explicit Start, else its creation.
func startedAt(r *scanpb.Run) int64 {
	if r.GetStart() != 0 {
		return r.GetStart()
	}
	if ts := r.GetCreatedAt(); ts != nil {
		return ts.AsTime().Unix()
	}
	return 0
}

// Stop cancels a running job, killing its scanner process. The partial results already gathered
// are still persisted (consume persists under a background context).
func (s *server) Stop(ctx context.Context, req *scanrpcpb.StopRequest) (*scanrpcpb.StopResponse, error) {
	job := s.getJob(req.GetJobId())
	if job == nil {
		return &scanrpcpb.StopResponse{JobId: req.GetJobId(), Stopped: false}, nil
	}
	job.cancel()
	return &scanrpcpb.StopResponse{JobId: req.GetJobId(), Stopped: true}, nil
}

// scannerFor resolves a scanner name to its server-side driver. nmap and masscan are wired; the
// switch is the extension point for naabu/… drivers.
func scannerFor(name string) (drive.Scanner, error) {
	switch name {
	case "nmap", "":
		return drive.Nmap{}, nil
	case "masscan":
		return drive.Masscan{}, nil
	default:
		return nil, fmt.Errorf("unknown scanner %q (known: nmap, masscan)", name)
	}
}

func jobIDUpdate(id string) *scanrpcpb.RunUpdate {
	return &scanrpcpb.RunUpdate{Update: &scanrpcpb.RunUpdate_JobId{JobId: id}}
}

func progressUpdate(p *scanpb.TaskProgress) *scanrpcpb.RunUpdate {
	return &scanrpcpb.RunUpdate{Update: &scanrpcpb.RunUpdate_Progress{Progress: p}}
}

func hostUpdate(h *hostpb.Host) *scanrpcpb.RunUpdate {
	return &scanrpcpb.RunUpdate{Update: &scanrpcpb.RunUpdate_Host{Host: h}}
}

func finalUpdate(r *scanpb.Run) *scanrpcpb.RunUpdate {
	return &scanrpcpb.RunUpdate{Update: &scanrpcpb.RunUpdate_Final{Final: r}}
}

func errorUpdate(msg string) *scanrpcpb.RunUpdate {
	return &scanrpcpb.RunUpdate{Update: &scanrpcpb.RunUpdate_Error{Error: msg}}
}
