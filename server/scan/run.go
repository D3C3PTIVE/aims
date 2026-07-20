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

	ctx    context.Context // the job's own context; ctx.Err() != nil means it was Stopped (cancelled)
	cancel context.CancelFunc

	mu    sync.Mutex
	subs  map[chan *scanrpcpb.RunUpdate]struct{}
	done  bool
	final *scanrpcpb.RunUpdate // terminal frame (Final or Error), replayed to late subscribers
}

func newScanJob(req *scanrpcpb.RunScanRequest, id string, ctx context.Context, cancel context.CancelFunc, started int64) *scanJob {
	return &scanJob{
		id:      id,
		scanner: req.GetScanner(),
		args:    req.GetArgs(),
		targets: req.GetTargets(),
		started: started,
		ctx:     ctx,
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
	job := newScanJob(req, id, jobCtx, cancel, time.Now().Unix())
	s.addJob(job)

	results, progress, errc, err := scanner.Scan(jobCtx, req.GetTargets(), req.GetArgs()...)
	if err != nil {
		cancel()
		s.removeJob(id)
		return err
	}

	// Consume the scan independently of any client: fold + broadcast + persist on completion.
	go s.consume(job, results, progress, errc)

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
func (s *server) consume(job *scanJob, results <-chan *scanpb.Result, progress <-chan *scanpb.TaskProgress, errc <-chan error) {
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
	// rows aren't re-minted each tick). lastPersist gates the throttled progress path so a chatty
	// scanner doesn't hammer the DB with a write per progress frame.
	var lastPersist time.Time
	snapshot := func() {
		pbRun := run.ToPB()
		pbRun.Id = job.id
		pbRun.Scanner = job.scanner
		_, _ = s.persistRun(context.Background(), pbRun)
		lastPersist = time.Now()
	}

	// setProgress folds a live progress frame into the run's Progress relation, keyed by task name so
	// a task's climbing percent updates one row rather than appending a row per tick. The row carries
	// a stable Id (minted once) so persistRun's column-scoped upsert refreshes it in place — which is
	// what lets a cross-process `scan attach`/`scan show` render a live progress bar from the DB.
	progressByTask := map[string]*scanpb.TaskProgress{}
	setProgress := func(p *scanpb.TaskProgress) {
		if cur := progressByTask[p.GetTask()]; cur != nil {
			cur.Percent, cur.Remaining, cur.Etc, cur.Time = p.GetPercent(), p.GetRemaining(), p.GetEtc(), p.GetTime()
		} else {
			if p.GetId() == "" {
				p.Id = uuid.Must(uuid.NewV4()).String()
			}
			progressByTask[p.GetTask()] = p
		}
		run.Progress = make([]*scanpb.TaskProgress, 0, len(progressByTask))
		for _, tp := range progressByTask {
			run.Progress = append(run.Progress, tp)
		}
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
				setProgress(p)
				job.broadcast(progressUpdate(p))
				// Persist the advancing progress so a cross-process attach/`scan show` sees it, but
				// throttled — the 5s heartbeat backstops it, so at most ~1 progress write per second.
				if time.Since(lastPersist) > time.Second {
					snapshot()
				}
			}
		case <-beat.C:
			snapshot()
		}
	}

	// The scanner's terminal outcome, drained now that both the result and progress channels have
	// closed. errc delivers exactly one value (nil == clean completion) then closes; a nil channel
	// (a caller that supplies none — e.g. a unit test exercising only interrupt/clean paths) simply
	// yields no error and the outcome falls to interrupted-or-success.
	var scanErr error
	if errc != nil {
		scanErr = <-errc
	}

	// Final persist (fresh context so a cancelled/Stopped scan still saves its partial results):
	// stamp provenance once, then upsert the authoritative stored run under the same job Id. Mark it
	// finished so stateOf reads a terminal state (a streamed run carries no nmap runstats, so without
	// this the completed run would linger as "queued"). Set once, on the final write.
	//
	// Terminal state, in precedence order interrupted > failed > success:
	//   - interrupted: the job's context was cancelled (a Stop). This wins even when the killed
	//     scanner also reports an exit error ("signal: killed") — a deliberate stop is not a failure.
	//     Stamped Exit=ExitInterrupted so it reads as "interrupted" (terminal, resumable), not a false
	//     "done"; the hosts it gathered are kept.
	//   - failed: the scanner signalled a real error AFTER launching (nmap "requires root privileges.
	//     QUITTING!", a resolve failure, a non-zero exit — surfaced via the driver's WaitResult).
	//     Stamped Exit="error" with the reason so stateOf reads stateFailed and the run shows
	//     "✗ <reason>" instead of a false "✓ done" over zero hosts.
	//   - success: a clean completion.
	//
	// The live progress rows persist for every outcome (persistRun is additive), so an interrupted or
	// failed run's `scan show` still shows how far each task got; a cleanly-finished run simply doesn't
	// surface them as "running" tasks (see scan.getTasks, which drops them once terminal).
	interrupted := job.ctx.Err() != nil
	now := time.Now().Unix()
	fin := &scanpb.Finished{
		Time:    now,
		Elapsed: float32(now - job.started), // measured duration, so the Info column can show it
	}
	switch {
	case interrupted:
		fin.Exit = scan.ExitInterrupted
	case scanErr != nil:
		fin.Exit = "error"
		fin.ErrorMsg = scanErr.Error()
	default:
		fin.Exit = "success"
	}

	pbRun := run.ToPB()
	pbRun.Id = job.id
	pbRun.Scanner = job.scanner
	pbRun.Stats = &scanpb.Stats{Finished: fin}
	stampScanProvenance(pbRun)

	stored, err := s.persistRun(context.Background(), pbRun)
	if err != nil {
		job.finish(errorUpdate(err.Error()))
		return
	}
	// Only a clean completion collapses older runs of the same definition, so `scan list`
	// self-collapses. A failed OR interrupted run is NOT collapsed: an interrupted (partial) run must
	// stay visible as its own row so an operator can find and `scan resume` it, and a failed run has
	// no results and must never tombstone a sibling's fuller, good history.
	if !interrupted && scanErr == nil {
		s.autoSupersede(context.Background(), stored.GetId())
	}
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

// attachFromDB streams a cross-process run's live state from the DB: it emits the persisted progress
// as it advances and each newly-observed host as the owning process persists it, then the terminal
// run once the run stops being running (finished, or heartbeat-stale/interrupted). The owning process
// snapshots its progress rows to the DB (see consume), so a DB-attach renders the same live progress
// bar as an in-process attach — only coarser in cadence (poll-driven, ~1s) since the two processes
// share no in-memory stream.
func (s *server) attachFromDB(ctx context.Context, id string, stream updateStream) error {
	sent := map[string]bool{}
	sentPct := map[string]float32{}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	// An initial job-id frame so the client's live view renders its header immediately (the poll
	// loop below then feeds it progress + hosts) rather than a blank screen until the first host.
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
		// Progress: emit a frame for each task whose percent advanced since we last sent it, so the
		// client's progress bar tracks the DB-persisted state.
		for _, p := range run.GetProgress() {
			if last, ok := sentPct[p.GetTask()]; ok && p.GetPercent() <= last {
				continue
			}
			sentPct[p.GetTask()] = p.GetPercent()
			if err := stream.Send(progressUpdate(p)); err != nil {
				return err
			}
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
