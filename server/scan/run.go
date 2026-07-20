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

func (s *server) addJob(j *scanJob)          { s.jobsMu.Lock(); s.jobs[j.id] = j; s.jobsMu.Unlock() }
func (s *server) removeJob(id string)         { s.jobsMu.Lock(); delete(s.jobs, id); s.jobsMu.Unlock() }
func (s *server) getJob(id string) *scanJob   { s.jobsMu.Lock(); defer s.jobsMu.Unlock(); return s.jobs[id] }

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
			}
		case p, ok := <-progress:
			if !ok {
				progress = nil
				continue
			}
			if p != nil {
				job.broadcast(progressUpdate(p))
			}
		}
	}

	// Persist under a fresh context so a cancelled (Stop) scan still saves the partial results it
	// found. stampScanProvenance + persistRun are the exact Create path (host unification).
	pbRun := run.ToPB()
	pbRun.Scanner = job.scanner
	stampScanProvenance(pbRun)

	stored, err := s.persistRun(context.Background(), pbRun)
	if err != nil {
		job.finish(errorUpdate(err.Error()))
		return
	}
	job.finish(finalUpdate(stored))
}

// Jobs lists the scans currently running server-side (finished jobs are kept briefly for late
// Attach replay but are not reported as running).
func (s *server) Jobs(ctx context.Context, req *scanrpcpb.JobsRequest) (*scanrpcpb.JobsResponse, error) {
	s.jobsMu.Lock()
	defer s.jobsMu.Unlock()

	var jobs []*scanrpcpb.ScanJob
	for _, j := range s.jobs {
		if j.isDone() {
			continue
		}
		jobs = append(jobs, &scanrpcpb.ScanJob{
			Id:        j.id,
			Scanner:   j.scanner,
			Args:      j.args,
			StartedAt: j.started,
			Targets:   j.targets,
		})
	}
	return &scanrpcpb.JobsResponse{Jobs: jobs}, nil
}

// Attach re-subscribes to a running (or just-finished) job's stream.
func (s *server) Attach(req *scanrpcpb.AttachRequest, stream scanrpcpb.Scans_AttachServer) error {
	job := s.getJob(req.GetJobId())
	if job == nil {
		return fmt.Errorf("no scan job %q", req.GetJobId())
	}
	return s.forward(stream, job)
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

// scannerFor resolves a scanner name to its server-side driver. Only nmap is wired today; the
// switch is the extension point for masscan/naabu/… drivers.
func scannerFor(name string) (drive.Scanner, error) {
	switch name {
	case "nmap", "":
		return drive.Nmap{}, nil
	default:
		return nil, fmt.Errorf("unknown scanner %q (only nmap is supported)", name)
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
