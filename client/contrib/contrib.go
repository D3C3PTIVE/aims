package contrib

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

// Package contrib is the client-side contribution facade: the "drop one line to add a host, a
// credential, a scan" surface an offensive-security tool reaches for instead of managing its own
// database, filling out request structs, or learning the object model.
//
// The design principle is deliberate thinness. AIMS's *server* already owns identity, dedup, merge,
// and provenance — the host ingest fold (host.IngestHosts), the credential merge, the scan
// host-unification. A contributor must be able to hand an object over and TRUST that re-adding the
// same host enriches rather than duplicates, that a service already seen by nmap merges with the one
// zgrab just found, that provenance is recorded. So this package builds no logic of its own: every
// verb is a request-builder + one RPC over an existing service, plus a single provenance stamp so a
// later `--source <tool>` read returns exactly what this tool put in.
//
// The one handle a tool holds is a Session. It is transport-agnostic by construction: today it wraps
// a linked *client.Client (a gRPC teamclient), and the seam is drawn so a future exec bridge — route
// each contribution by shelling into a detected local `aims _contribute` (the carapace-bridge
// analogue, running the completion machinery backwards) — can back the same call sites without a
// contributor noticing. See CONTRIBUTE.md for that roadmap.

import (
	"context"
	"errors"

	"github.com/gofrs/uuid"

	"github.com/d3c3ptive/aims/client"
	credpb "github.com/d3c3ptive/aims/credential/pb"
	credrpc "github.com/d3c3ptive/aims/credential/pb/rpc"
	hostpb "github.com/d3c3ptive/aims/host/pb"
	hostrpc "github.com/d3c3ptive/aims/host/pb/rpc"
	provpb "github.com/d3c3ptive/aims/provenance/pb"
	scanpb "github.com/d3c3ptive/aims/scan/pb"
	scanrpc "github.com/d3c3ptive/aims/scan/pb/rpc"
)

// Session is a contributing tool's handle on an AIMS database. Obtain it once from a connected
// client, optionally name the tool with As, then contribute through the per-domain verbs — each an
// Add (additive + dedup), an Upsert (merge in place), and reads that trust the same server-side
// identity the writes rely on.
type Session struct {
	con  *client.Client
	tool string

	// Hosts contributes hosts (and, through their ports, services). Creds contributes credentials.
	// Scans contributes whole scan runs (their host trees fold through the same unification the
	// nmap driver uses). Value receivers reading s.tool live see any later As(...).
	Hosts HostContrib
	Creds CredContrib
	Scans ScanContrib
}

// New returns a contribution Session over an already-connected AIMS client. It performs no I/O; the
// first RPC happens on the first Add/Upsert/List. Use it when the program already holds a client (a
// console, a test harness); use Dial when it does not and wants one bootstrapped from good defaults.
func New(con *client.Client) *Session {
	s := &Session{con: con}
	s.Hosts = HostContrib{s: s}
	s.Creds = CredContrib{s: s}
	s.Scans = ScanContrib{s: s}
	return s
}

// Dial is the one-call bootstrap: it stands up an AIMS teamclient, connects it to the operator's
// existing `aims` server, and returns a ready contribution Session — the whole "call the library
// once and start contributing" path. It is DELIBERATELY zero-configuration: the server is discovered
// from the current user's system teamclient config (client.DefaultConfig / the team API's on-disk
// config), so a contributing tool requires no flag, env var, or config file of its own — it inherits
// whatever connection the operator already set up. When no system config exists there is nothing to
// contribute to, and Dial returns an error saying so rather than hanging or silently doing nothing.
//
// The default send/receive path is thus a pure, in-code teamclient connection — never an exec of the
// `aims` binary. (The exec bridge is a fallback for programs that cannot link this client at all; it
// never preempts a live teamclient.) The returned Session owns the connection; Close it when done.
func Dial() (*Session, error) {
	con, err := client.New()
	if err != nil {
		return nil, err
	}

	cfg, ok := con.DefaultConfig()
	if !ok {
		return nil, errors.New("contrib: no system teamclient config found for 'aims' — import one " +
			"(e.g. `aims teamserver client import <file>`) so tools can discover the server")
	}
	con.SetServerConfig(cfg)

	if err := con.Connect(); err != nil {
		return nil, err
	}
	return New(con), nil
}

// Close tears down the Session's connection. It is meant for a Session obtained from Dial (which owns
// its client); calling it on a New(con) Session also disconnects that shared client, so only Close
// what you Dialed.
func (s *Session) Close() error {
	if s.con == nil {
		return nil
	}
	return s.con.Disconnect()
}

// As names the contributing tool. Every object contributed afterwards is stamped with a provenance
// Source carrying this name, so the tool's work is attributable and a later
// `... --source <tool>` read (provenance.WhereContributedBy) returns exactly what it put in. Empty
// tool (the default) contributes without a provenance stamp. Returns the Session for chaining:
//
//	db := contrib.New(con).As("recon-x")
//	db.Hosts.Add(host)
func (s *Session) As(tool string) *Session {
	s.tool = tool
	return s
}

// Tool reports the provenance name set by As (empty if unset).
func (s *Session) Tool() string { return s.tool }

//
// [ Hosts ] --------------------------------------------------------------
//

// HostContrib is the host contribution surface. A host carries its own ports and, on each port, a
// service — so contributing a host contributes its services too, folded by the server.
type HostContrib struct{ s *Session }

// Add contributes hosts additively: the server skips any that are byte-for-byte a host it already
// holds (SameHost) and merges new evidence into the rest, so re-adding the same recon output never
// duplicates rows. Returns the stored hosts (ids and merged state filled in).
func (h HostContrib) Add(hosts ...*hostpb.Host) ([]*hostpb.Host, error) {
	stampHosts(hosts, h.s.tool)
	res, err := h.s.con.Hosts.Create(context.Background(), &hostrpc.CreateHostRequest{Hosts: hosts})
	if err != nil {
		return nil, err
	}
	return res.GetHosts(), nil
}

// Upsert contributes hosts through the merge path: each is unified with the stored host of the same
// identity (field-class merge — fill-only scalars, unioned collections), enriching it in place.
func (h HostContrib) Upsert(hosts ...*hostpb.Host) ([]*hostpb.Host, error) {
	stampHosts(hosts, h.s.tool)
	res, err := h.s.con.Hosts.Upsert(context.Background(), &hostrpc.UpsertHostRequest{Hosts: hosts})
	if err != nil {
		return nil, err
	}
	return res.GetHosts(), nil
}

// List returns the hosts matching filter (nil filter = every host). It reads through the same
// service the CLI uses, so results reflect all contributors, not just this one.
func (h HostContrib) List(filter *hostpb.Host) ([]*hostpb.Host, error) {
	if filter == nil {
		filter = &hostpb.Host{}
	}
	// The host service exposes no List RPC — Read returns every match by default (a single-object
	// read is just a Read with an id-bearing filter), so List reads through Read.
	res, err := h.s.con.Hosts.Read(context.Background(), &hostrpc.ReadHostRequest{Host: filter})
	if err != nil {
		return nil, err
	}
	return res.GetHosts(), nil
}

//
// [ Credentials ] --------------------------------------------------------
//

// CredContrib is the credential contribution surface.
type CredContrib struct{ s *Session }

// Add contributes credentials additively (server-side dedup by credential identity).
func (c CredContrib) Add(creds ...*credpb.Core) ([]*credpb.Core, error) {
	stampCreds(creds, c.s.tool)
	res, err := c.s.con.Creds.Create(context.Background(), &credrpc.CreateCredentialRequest{Credentials: creds})
	if err != nil {
		return nil, err
	}
	return res.GetCredentials(), nil
}

// Upsert contributes credentials through the merge path (enrich a known credential in place).
func (c CredContrib) Upsert(creds ...*credpb.Core) ([]*credpb.Core, error) {
	stampCreds(creds, c.s.tool)
	res, err := c.s.con.Creds.Upsert(context.Background(), &credrpc.UpsertCredentialRequest{Credentials: creds})
	if err != nil {
		return nil, err
	}
	return res.GetCredentials(), nil
}

// List returns the credentials matching filter (nil filter = every credential).
func (c CredContrib) List(filter *credpb.Core) ([]*credpb.Core, error) {
	if filter == nil {
		filter = &credpb.Core{}
	}
	res, err := c.s.con.Creds.List(context.Background(), &credrpc.ReadCredentialRequest{Credential: filter})
	if err != nil {
		return nil, err
	}
	return res.GetCredentials(), nil
}

//
// [ Scans ] --------------------------------------------------------------
//

// ScanContrib is the scan-run contribution surface: hand AIMS a whole run (however the tool built
// it) and its host tree folds through the same unification the live nmap driver uses.
type ScanContrib struct{ s *Session }

// Add contributes scan runs. Provenance rides the run's Scanner field (the server stamps every host,
// address, port, and service the run produced from it), so As(tool) fills an unset Scanner rather
// than stamping Sources directly — matching how server-side scans record their producer.
func (sc ScanContrib) Add(runs ...*scanpb.Run) ([]*scanpb.Run, error) {
	stampRuns(runs, sc.s.tool)
	res, err := sc.s.con.Scans.Create(context.Background(), &scanrpc.CreateScanRequest{Scans: runs})
	if err != nil {
		return nil, err
	}
	return res.GetScans(), nil
}

// Upsert contributes scan runs idempotently (insert-or-return-existing by run identity).
func (sc ScanContrib) Upsert(runs ...*scanpb.Run) ([]*scanpb.Run, error) {
	stampRuns(runs, sc.s.tool)
	res, err := sc.s.con.Scans.Upsert(context.Background(), &scanrpc.UpsertScanRequest{Scans: runs})
	if err != nil {
		return nil, err
	}
	return res.GetScans(), nil
}

// List returns the scan runs matching filter (nil filter = every surviving run).
func (sc ScanContrib) List(filter *scanpb.Run) ([]*scanpb.Run, error) {
	if filter == nil {
		filter = &scanpb.Run{}
	}
	res, err := sc.s.con.Scans.List(context.Background(), &scanrpc.ReadScanRequest{Scan: filter})
	if err != nil {
		return nil, err
	}
	return res.GetScans(), nil
}

//
// [ Provenance stamping ] ------------------------------------------------
//

// stampHosts hangs one provenance Source (naming tool) on each host and — mirroring the server-side
// scan stamp — on its addresses, ports, and port services, so a `--source tool` read reaches every
// object the contribution produced, not just the host root. Host Create does not auto-stamp (unlike
// the scan path), so the client owns this. A shared, pre-assigned Source Id per host means the row
// is written once (the m2m insert is OnConflict-DoNothing) and every child references it. Empty tool
// is a no-op.
func stampHosts(hosts []*hostpb.Host, tool string) {
	if tool == "" {
		return
	}
	for _, h := range hosts {
		if h == nil {
			continue
		}
		src := &provpb.Source{
			Id:   uuid.Must(uuid.NewV4()).String(),
			Tool: tool,
			Type: provpb.SourceType_Import,
		}
		h.Sources = append(h.Sources, src)
		for _, a := range h.GetAddresses() {
			if a != nil {
				a.Sources = append(a.Sources, src)
			}
		}
		for _, p := range h.GetPorts() {
			if p == nil {
				continue
			}
			p.Sources = append(p.Sources, src)
			if p.Service != nil {
				p.Service.Sources = append(p.Service.Sources, src)
			}
		}
	}
}

// stampCreds hangs one provenance Source (naming tool) on each credential. Empty tool is a no-op.
func stampCreds(creds []*credpb.Core, tool string) {
	if tool == "" {
		return
	}
	for _, c := range creds {
		if c == nil {
			continue
		}
		c.Sources = append(c.Sources, &provpb.Source{Tool: tool, Type: provpb.SourceType_Import})
	}
}

// stampRuns records the contributing tool as a run's Scanner when the caller left it unset — the
// scan server derives every produced object's provenance from Scanner, so this is the scan-domain
// equivalent of a Sources stamp. A run that already names its scanner is left untouched. No-op on
// empty tool.
func stampRuns(runs []*scanpb.Run, tool string) {
	if tool == "" {
		return
	}
	for _, r := range runs {
		if r != nil && r.GetScanner() == "" {
			r.Scanner = tool
		}
	}
}
