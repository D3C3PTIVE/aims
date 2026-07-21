package ingest

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
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"

	hostdomain "github.com/d3c3ptive/aims/host"
	hostpb "github.com/d3c3ptive/aims/host/pb"
	networkpb "github.com/d3c3ptive/aims/network/pb"
	scandomain "github.com/d3c3ptive/aims/scan"
	scanpb "github.com/d3c3ptive/aims/scan/pb"
)

func init() { Register(nucleiIngestor{}) }

// nucleiIngestor folds nuclei's JSONL findings into the shared model. nuclei is a vulnerability /
// finding scanner rather than a port scanner: each finding is filed as a severity-tagged NSE-style
// script ("nuclei.<template-id>") on the matched host/port via the generic jsonToScript walker, so
// adding it needs no new proto columns — the same schemaless-extension path zgrab uses. The whole
// finding record is preserved structurally on that script (name, severity, tags, matched-at,
// extracted-results, …); the typed fields below are only what we need to place it on the right host
// and port.
//
// The per-finding mapping lives in FindingToResult so the live driver (scan/drive/nuclei.go) folds a
// streamed finding through the exact same code — `scan import nuclei` and `scan run nuclei` produce
// byte-identical Results, mirroring how the masscan driver reuses the nmap XML parser.
type nucleiIngestor struct{}

func (nucleiIngestor) Name() string { return scandomain.ScannerNuclei }

func (nucleiIngestor) Ingest(raw []byte) (*scanpb.Run, error) {
	run := &scandomain.Run{}
	run.Scanner = scandomain.ScannerNuclei
	// Record the raw output as the run's identity (as zgrab does): nuclei has no nmap-style run
	// metadata, so without this two different finding sets would collapse into one run on Scanner
	// alone. RawXML is the authoritative dedup key — same bytes re-imported stay idempotent.
	run.RawXML = string(raw)

	// nuclei -jsonl emits one finding object per line. A streaming decoder walks them regardless of
	// framing and, crucially, has no line-length limit — an operator's own file (without the driver's
	// -omit-raw) can carry multi-KB request/response bodies per finding, which a bufio.Scanner would
	// truncate. UseNumber keeps ports/counts integral inside jsonToScript.
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	for {
		var finding map[string]any
		if err := dec.Decode(&finding); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		if res := findingToResult(finding); res != nil {
			_ = run.AddResult(res)
		}
	}

	return run.ToPB(), nil
}

// FindingToResult decodes one nuclei -jsonl finding line into a feeder Result. It is the shared entry
// point for the live driver, which reads findings line-by-line off nuclei's stdout. A blank or
// unparseable line yields (nil, false) so the caller can skip it; a decode error other than that is
// returned so a genuinely malformed stream is not silently swallowed.
func FindingToResult(line []byte) (*scandomain.Result, bool) {
	if len(bytes.TrimSpace(line)) == 0 {
		return nil, false
	}
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.UseNumber()
	var finding map[string]any
	if err := dec.Decode(&finding); err != nil {
		return nil, false
	}
	res := findingToResult(finding)
	return res, res != nil
}

// findingToResult builds the {Host, Address, Port, Service} subtree for one decoded finding and hangs
// the finding's full structure on it as an NSE script. The script lands on the matched Port when the
// finding reveals one, else at host scope (mirroring how nmap files hostscripts) — a finding is never
// discarded and a port is never invented.
func findingToResult(finding map[string]any) *scandomain.Result {
	templateID := mapString(finding, "template-id")

	host := &hostpb.Host{
		// A finding is proof the target answered over the network — assert it up, carrying the reason
		// as evidence (Part A: every assertion states fact + why).
		Status: &hostpb.Status{State: hostdomain.StateUp, Reason: "nuclei-response"},
	}
	res := &scandomain.Result{Host: host}

	// Address: nuclei resolves the target and reports the IP separately from the (possibly named)
	// host token. The IP is the identity anchor.
	ip := mapString(finding, "ip")
	if ip != "" {
		res.Address = &networkpb.Address{Addr: ip, Type: addrType(ip)}
	}
	// Hostname: the "host" field is whatever was scanned; keep it as a hostname only when it is a
	// name, not a bare IP literal (that is already the address).
	if name := nucleiHostname(finding); name != "" {
		host.Hostnames = append(host.Hostnames, &hostpb.Hostname{Name: name})
	}

	// Service name: prefer the URL scheme (http/https/…), fall back to the protocol family nuclei
	// reports as "type" (dns/tcp/ssl/…).
	svcName := mapString(finding, "scheme")
	if svcName == "" {
		svcName = mapString(finding, "type")
	}
	service := &networkpb.Service{Name: svcName}
	res.Service = service

	script := jsonToScript("nuclei."+templateID, finding)

	if port := nucleiPort(finding); port > 0 {
		service.Protocol = "tcp"
		res.Port = &hostpb.Port{
			Number:   port,
			Protocol: "tcp",
			Service:  service,
			// A finding on a port proves it open.
			State: &hostpb.State{State: hostdomain.PortOpen, Reason: "nuclei-response"},
		}
		res.Port.Scripts = append(res.Port.Scripts, script)
	} else {
		// No port surfaced (a host-scoped finding, e.g. a dns template): keep the evidence at host
		// scope rather than invent a port.
		host.HostScripts = append(host.HostScripts, script)
	}

	return res
}

// nucleiHostname returns the finding's host as a hostname, or "" when the host is absent or is a bare
// IP literal (which belongs to the address, not the hostname set). It falls back to the URL host.
func nucleiHostname(finding map[string]any) string {
	h := mapString(finding, "host")
	if h == "" {
		if u, err := url.Parse(mapString(finding, "url")); err == nil {
			h = u.Hostname()
		}
	}
	if h == "" || net.ParseIP(h) != nil {
		return ""
	}
	return h
}

// nucleiPort extracts the finding's TCP port. nuclei reports it as a string ("8000"); if absent it is
// recovered from the matched-at / url host:port. Out-of-range or missing yields 0 (host-scoped).
func nucleiPort(finding map[string]any) uint32 {
	if p := parsePort(mapString(finding, "port")); p > 0 {
		return p
	}
	for _, key := range []string{"matched-at", "url"} {
		if u, err := url.Parse(mapString(finding, key)); err == nil {
			if p := parsePort(u.Port()); p > 0 {
				return p
			}
		}
	}
	return 0
}

func parsePort(s string) uint32 {
	if s == "" {
		return 0
	}
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 || n > 65535 {
		return 0
	}
	return uint32(n)
}

// mapString reads a string field from a decoded finding, tolerating the json.Number the UseNumber
// decoder produces for any numeric value.
func mapString(m map[string]any, key string) string {
	switch v := m[key].(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	default:
		return ""
	}
}

// (addrType is shared with zgrab.go — classifies an address literal as ipv4/ipv6.)
var _ = strings.Contains
