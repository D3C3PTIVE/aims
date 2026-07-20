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
	"sort"
	"strings"

	hostpb "github.com/d3c3ptive/aims/host/pb"
	networkpb "github.com/d3c3ptive/aims/network/pb"
	scandomain "github.com/d3c3ptive/aims/scan"
	scanpb "github.com/d3c3ptive/aims/scan/pb"
)

func init() { Register(zgrabIngestor{}) }

// zgrabIngestor is the concrete demonstrator that any-JSON-tool ingestion works: it folds
// zgrab2's newline-delimited output into the shared model, hanging each module's bespoke
// result on the recursive NSE Script tree via the generic jsonToScript walker. Nothing here
// is zgrab-specific except the two-field envelope (Grab / ScanResponse); the same shape maps
// nuclei/httpx/testssl the moment their envelope is decoded, which is the whole point of
// routing structured output through jsonToScript rather than per-tool proto columns.
//
// zgrab2 is a separate, heavy module (github.com/zmap/zgrab2); we deliberately do NOT import
// it. Its output envelope is tiny and stable, so a local decode struct is all we need.
type zgrabIngestor struct{}

// zgrabGrab is one output record (one target). zgrab2 emits one JSON object per line.
type zgrabGrab struct {
	IP     string                   `json:"ip,omitempty"`
	Domain string                   `json:"domain,omitempty"`
	Data   map[string]zgrabResponse `json:"data,omitempty"`
}

// zgrabResponse is one module's result within a Grab (keyed by module name in Data). Result
// is the arbitrary per-module payload — exactly what jsonToScript is built to consume.
type zgrabResponse struct {
	Status   string `json:"status"`
	Protocol string `json:"protocol"`
	Result   any    `json:"result,omitempty"`
}

func (zgrabIngestor) Name() string { return "zgrab2" }

func (zgrabIngestor) Ingest(raw []byte) (*scanpb.Run, error) {
	run := &scandomain.Run{}
	run.Scanner = "zgrab2"
	// Record the raw output as the run's identity. zgrab has no nmap-style run metadata
	// (Start/Args/version), so without this two DIFFERENT zgrab files would collapse into one
	// run (AreScansIdentical would match on Scanner alone). RawXML is the authoritative dedup
	// key: same bytes re-imported stay idempotent, different bytes become a distinct run.
	run.RawXML = string(raw)

	// zgrab2 output is a sequence of JSON objects (one target per line). A streaming decoder
	// with UseNumber walks them regardless of the exact whitespace/newline framing and keeps
	// numbers integral so ports and counts don't drift into floats inside jsonToScript.
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	for {
		var grab zgrabGrab
		if err := dec.Decode(&grab); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		ingestGrab(run, &grab)
	}

	return run.ToPB(), nil
}

// ingestGrab folds one zgrab target record into the Run, one module at a time. Modules are
// visited in sorted order so the emitted tree is deterministic. Each module becomes an NSE
// script named "zgrab.<module>"; it lands on a Port when the module result reveals one, else
// on the host itself.
func ingestGrab(run *scandomain.Run, grab *zgrabGrab) {
	for _, module := range sortedModules(grab.Data) {
		resp := grab.Data[module]
		script := jsonToScript("zgrab."+module, resp.Result)
		ok := resp.Status == "success"

		host := &hostpb.Host{}
		if grab.Domain != "" {
			host.Hostnames = append(host.Hostnames, &hostpb.Hostname{Name: grab.Domain})
		}
		// A target that produced a zgrab record was reached over the network — assert it up,
		// carrying the reason as evidence (Part A: every assertion states fact + why).
		host.Status = &hostpb.Status{State: "up", Reason: "zgrab-response"}

		res := &scandomain.Result{
			Host:    host,
			Service: &networkpb.Service{Name: resp.Protocol},
		}
		if grab.IP != "" {
			res.Address = &networkpb.Address{Addr: grab.IP, Type: addrType(grab.IP)}
		}

		if port, hasPort := extractPort(resp.Result); hasPort {
			res.Service.Protocol = "tcp"
			res.Port = &hostpb.Port{Number: port, Protocol: "tcp", Service: res.Service}
			// A module that got a successful response proves the port open.
			if ok {
				res.Port.State = &hostpb.State{State: "open", Reason: "zgrab-response"}
			}
			res.Port.Scripts = append(res.Port.Scripts, script)
		} else {
			// No port surfaced by this module: keep the evidence at host scope rather than
			// invent a port, mirroring how nmap files hostscripts.
			host.HostScripts = append(host.HostScripts, script)
		}

		// AddResult merges into any host/port the fold already holds (SameHost/SamePort), so
		// several modules on one IP enrich a single host with several ports/scripts.
		_ = run.AddResult(res)
	}
}

// extractPort pulls a plausible TCP port out of a module result when it carries one at top
// level (the common "port" convention shared by zgrab/httpx/naabu). Absent or out-of-range,
// the caller keeps the script at host scope.
func extractPort(v any) (uint32, bool) {
	m, ok := v.(map[string]any)
	if !ok {
		return 0, false
	}
	for _, key := range []string{"port", "Port"} {
		n, ok := m[key].(json.Number)
		if !ok {
			continue
		}
		if i, err := n.Int64(); err == nil && i > 0 && i <= 65535 {
			return uint32(i), true
		}
	}
	return 0, false
}

// addrType classifies an address literal the way nmap's addrtype attribute does.
func addrType(addr string) string {
	if strings.Contains(addr, ":") {
		return "ipv6"
	}
	return "ipv4"
}

// sortedModules returns a Grab's module names in stable order for deterministic output.
func sortedModules(data map[string]zgrabResponse) []string {
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
