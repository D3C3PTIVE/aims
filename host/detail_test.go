package host

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
	"strings"
	"testing"

	"github.com/d3c3ptive/aims/cmd/display"
	"github.com/d3c3ptive/aims/host/pb"
	networkpb "github.com/d3c3ptive/aims/network/pb"
)

// openPort is a small builder for an open port with a named service.
func openPort(num uint32, proto, svc string) *pb.Port {
	return &pb.Port{
		Number:   num,
		Protocol: proto,
		State:    &pb.State{State: "open"},
		Service:  &networkpb.Service{Name: svc},
	}
}

func TestHostLabel(t *testing.T) {
	tests := []struct {
		name string
		host *pb.Host
		want string
	}{
		{
			"hostname preferred",
			&pb.Host{
				Hostnames: []*pb.Hostname{{Name: "web01"}},
				Addresses: []*networkpb.Address{{Addr: "10.0.0.5"}},
			},
			"web01",
		},
		{
			"address when no hostname",
			&pb.Host{Addresses: []*networkpb.Address{{Addr: "10.0.0.5"}}},
			"10.0.0.5",
		},
		{
			"short id as last resort",
			&pb.Host{Id: "aaaaaaaa-1111-4aaa-8aaa-web0100000001"},
			display.FormatSmallID("aaaaaaaa-1111-4aaa-8aaa-web0100000001"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hostLabel(tt.host); got != tt.want {
				t.Errorf("hostLabel() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestOpenPorts confirms only ports in the "open" state are surfaced.
func TestOpenPorts(t *testing.T) {
	h := &pb.Host{Ports: []*pb.Port{
		openPort(22, "tcp", "ssh"),
		{Number: 25, Protocol: "tcp", State: &pb.State{State: "filtered"}},
		{Number: 3389, Protocol: "tcp"}, // no state
		openPort(443, "tcp", "https"),
	}}
	if got := len(openPorts(h)); got != 2 {
		t.Fatalf("openPorts() returned %d ports, want 2 (only the open ones)", got)
	}
}

// TestCleartextServices covers detection by service name and by well-known port number, and that
// results are de-duplicated and drawn only from open ports.
func TestCleartextServices(t *testing.T) {
	h := &pb.Host{Ports: []*pb.Port{
		openPort(23, "tcp", ""),                                          // telnet by number
		openPort(8080, "tcp", "http"),                                    // http by name
		openPort(80, "tcp", "http"),                                      // duplicate http — must collapse
		openPort(443, "tcp", "https"),                                    // encrypted — excluded
		{Number: 21, Protocol: "tcp", State: &pb.State{State: "closed"}}, // closed ftp — excluded
	}}

	got := cleartextServices(h)
	want := map[string]bool{"telnet": true, "http": true}
	if len(got) != len(want) {
		t.Fatalf("cleartextServices() = %v, want keys %v", got, want)
	}
	for _, name := range got {
		if !want[name] {
			t.Errorf("cleartextServices() returned unexpected %q", name)
		}
	}
}

func TestOSConfidence(t *testing.T) {
	tests := []struct {
		name        string
		host        *pb.Host
		wantPct     int
		wantGuessed bool
	}{
		{"authoritative OSName is not a guess", &pb.Host{OSName: "Linux"}, 0, false},
		{"no OS data", &pb.Host{}, 0, false},
		{
			"sub-100 match is a guess",
			&pb.Host{OS: &pb.OS{Matches: []*pb.OSMatch{{Accuracy: 88}, {Accuracy: 95}}}},
			95, true,
		},
		{
			"perfect match is not a guess",
			&pb.Host{OS: &pb.OS{Matches: []*pb.OSMatch{{Accuracy: 100}}}},
			100, false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pct, guessed := osConfidence(tt.host)
			if pct != tt.wantPct || guessed != tt.wantGuessed {
				t.Errorf("osConfidence() = (%d, %v), want (%d, %v)", pct, guessed, tt.wantPct, tt.wantGuessed)
			}
		})
	}
}

func TestUptimeLabel(t *testing.T) {
	tests := []struct {
		name string
		up   *pb.Uptime
		want string
	}{
		{"nil uptime", nil, ""},
		{"days and hours", &pb.Uptime{Seconds: 90061}, "1d 1h"}, // 1d 1h 1m 1s
		{"hours only", &pb.Uptime{Seconds: 7200}, "2h"},
		{"lastboot fallback", &pb.Uptime{LastBoot: "Mon Jul 20 09:00"}, "Mon Jul 20 09:00"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := uptimeLabel(&pb.Host{Uptime: tt.up}); got != tt.want {
				t.Errorf("uptimeLabel() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestSectionsRouteGating proves the Open Ports section always appears when ports are open, while
// the Route section appears only when showRoute is set (it can be long).
func TestSectionsRouteGating(t *testing.T) {
	h := &pb.Host{
		Ports: []*pb.Port{openPort(22, "tcp", "ssh")},
		Trace: &networkpb.Trace{Hops: []*networkpb.Hop{
			{IPAddr: "10.0.0.1", Host: "gw01", RTT: "1ms"},
			{IPAddr: "10.0.0.9", RTT: "2ms"},
		}},
	}

	titles := func(showRoute bool) []string {
		var out []string
		for _, s := range sections(h, showRoute) {
			out = append(out, s.Title)
		}
		return out
	}

	if got := titles(false); !contains(got, "Open Ports") || contains(got, "Route") {
		t.Errorf("sections(showRoute=false) = %v, want Open Ports and no Route", got)
	}
	if got := titles(true); !contains(got, "Open Ports") || !contains(got, "Route") {
		t.Errorf("sections(showRoute=true) = %v, want both Open Ports and Route", got)
	}
}

// TestDetailRenderSmoke renders a representative host and checks the assembled view (ANSI-stripped)
// carries the banner identity, an insight for its cleartext service, and its open-ports section —
// proving the pieces reach the shared renderer.
func TestDetailRenderSmoke(t *testing.T) {
	h := &pb.Host{
		Id:        "aaaaaaaa-1111-4aaa-8aaa-web0100000001",
		Hostnames: []*pb.Hostname{{Name: "web01"}},
		Addresses: []*networkpb.Address{{Addr: "10.0.0.5"}},
		OSName:    "Linux",
		Status:    &pb.Status{State: "up", Reason: "syn-ack"},
		Ports: []*pb.Port{
			openPort(23, "tcp", "telnet"),
			openPort(443, "tcp", "https"),
		},
	}

	out := display.StripANSI(Detail(h, false).Render(120))

	for _, want := range []string{"web01", "Linux", "State", "telnet", "Open Ports", "23/tcp"} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered detail missing %q:\n%s", want, out)
		}
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
