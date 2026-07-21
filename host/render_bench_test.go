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

// BenchmarkTableHosts renders a real host list through the shared display engine with the host
// domain's own DisplayFields, so the per-domain field-func cost (the nmap-style OS guess in
// GetOperatingSystem, the traceroute-hop rendering, the CPU/arch guess) is measured — not just the
// generic engine's synthetic BenchmarkTable (reviews/benchmark-review.md §B #6). Each fixture host
// deliberately leaves OSName/OSFamily empty and carries OS.Matches so the guess path runs rather
// than being short-circuited. Pure CPU (no DB): the rows are built once and the timer reset before
// the render loop.
import (
	"fmt"
	"testing"

	"github.com/d3c3ptive/aims/cmd/display"
	pb "github.com/d3c3ptive/aims/host/pb"
	network "github.com/d3c3ptive/aims/network/pb"
)

// benchDisplayHost builds a host rich enough to exercise the domain field funcs: an up status, a
// couple of addresses/hostnames, an OS with competing matches (drives GetOperatingSystem's
// strongest/second scan), a traceroute (drives the Hops/Route funcs) and ports.
func benchDisplayHost(i int) *pb.Host {
	return &pb.Host{
		Id:        fmt.Sprintf("%08d-aaaa-bbbb-cccc-0123456789ab", i),
		Addresses: []*network.Address{{Addr: fmt.Sprintf("10.0.%d.%d", (i>>8)&0xff, i&0xff)}},
		Hostnames: []*pb.Hostname{{Name: fmt.Sprintf("host%05d.corp.local", i)}},
		Status:    &pb.Status{State: StateUp},
		OS: &pb.OS{
			Matches: []*pb.OSMatch{
				{Name: "Linux 5.4 - 5.15", Accuracy: 96, Classes: []*pb.OSClass{{Vendor: "Linux", OSGeneration: "5.X", Type: "general purpose", Accuracy: 96}}},
				{Name: "Linux 4.19", Accuracy: 90, Classes: []*pb.OSClass{{Vendor: "Linux", OSGeneration: "4.X", Type: "general purpose", Accuracy: 90}}},
			},
		},
		Trace: &network.Trace{
			Protocol: "tcp",
			Port:     80,
			Hops: []*network.Hop{
				{TTL: 1, RTT: "0.42", IPAddr: "10.0.0.1", Host: "gw.corp.local"},
				{TTL: 2, RTT: "3.10", IPAddr: "10.0.0.254", Host: "core.corp.local"},
			},
		},
		Ports: []*pb.Port{
			{Number: 22, Protocol: "tcp", State: &pb.State{State: "open"}, Service: &network.Service{Name: "ssh", Product: "openssh"}},
			{Number: 80, Protocol: "tcp", State: &pb.State{State: "open"}, Service: &network.Service{Name: "http", Product: "nginx"}},
		},
	}
}

func benchDisplayHosts(n int) []*pb.Host {
	hosts := make([]*pb.Host, 0, n)
	for i := 0; i < n; i++ {
		hosts = append(hosts, benchDisplayHost(i))
	}
	return hosts
}

func BenchmarkTableHosts(b *testing.B) {
	headers := DisplayHeaders()
	for _, n := range []int{100, 1000, 10000} {
		n := n
		hosts := benchDisplayHosts(n)

		b.Run(fmt.Sprintf("N=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = display.Table(hosts, DisplayFields, headers...).Render()
			}
		})
	}
}
