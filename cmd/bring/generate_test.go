package bring

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
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc"

	pb "github.com/d3c3ptive/aims/c2/pb"
	c2 "github.com/d3c3ptive/aims/c2/pb/rpc"
	"github.com/d3c3ptive/aims/cmd/bring/shell"
)

// mockAgents is a fake agentReader so bring's lookup and payload emission can be tested without a
// teamserver or the real c2 data model. It emulates the server's exact-id Where: a request with an
// id returns the matching agent(s); an empty id returns all.
type mockAgents struct {
	agents []*pb.Agent
	err    error
	gotReq *c2.ReadAgentRequest
}

func (m *mockAgents) Read(ctx context.Context, in *c2.ReadAgentRequest, opts ...grpc.CallOption) (*c2.ReadAgentResponse, error) {
	m.gotReq = in
	if m.err != nil {
		return nil, m.err
	}
	want := in.GetAgent().GetId()
	var out []*pb.Agent
	for _, a := range m.agents {
		if want == "" || a.GetId() == want {
			out = append(out, a)
		}
	}
	return &c2.ReadAgentResponse{Agents: out}, nil
}

// mockAgentData returns representative agents, including one whose name is a command-substitution
// injection attempt, to prove the payload stays inert.
func mockAgentData() []*pb.Agent {
	return []*pb.Agent{
		{Id: "aaaaaaaa-1111-4aaa-8aaa-web0100000001", Name: "web01", Tool: "sliver", WorkingDirectory: "/var/www"},
		{Id: "bbbbbbbb-2222-4bbb-8bbb-db0100000002", Name: "db01", Tool: "sliver", WorkingDirectory: "/root"},
		{Id: "cccccccc-3333-4ccc-8ccc-evil00000003", Name: "$(touch OWNED)", Tool: "mythic", WorkingDirectory: "/tmp"},
	}
}

// parsePayload turns emitted key<TAB>value lines back into a map for assertions.
func parsePayload(t *testing.T, out string) map[string]string {
	t.Helper()
	got := map[string]string{}
	for _, line := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		if line == "" {
			continue
		}
		kv := strings.SplitN(line, "\t", 2)
		if len(kv) != 2 {
			t.Fatalf("payload line %q is not key<TAB>value", line)
		}
		got[kv[0]] = kv[1]
	}
	return got
}

func TestEmitAgentPayloadByFullID(t *testing.T) {
	m := &mockAgents{agents: mockAgentData()}

	var b strings.Builder
	if err := emitAgentPayload(context.Background(), m, "aaaaaaaa-1111-4aaa-8aaa-web0100000001", &b); err != nil {
		t.Fatalf("emitAgentPayload: %v", err)
	}

	got := parsePayload(t, b.String())
	if got[shell.KeyID] != "aaaaaaaa-1111-4aaa-8aaa-web0100000001" {
		t.Errorf("id = %q, want the web01 full id", got[shell.KeyID])
	}
	if got[shell.KeyName] != "web01" {
		t.Errorf("name = %q, want web01", got[shell.KeyName])
	}
	if got[shell.KeyTool] != "sliver" {
		t.Errorf("tool = %q, want sliver", got[shell.KeyTool])
	}
	if got[shell.KeyCWD] != "/var/www" {
		t.Errorf("cwd = %q, want /var/www", got[shell.KeyCWD])
	}
	// The request must carry the id so the server can resolve it exactly.
	if m.gotReq.GetAgent().GetId() == "" {
		t.Error("Read was called without an agent id")
	}
}

func TestEmitAgentPayloadSanitizesHostileName(t *testing.T) {
	m := &mockAgents{agents: mockAgentData()}

	var b strings.Builder
	if err := emitAgentPayload(context.Background(), m, "cccccccc-3333-4ccc-8ccc-evil00000003", &b); err != nil {
		t.Fatalf("emitAgentPayload: %v", err)
	}

	out := b.String()
	if strings.Contains(out, "$(") || strings.Contains(out, "`") {
		t.Errorf("hostile name reached the payload with substitution intact:\n%s", out)
	}
	if got := parsePayload(t, out)[shell.KeyName]; got != "(touch OWNED)" {
		t.Errorf("name = %q, want sanitized %q", got, "(touch OWNED)")
	}
}

func TestEmitAgentPayloadNotFound(t *testing.T) {
	m := &mockAgents{agents: mockAgentData()}

	var b strings.Builder
	err := emitAgentPayload(context.Background(), m, "no-such-id", &b)
	if err == nil {
		t.Fatal("expected an error for an unknown id, got nil")
	}
	if b.Len() != 0 {
		t.Errorf("no payload should be written on not-found, got %q", b.String())
	}
}

func TestEmitAgentPayloadPropagatesReadError(t *testing.T) {
	m := &mockAgents{err: errors.New("boom")}
	if err := emitAgentPayload(context.Background(), m, "whatever", &nopWriter{}); err == nil {
		t.Fatal("expected the reader error to propagate, got nil")
	}
}

// TestFindAgentByIDPrefix verifies the prefix resolver bring will reuse once a List RPC returns the
// full agent set — short ids then resolve without any other change.
func TestFindAgentByIDPrefix(t *testing.T) {
	agents := mockAgentData()

	if a := findAgentByIDPrefix(agents, "aaaaaaaa"); a == nil || a.GetName() != "web01" {
		t.Errorf("prefix aaaaaaaa did not resolve to web01: %v", a)
	}
	if a := findAgentByIDPrefix(agents, "bbbb"); a == nil || a.GetName() != "db01" {
		t.Errorf("prefix bbbb did not resolve to db01: %v", a)
	}
	if a := findAgentByIDPrefix(agents, "zzzz"); a != nil {
		t.Errorf("unknown prefix resolved to %v, want nil", a)
	}
}

type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }
