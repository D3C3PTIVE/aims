package c2

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"

	pb "github.com/d3c3ptive/aims/c2/pb"
	c2 "github.com/d3c3ptive/aims/c2/pb/rpc"
	"github.com/d3c3ptive/aims/internal/db"
)

type agentServer struct {
	db *gorm.DB
	*c2.UnimplementedAgentsServer
}

func New(db *gorm.DB) *agentServer {
	return &agentServer{db: db, UnimplementedAgentsServer: &c2.UnimplementedAgentsServer{}}
}

func (s *agentServer) Create(ctx context.Context, req *c2.CreateAgentRequest) (*c2.CreateAgentResponse, error) {
	if len(req.GetAgents()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "no agents were provided")
	}

	var agents []*pb.AgentORM

	for _, h := range req.GetAgents() {
		horm, err := h.ToORM(ctx)
		if err != nil {
			return nil, err
		}
		agents = append(agents, &horm)
	}

	// TODO: filter agents to add according to AIMS criteria first (dedup against
	// existing rows), as the host domain does via host.IngestHosts.
	err := s.db.Create(&agents).Error

	agentspb, convErr := db.ToPBs[*pb.AgentORM, pb.Agent](ctx, agents)
	if convErr != nil {
		return nil, convErr
	}
	return &c2.CreateAgentResponse{Agents: agentspb}, err
}

func (s *agentServer) Read(ctx context.Context, req *c2.ReadAgentRequest) (*c2.ReadAgentResponse, error) {
	// Convert to ORM model
	cred, err := req.GetAgent().ToORM(ctx)
	if err != nil {
		return nil, err
	}

	// Query. QueryToPBs swallows gorm.ErrRecordNotFound as an empty result: a filtered Read that
	// matches no rows is a valid "nothing here" answer, so the CLI's len(res)==0 branch (e.g.
	// "No agents in database.") fires instead of surfacing a bare gorm "record not found".
	agentspb, err := db.QueryToPBs[*pb.AgentORM, pb.Agent](ctx, Preloads(s.db).Where(cred), true)
	if err != nil {
		return nil, err
	}
	return &c2.ReadAgentResponse{Agents: agentspb}, nil
}

func (s *agentServer) List(ctx context.Context, req *c2.ReadAgentRequest) (*c2.ReadAgentResponse, error) {
	// Convert to ORM model
	cred, err := req.GetAgent().ToORM(ctx)
	if err != nil {
		return nil, err
	}

	// Query. A list renders one row per agent and never the full host route, so it loads only the
	// agent's immediate associations (shallow) — not the nested Host.Trace.Hops/Host.Distance
	// subtree the detail Read pulls, which would otherwise be fetched for every row (P5).
	agentspb, err := db.QueryToPBs[*pb.AgentORM, pb.Agent](ctx, listPreloads(s.db).Where(cred), false)
	if err != nil {
		return nil, err
	}
	return &c2.ReadAgentResponse{Agents: agentspb}, nil
}

func (s *agentServer) Upsert(context.Context, *c2.UpsertAgentRequest) (*c2.UpsertAgentResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpsertAgent not implemented")
}

func (s *agentServer) Delete(context.Context, *c2.DeleteAgentRequest) (*c2.DeleteAgentResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteAgent not implemented")
}

// Preloads loads the agent associations the c2 detail read path needs. Beyond the agent's
// top-level relations (clause.Associations, via db.PreloadAll) it names the nested Host.* chain
// bring's prompt route summary reads — the agent's host, its traceroute hops and its hop distance —
// which clause.Associations does not reach on its own.
func Preloads(database *gorm.DB) *gorm.DB {
	return db.PreloadAll(database,
		"Channels",
		"Host.Trace.Hops",
		"Host.Distance",
	)
}

// listPreloads is the shallow counterpart of Preloads for the List path: it loads only the agent's
// immediate associations (its Host and Channels, via clause.Associations) and deliberately omits
// the nested Host route subtree (Trace.Hops, Distance). A list shows one row per agent and never
// the full traceroute, so pulling that subtree for every row is pure waste (P5).
func listPreloads(database *gorm.DB) *gorm.DB {
	return db.PreloadAll(database)
}
