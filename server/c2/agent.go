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

type server struct {
	db *gorm.DB
	*c2.UnimplementedAgentsServer
}

func New(db *gorm.DB) *server {
	return &server{db: db, UnimplementedAgentsServer: &c2.UnimplementedAgentsServer{}}
}

func (s *server) Create(ctx context.Context, req *c2.CreateAgentRequest) (*c2.CreateAgentResponse, error) {
	var agents []*pb.AgentORM

	for _, h := range req.GetAgents() {
		horm, _ := h.ToORM(ctx)
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

func (s *server) Read(ctx context.Context, req *c2.ReadAgentRequest) (*c2.ReadAgentResponse, error) {
	// Convert to ORM model
	cred, err := req.GetAgent().ToORM(ctx)
	if err != nil {
		return nil, err
	}

	// Query
	agents := []*pb.AgentORM{}
	database := Preloads(s.db, &c2.AgentFilters{})
	err = database.Where(cred).First(&agents).Error

	agentspb, convErr := db.ToPBs[*pb.AgentORM, pb.Agent](ctx, agents)
	if convErr != nil {
		return nil, convErr
	}
	return &c2.ReadAgentResponse{Agents: agentspb}, err
}

func (s *server) List(ctx context.Context, req *c2.ReadAgentRequest) (*c2.ReadAgentResponse, error) {
	// Convert to ORM model
	cred, err := req.GetAgent().ToORM(ctx)
	if err != nil {
		return nil, err
	}

	// Query
	agents := []*pb.AgentORM{}
	database := Preloads(s.db, &c2.AgentFilters{})
	err = database.Where(cred).Find(&agents).Error

	agentspb, convErr := db.ToPBs[*pb.AgentORM, pb.Agent](ctx, agents)
	if convErr != nil {
		return nil, convErr
	}
	return &c2.ReadAgentResponse{Agents: agentspb}, err
}

func (s *server) Upsert(context.Context, *c2.UpsertAgentRequest) (*c2.UpsertAgentResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpsertAgent not implemented")
}

func (s *server) Delete(context.Context, *c2.DeleteAgentRequest) (*c2.DeleteAgentResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteAgent not implemented")
}

// Preloads loads the agent associations the c2 read paths need. Beyond the agent's top-level
// relations (clause.Associations, via db.PreloadAll) it names the nested Host.* chain bring's
// prompt route summary reads — the agent's host, its traceroute hops and its hop distance — which
// clause.Associations does not reach on its own.
func Preloads(database *gorm.DB, filters *c2.AgentFilters) *gorm.DB {
	return db.PreloadAll(database,
		"Channels",
		"Host.Trace.Hops",
		"Host.Distance",
	)
}
