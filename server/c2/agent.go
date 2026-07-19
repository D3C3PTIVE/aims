package c2

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	pb "github.com/d3c3ptive/aims/c2/pb"
	c2 "github.com/d3c3ptive/aims/c2/pb/rpc"
)

type server struct {
	db *gorm.DB
	*c2.UnimplementedAgentsServer
}

func New(db *gorm.DB) *server {
	return &server{db: db}
}

func (s *server) Create(ctx context.Context, req *c2.CreateAgentRequest) (*c2.CreateAgentResponse, error) {
	var agents []pb.AgentORM

	for _, h := range req.GetAgents() {
		horm, _ := h.ToORM(ctx)
		agents = append(agents, horm)
	}

	// Filter agents to add according to AIMS criteria first.
	dbAgents := []*pb.AgentORM{}
	database := Preloads(s.db, &c2.AgentFilters{})
	database.Find(&dbAgents)
	// filtered := core.FilterIdenticalAgent(agents, dbAgents)
	filtered := agents

	err := s.db.Create(&filtered).Error

	var agentspb []*pb.Agent
	for _, horm := range agents {
		hpb, _ := horm.ToPB(ctx)
		agentspb = append(agentspb, &hpb)
	}

	// Response
	res := &c2.CreateAgentResponse{Agents: agentspb}

	return res, err
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

	agentspb := []*pb.Agent{}
	for _, cred := range agents {
		credpb, _ := cred.ToPB(ctx)
		agentspb = append(agentspb, &credpb)
	}

	// Response
	res := &c2.ReadAgentResponse{Agents: agentspb}

	return res, err
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

	agentspb := []*pb.Agent{}
	for _, cred := range agents {
		pb, _ := cred.ToPB(ctx)
		agentspb = append(agentspb, &pb)
	}

	// Response
	res := &c2.ReadAgentResponse{Agents: agentspb}

	return res, err
}

func (s *server) Upsert(context.Context, *c2.UpsertAgentRequest) (*c2.UpsertAgentResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpsertAgent not implemented")
}

func (s *server) Delete(context.Context, *c2.DeleteAgentRequest) (*c2.DeleteAgentResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteAgent not implemented")
}

// Preloads loads a given database with preload agent association clauses before querying.
func Preloads(database *gorm.DB, filters *c2.AgentFilters) *gorm.DB {
	if filters == nil {
		filters = &c2.AgentFilters{}
	}

	filts := map[string]bool{
		"Channels": true,
	}

	preloaded := database.Preload(clause.Associations)

	for name, load := range filts {
		if !load {
			continue
		}

		preloaded = preloaded.Preload(name)
	}

	return preloaded
}

func getFilters(filts *c2.AgentFilters) *c2.AgentFilters {
	if filts != nil {
		return filts
	}

	return &c2.AgentFilters{}
}
