package c2

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	core "github.com/maxlandon/aims/c2"
	pb "github.com/maxlandon/aims/proto/c2"
	"github.com/maxlandon/aims/proto/rpc/c2"
)

type server struct {
	db *gorm.DB
	*c2.UnimplementedAgentsServer
}

func New(db *gorm.DB) *server {
	return &server{db: db}
}

func (s *server) Create(ctx context.Context, req *c2.CreateAgentRequest) (*c2.CreateAgentResponse, error) {
	var hostsORM []pb.AgentORM

	for _, h := range req.GetAgents() {
		horm, _ := h.ToORM(ctx)
		hostsORM = append(hostsORM, horm)
	}

	// Filter hosts to add according to AIMS criteria first.
	dbHosts := []*pb.AgentORM{}
	database := Preloads(s.db, &c2.AgentFilters{})
	database.Find(&dbHosts)
	filtered := core.FilterIdenticalAgent(hostsORM, dbHosts)

	err := s.db.Create(&filtered).Error

	var hostsPB []*pb.Agent
	for _, horm := range hostsORM {
		hpb, _ := horm.ToPB(ctx)
		hostsPB = append(hostsPB, &hpb)
	}

	// Response
	res := &c2.CreateAgentResponse{Agents: hostsPB}

	return res, err
}

func (s *server) Read(ctx context.Context, req *c2.ReadAgentRequest) (*c2.ReadAgentResponse, error) {
	// Convert to ORM model
	cred, err := req.GetAgent().ToORM(ctx)
	if err != nil {
		return nil, err
	}

	// Query
	creds := []*pb.AgentORM{}
	database := Preloads(s.db, &c2.AgentFilters{})
	err = database.Where(cred).First(&creds).Error

	credspb := []*pb.Agent{}
	for _, cred := range creds {
		credpb, _ := cred.ToPB(ctx)
		credspb = append(credspb, &credpb)
	}

	// Response
	res := &c2.ReadAgentResponse{Agents: credspb}

	return res, err
}

func (s *server) List(ctx context.Context, req *c2.ReadAgentRequest) (*c2.ReadAgentResponse, error) {
	// Convert to ORM model
	cred, err := req.GetAgent().ToORM(ctx)
	if err != nil {
		return nil, err
	}

	// Query
	creds := []*pb.AgentORM{}
	database := Preloads(s.db, &c2.AgentFilters{})
	err = database.Where(cred).Find(&creds).Error

	credspb := []*pb.Agent{}
	for _, cred := range creds {
		pb, _ := cred.ToPB(ctx)
		credspb = append(credspb, &pb)
	}

	// Response
	res := &c2.ReadAgentResponse{Agents: credspb}

	return res, err
}

func (s *server) Upsert(context.Context, *c2.UpsertAgentRequest) (*c2.UpsertAgentResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpsertAgent not implemented")
}

func (s *server) Delete(context.Context, *c2.DeleteAgentRequest) (*c2.DeleteAgentResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteAgent not implemented")
}

// Preloads loads a given database with preload hosts association clauses before querying.
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
