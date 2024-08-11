package c2

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"

	pb "github.com/maxlandon/aims/proto/c2"
	"github.com/maxlandon/aims/proto/rpc/c2"
)

type channelServer struct {
	db *gorm.DB
	*c2.UnimplementedChannelsServer
}

func NewChannelServer(db *gorm.DB) *channelServer {
	return &channelServer{db: db}
}

func (s *channelServer) Create(ctx context.Context, req *c2.CreateChannelRequest) (*c2.CreateChannelResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateChannel not implemented")
}

func (s *channelServer) Read(ctx context.Context, req *c2.ReadChannelRequest) (*c2.ReadChannelResponse, error) {
	// Convert to ORM model
	cred, err := req.GetChannel().ToORM(ctx)
	if err != nil {
		return nil, err
	}

	// Query
	creds := []*pb.ChannelORM{}
	err = s.db.Where(cred).First(&creds).Error

	credspb := []*pb.Channel{}
	for _, cred := range creds {
		pb, _ := cred.ToPB(ctx)
		credspb = append(credspb, &pb)
	}

	// Response
	res := &c2.ReadChannelResponse{Channels: credspb}

	return res, err
}

func (s *channelServer) List(ctx context.Context, req *c2.ReadChannelRequest) (*c2.ReadChannelResponse, error) {
	// Convert to ORM model
	cred, err := req.GetChannel().ToORM(ctx)
	if err != nil {
		return nil, err
	}

	// Query
	creds := []*pb.ChannelORM{}
	err = s.db.Where(cred).Find(&creds).Error

	credspb := []*pb.Channel{}
	for _, cred := range creds {
		pb, _ := cred.ToPB(ctx)
		credspb = append(credspb, &pb)
	}

	// Response
	res := &c2.ReadChannelResponse{Channels: credspb}

	return res, err
}

func (s *channelServer) Upsert(context.Context, *c2.UpsertChannelRequest) (*c2.UpsertChannelResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpsertChannel not implemented")
}

func (s *channelServer) Delete(context.Context, *c2.DeleteChannelRequest) (*c2.DeleteChannelResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteChannel not implemented")
}
