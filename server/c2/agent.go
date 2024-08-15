package c2

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"

	pb "github.com/d3c3ptive/aims/c2/pb"
	c2 "github.com/d3c3ptive/aims/c2/pb/rpc"
)

type channelServer struct {
	db *gorm.DB
	*c2.UnimplementedChannelsServer
}

func NewChannelServer(db *gorm.DB) *channelServer {
	return &channelServer{db: db}
}

func (s *channelServer) Create(ctx context.Context, req *c2.CreateChannelRequest) (*c2.CreateChannelResponse, error) {
	var channelsORM []pb.ChannelORM

	for _, h := range req.GetChannels() {
		horm, _ := h.ToORM(ctx)
		channelsORM = append(channelsORM, horm)
	}

	// Filter channels to add according to AIMS criteria first.
	dbChans := []*pb.ChannelORM{}
	s.db.Find(&dbChans)

	err := s.db.Create(&dbChans).Error

	var chanspb []*pb.Channel
	for _, horm := range channelsORM {
		hpb, _ := horm.ToPB(ctx)
		chanspb = append(chanspb, &hpb)
	}

	// Response
	res := &c2.CreateChannelResponse{Channels: chanspb}

	return res, err
}

func (s *channelServer) Read(ctx context.Context, req *c2.ReadChannelRequest) (*c2.ReadChannelResponse, error) {
	// Convert to ORM model
	cred, err := req.GetChannel().ToORM(ctx)
	if err != nil {
		return nil, err
	}

	// Query
	chans := []*pb.ChannelORM{}
	err = s.db.Where(cred).First(&chans).Error

	chanspb := []*pb.Channel{}
	for _, cred := range chans {
		pb, _ := cred.ToPB(ctx)
		chanspb = append(chanspb, &pb)
	}

	// Response
	res := &c2.ReadChannelResponse{Channels: chanspb}

	return res, err
}

func (s *channelServer) List(ctx context.Context, req *c2.ReadChannelRequest) (*c2.ReadChannelResponse, error) {
	// Convert to ORM model
	cred, err := req.GetChannel().ToORM(ctx)
	if err != nil {
		return nil, err
	}

	// Query
	chans := []*pb.ChannelORM{}
	err = s.db.Where(cred).Find(&chans).Error

	chanspb := []*pb.Channel{}
	for _, cred := range chans {
		pb, _ := cred.ToPB(ctx)
		chanspb = append(chanspb, &pb)
	}

	// Response
	res := &c2.ReadChannelResponse{Channels: chanspb}

	return res, err
}

func (s *channelServer) Upsert(context.Context, *c2.UpsertChannelRequest) (*c2.UpsertChannelResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpsertChannel not implemented")
}

func (s *channelServer) Delete(context.Context, *c2.DeleteChannelRequest) (*c2.DeleteChannelResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteChannel not implemented")
}
