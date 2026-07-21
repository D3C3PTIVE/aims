package c2

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"

	pb "github.com/d3c3ptive/aims/c2/pb"
	c2 "github.com/d3c3ptive/aims/c2/pb/rpc"
	"github.com/d3c3ptive/aims/internal/db"
)

type channelServer struct {
	db *gorm.DB
	*c2.UnimplementedChannelsServer
}

func NewChannelServer(db *gorm.DB) *channelServer {
	return &channelServer{db: db, UnimplementedChannelsServer: &c2.UnimplementedChannelsServer{}}
}

func (s *channelServer) Create(ctx context.Context, req *c2.CreateChannelRequest) (*c2.CreateChannelResponse, error) {
	if len(req.GetChannels()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "no channels were provided")
	}

	var channelsORM []*pb.ChannelORM

	for _, h := range req.GetChannels() {
		horm, err := h.ToORM(ctx)
		if err != nil {
			return nil, err
		}
		channelsORM = append(channelsORM, &horm)
	}

	// TODO: filter channels to add according to AIMS criteria first (dedup on
	// insert, as the host/credential ingest paths do). For now this is a plain
	// additive insert of the incoming channels.
	err := s.db.Create(&channelsORM).Error

	chanspb, convErr := db.ToPBs[*pb.ChannelORM, pb.Channel](ctx, channelsORM)
	if convErr != nil {
		return nil, convErr
	}
	return &c2.CreateChannelResponse{Channels: chanspb}, err
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
	// An empty result set is not an error (see Agents.Read): map "record not found" to an
	// empty successful response so the CLI renders "no channels" rather than an error.
	if errors.Is(err, gorm.ErrRecordNotFound) {
		err = nil
	}

	chanspb, convErr := db.ToPBs[*pb.ChannelORM, pb.Channel](ctx, chans)
	if convErr != nil {
		return nil, convErr
	}
	return &c2.ReadChannelResponse{Channels: chanspb}, err
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

	chanspb, convErr := db.ToPBs[*pb.ChannelORM, pb.Channel](ctx, chans)
	if convErr != nil {
		return nil, convErr
	}
	return &c2.ReadChannelResponse{Channels: chanspb}, err
}

func (s *channelServer) Upsert(context.Context, *c2.UpsertChannelRequest) (*c2.UpsertChannelResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpsertChannel not implemented")
}

func (s *channelServer) Delete(context.Context, *c2.DeleteChannelRequest) (*c2.DeleteChannelResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteChannel not implemented")
}
