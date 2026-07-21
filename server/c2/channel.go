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
	// A failed write must not return a partially-built response alongside the error (the raw
	// gorm error is also wrapped to a coded gRPC status here — R4).
	if err := s.db.Create(&channelsORM).Error; err != nil {
		return nil, db.WrapDBError(err)
	}

	chanspb, err := db.ToPBs[*pb.ChannelORM, pb.Channel](ctx, channelsORM)
	if err != nil {
		return nil, db.WrapDBError(err)
	}
	return &c2.CreateChannelResponse{Channels: chanspb}, nil
}

func (s *channelServer) Read(ctx context.Context, req *c2.ReadChannelRequest) (*c2.ReadChannelResponse, error) {
	// Convert to ORM model
	cred, err := req.GetChannel().ToORM(ctx)
	if err != nil {
		return nil, err
	}

	// Query. QueryToPBs swallows gorm.ErrRecordNotFound as an empty result (see Agents.Read), so
	// the CLI renders "no channels" rather than surfacing a bare "record not found". Any other
	// error is a real DB failure, so it is wrapped to a coded gRPC status (R4).
	chanspb, err := db.QueryToPBs[*pb.ChannelORM, pb.Channel](ctx, s.db.Where(cred), true)
	if err != nil {
		return nil, db.WrapDBError(err)
	}
	return &c2.ReadChannelResponse{Channels: chanspb}, nil
}

func (s *channelServer) List(ctx context.Context, req *c2.ReadChannelRequest) (*c2.ReadChannelResponse, error) {
	// Convert to ORM model
	cred, err := req.GetChannel().ToORM(ctx)
	if err != nil {
		return nil, err
	}

	// Query. Any error is a real DB failure, so it is wrapped to a coded gRPC status (R4).
	chanspb, err := db.QueryToPBs[*pb.ChannelORM, pb.Channel](ctx, s.db.Where(cred), false)
	if err != nil {
		return nil, db.WrapDBError(err)
	}
	return &c2.ReadChannelResponse{Channels: chanspb}, nil
}

func (s *channelServer) Upsert(context.Context, *c2.UpsertChannelRequest) (*c2.UpsertChannelResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpsertChannel not implemented")
}

func (s *channelServer) Delete(context.Context, *c2.DeleteChannelRequest) (*c2.DeleteChannelResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteChannel not implemented")
}
