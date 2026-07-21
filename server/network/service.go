package network

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
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"

	"github.com/d3c3ptive/aims/host"
	hostpb "github.com/d3c3ptive/aims/host/pb"
	"github.com/d3c3ptive/aims/internal/db"
	"github.com/d3c3ptive/aims/network/pb"
	network "github.com/d3c3ptive/aims/network/pb/rpc"
)

type server struct {
	db *gorm.DB
	*network.UnimplementedServicesServer
}

func New(db *gorm.DB) *server {
	return &server{db: db, UnimplementedServicesServer: &network.UnimplementedServicesServer{}}
}

func (s *server) Create(ctx context.Context, req *network.CreateServiceRequest) (*network.CreateServiceResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateService not implemented")
}

// Read returns the first service matching the request filters ("services alone", per the proto's
// own split): the response carries Services only, never the hosts they run on. ReadHost is the
// with-host-context variant.
func (s *server) Read(ctx context.Context, req *network.ReadServiceRequest) (*network.ReadServiceResponse, error) {
	servicespb, err := s.query(ctx, req, true)
	if err != nil {
		return nil, err
	}
	return &network.ReadServiceResponse{Services: servicespb}, nil
}

// List returns every service matching the request filters, services alone (see Read).
func (s *server) List(ctx context.Context, req *network.ReadServiceRequest) (*network.ReadServiceResponse, error) {
	servicespb, err := s.query(ctx, req, false)
	if err != nil {
		return nil, err
	}
	return &network.ReadServiceResponse{Services: servicespb}, nil
}

// ReadHost is Read with host context: the same single service, plus the host it runs on in the
// response's Host field. This is the semantic the proto's two RPC groups ask for — "services alone"
// (Read/List) versus "host services (with extra ports and lower-level stuff)" (ReadHost/ListHost) —
// expressed as the same query with the owning hosts resolved and attached, rather than as two
// different filters. A caller that already knows the host (it filtered by one) can keep using Read.
func (s *server) ReadHost(ctx context.Context, req *network.ReadServiceRequest) (*network.ReadServiceResponse, error) {
	return s.readWithHosts(ctx, req, true)
}

// ListHost is List with host context: every matching service, plus the distinct hosts they run on.
func (s *server) ListHost(ctx context.Context, req *network.ReadServiceRequest) (*network.ReadServiceResponse, error) {
	return s.readWithHosts(ctx, req, false)
}

// query is the shared Read/List body: build the filtered, scoped query and run it. single selects
// the First fast path (Read) over Find (List), so both share one definition of what the filters mean
// — the previous List silently ignored the Source scope Read applied.
func (s *server) query(ctx context.Context, req *network.ReadServiceRequest, single bool) ([]*pb.Service, error) {
	// Convert to ORM model
	service, err := req.GetService().ToORM(ctx)
	if err != nil {
		return nil, err
	}

	// Query. Preload the service's provenance Sources so a read service carries the tools that
	// contributed it, consistent with the other domains (host/credential) rather than coming back
	// bare (P5). Sources is a service's only association, so PreloadAll is exactly this set.
	query := db.PreloadAll(s.db).Where(service)
	// Per-tool scoping: restrict to services contributed by a given tool via the
	// service_sources provenance join. Empty Source is a no-op (all services).
	query = db.ScopeBySource(query, "service_sources", "service_id", req.GetSource())
	// Host scoping: restrict to services running on the requested host. A service attaches to a
	// host through a port, so `ports` is the join carrying both FKs. Nil/empty Host is a no-op.
	query = db.ScopeByHost(query, "ports", "service_id", "host_id", host.IDsMatching(query, req.GetHost()))
	// Server-side completion filter: when a prefix is set, push a prefix LIKE down to the DB so a
	// service-name Tab returns only the candidate services. Empty prefix is a no-op.
	query = scopeServiceByPrefix(query, req.GetPrefix())

	// QueryToPBs runs the First and swallows gorm.ErrRecordNotFound as an empty result, so a
	// filtered Read matching no rows returns an empty list the caller's len==0 branch renders.
	// Any other error is a real DB failure, so it is wrapped to a coded gRPC status (R4).
	servicespb, err := db.QueryToPBs[*pb.ServiceORM, pb.Service](ctx, query, single)
	if err != nil {
		return nil, db.WrapDBError(err)
	}
	return servicespb, nil
}

// readWithHosts runs the same query as Read/List and additionally resolves the distinct hosts the
// matched services run on, so the caller gets the port/host context in one round trip.
func (s *server) readWithHosts(ctx context.Context, req *network.ReadServiceRequest, single bool) (*network.ReadServiceResponse, error) {
	servicespb, err := s.query(ctx, req, single)
	if err != nil {
		return nil, err
	}

	hostspb, err := s.hostsOf(ctx, servicespb)
	if err != nil {
		return nil, err
	}

	return &network.ReadServiceResponse{Services: servicespb, Host: hostspb}, nil
}

// hostsOf loads the distinct hosts running the given services, walking back up the same
// ports.service_id -> ports.host_id link the host scope uses. An empty service set yields no hosts
// (and no query).
func (s *server) hostsOf(ctx context.Context, services []*pb.Service) ([]*hostpb.Host, error) {
	ids := make([]string, 0, len(services))
	for _, svc := range services {
		if svc.GetId() != "" {
			ids = append(ids, svc.GetId())
		}
	}
	if len(ids) == 0 {
		return nil, nil
	}

	hostIDs := s.db.Session(&gorm.Session{NewDB: true}).
		Table("ports").
		Select("ports.host_id").
		Where("ports.host_id IS NOT NULL").
		Where("ports.service_id IN ?", ids)

	query := db.PreloadAll(s.db).Where("id IN (?)", hostIDs)
	hostspb, err := db.QueryToPBs[*hostpb.HostORM, hostpb.Host](ctx, query, false)
	if err != nil {
		return nil, db.WrapDBError(err)
	}
	return hostspb, nil
}

// scopeServiceByPrefix restricts the query to services whose name or product begins with prefix, OR
// whose id begins with it — the server-side completion filter behind ReadServiceRequest.Prefix, the
// same shape as scopeCredByPrefix/scopeHostByPrefix. The id leg keeps the name-less services (which
// the completer renders by their id fallback) inside the superset the client filter narrows, so the
// pushdown can never drop a candidate carapace would have shown; the product leg widens the superset
// further, which is free for the same reason. Empty prefix is a no-op. The LIKE is left-anchored
// (prefix%) and its metacharacters are escaped (ESCAPE '\') so a typed '_'/'%' matches literally.
func scopeServiceByPrefix(query *gorm.DB, prefix string) *gorm.DB {
	if prefix == "" {
		return query
	}
	like := escapeLike(prefix) + "%"
	return query.Where(
		`name LIKE ? ESCAPE '\' OR product LIKE ? ESCAPE '\' OR id LIKE ? ESCAPE '\'`,
		like, like, like,
	)
}

// escapeLike neutralises the SQL LIKE wildcards in a user-typed prefix so it is matched literally
// under an `ESCAPE '\'` clause (backslash escaped first so it does not double-escape).
func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

func (s *server) Upsert(ctx context.Context, req *network.UpsertServiceRequest) (*network.UpsertServiceResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpsertService not implemented")
}

func (s *server) Delete(ctx context.Context, req *network.DeleteServiceRequest) (*network.DeleteServiceResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteService not implemented")
}
