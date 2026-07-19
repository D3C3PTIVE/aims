package transport

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
	"encoding/json"
	"log/slog"
	"time"

	"github.com/reeflective/team/server"

	grpc_auth "github.com/grpc-ecosystem/go-grpc-middleware/auth"
	grpc_tags "github.com/grpc-ecosystem/go-grpc-middleware/tags"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// bufferingOptions returns a list of server options with max send/receive
// message size, which value is that of the ServerMaxMessageSize variable (2GB).
func bufferingOptions() (options []grpc.ServerOption) {
	options = append(options,
		grpc.MaxRecvMsgSize(ServerMaxMessageSize),
		grpc.MaxSendMsgSize(ServerMaxMessageSize),
	)

	return
}

// logMiddlewareOptions is a set of logging middleware options
// preconfigured to perform the following tasks:
// - Log all connections/disconnections to/from the teamserver listener.
// - Log all raw client requests into a teamserver audit file (see server.AuditLog()).
func logMiddlewareOptions(s *server.Server) ([]grpc.ServerOption, error) {
	var requestOpts []grpc.UnaryServerInterceptor
	var streamOpts []grpc.StreamServerInterceptor

	cfg := s.GetConfig()

	// Audit-log all requests. Any failure to audit-log the requests
	// of this server will themselves be logged to the root teamserver log.
	auditLog, err := s.AuditLogger()
	if err != nil {
		return nil, err
	}

	requestOpts = append(requestOpts, auditLogUnaryServerInterceptor(s, auditLog))

	requestOpts = append(requestOpts,
		grpc_tags.UnaryServerInterceptor(grpc_tags.WithFieldExtractor(grpc_tags.CodeGenRequestFieldExtractor)),
	)

	streamOpts = append(streamOpts,
		grpc_tags.StreamServerInterceptor(grpc_tags.WithFieldExtractor(grpc_tags.CodeGenRequestFieldExtractor)),
	)

	// Logging interceptors: log the outcome of every call at a level derived
	// from its gRPC code, optionally dumping payloads when configured.
	logger := s.NamedLogger("transport", "grpc")

	requestOpts = append(requestOpts,
		logUnaryServerInterceptor(logger, cfg.Log.GRPCUnaryPayloads),
	)

	streamOpts = append(streamOpts,
		logStreamServerInterceptor(logger, cfg.Log.GRPCStreamPayloads),
	)

	return []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(requestOpts...),
		grpc.ChainStreamInterceptor(streamOpts...),
	}, nil
}

// tlsAuthMiddlewareOptions is a set of transport security options which will use
// the preconfigured teamserver TLS (credentials) configuration to authenticate
// incoming client connections. The authentication is Mutual TLS, used because
// all teamclients will connect with a known TLS credentials set.
func tlsAuthMiddlewareOptions(s *server.Server) ([]grpc.ServerOption, error) {
	var options []grpc.ServerOption

	tlsConfig, err := s.UsersTLSConfig()
	if err != nil {
		return nil, err
	}

	creds := credentials.NewTLS(tlsConfig)
	options = append(options, grpc.Creds(creds))

	return options, nil
}

// initAuthMiddleware - Initialize middleware logger.
func (ts *teamserver) initAuthMiddleware() ([]grpc.ServerOption, error) {
	var requestOpts []grpc.UnaryServerInterceptor
	var streamOpts []grpc.StreamServerInterceptor

	// Authentication interceptors.
	if ts.conn == nil {
		// All remote connections are users who need authentication.
		requestOpts = append(requestOpts,
			grpc_auth.UnaryServerInterceptor(ts.tokenAuthFunc),
		)

		streamOpts = append(streamOpts,
			grpc_auth.StreamServerInterceptor(ts.tokenAuthFunc),
		)
	} else {
		// Local in-memory connections have no auth.
		requestOpts = append(requestOpts,
			grpc_auth.UnaryServerInterceptor(serverAuthFunc),
		)
		streamOpts = append(streamOpts,
			grpc_auth.StreamServerInterceptor(serverAuthFunc),
		)
	}

	// Return middleware for all requests and stream interactions in gRPC.
	return []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(requestOpts...),
		grpc.ChainStreamInterceptor(streamOpts...),
	}, nil
}

type contextKey int

const (
	Transport contextKey = iota
	Operator
)

func serverAuthFunc(ctx context.Context) (context.Context, error) {
	newCtx := context.WithValue(ctx, Transport, "local")
	newCtx = context.WithValue(newCtx, Operator, "server")

	return newCtx, nil
}

// tokenAuthFunc uses the core reeflective/team/server to authenticate user requests.
func (ts *teamserver) tokenAuthFunc(ctx context.Context) (context.Context, error) {
	log := ts.NamedLogger("transport", "grpc")
	log.Debug("Auth interceptor checking user token")

	rawToken, err := grpc_auth.AuthFromMD(ctx, "Bearer")
	if err != nil {
		log.Error("Authentication failure", "error", err)
		return nil, status.Error(codes.Unauthenticated, "Authentication failure")
	}

	// Let our core teamserver driver authenticate the user.
	// The teamserver has its credentials, tokens and everything in database.
	user, err := ts.Authenticate(rawToken)
	if err != nil || user == nil || user.Name == "" {
		log.Error("Authentication failure", "error", err)
		return nil, status.Error(codes.Unauthenticated, "Authentication failure")
	}

	newCtx := context.WithValue(ctx, Transport, "mtls")
	newCtx = context.WithValue(newCtx, Operator, user.Name)

	return newCtx, nil
}

type auditUnaryLogMsg struct {
	Request  string `json:"request"`
	Method   string `json:"method"`
	Session  string `json:"session,omitempty"`
	Beacon   string `json:"beacon,omitempty"`
	RemoteIP string `json:"remote_ip"`
	User     string `json:"user"`
}

func auditLogUnaryServerInterceptor(ts *server.Server, auditLog *slog.Logger) grpc.UnaryServerInterceptor {
	log := ts.NamedLogger("grpc", "audit")

	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (_ interface{}, err error) {
		rawRequest, err := json.Marshal(req)
		if err != nil {
			log.Error("Failed to serialize request", "error", err)
			return
		}

		log.Debug("Raw request", "payload", string(rawRequest))

		p, _ := peer.FromContext(ctx)

		// Construct Log Message
		msg := &auditUnaryLogMsg{
			Request:  string(rawRequest),
			Method:   info.FullMethod,
			User:     getUser(p),
			RemoteIP: p.Addr.String(),
		}

		msgData, _ := json.Marshal(msg)
		auditLog.Info(string(msgData))

		resp, err := handler(ctx, req)

		return resp, err
	}
}

func getUser(client *peer.Peer) string {
	tlsAuth, ok := client.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return ""
	}
	if len(tlsAuth.State.VerifiedChains) == 0 || len(tlsAuth.State.VerifiedChains[0]) == 0 {
		return ""
	}
	if tlsAuth.State.VerifiedChains[0][0].Subject.CommonName != "" {
		return tlsAuth.State.VerifiedChains[0][0].Subject.CommonName
	}
	return ""
}

// logUnaryServerInterceptor logs the outcome of each unary call at a level
// derived from its gRPC status code, optionally dumping the request payload.
func logUnaryServerInterceptor(logger *slog.Logger, logPayloads bool) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if logPayloads {
			if raw, err := json.Marshal(req); err == nil {
				logger.Debug("Received payload", "method", info.FullMethod, "payload", string(raw))
			}
		}

		start := time.Now()
		resp, err := handler(ctx, req)

		logger.Log(ctx, codeToLevel(status.Code(err)), "unary call",
			"method", info.FullMethod, "duration", time.Since(start).String(), "error", err)

		return resp, err
	}
}

// logStreamServerInterceptor logs the outcome of each streaming call at a level
// derived from its gRPC status code.
func logStreamServerInterceptor(logger *slog.Logger, logPayloads bool) grpc.StreamServerInterceptor {
	return func(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		start := time.Now()
		err := handler(srv, stream)

		logger.Log(stream.Context(), codeToLevel(status.Code(err)), "stream call",
			"method", info.FullMethod, "duration", time.Since(start).String(), "error", err)

		return err
	}
}

// codeToLevel maps a grpc response code to an slog logging level.
func codeToLevel(code codes.Code) slog.Level {
	switch code {
	case codes.OK:
		return slog.LevelInfo
	case codes.Canceled:
		return slog.LevelInfo
	case codes.Unknown:
		return slog.LevelError
	case codes.InvalidArgument:
		return slog.LevelInfo
	case codes.DeadlineExceeded:
		return slog.LevelWarn
	case codes.NotFound:
		return slog.LevelInfo
	case codes.AlreadyExists:
		return slog.LevelInfo
	case codes.PermissionDenied:
		return slog.LevelWarn
	case codes.Unauthenticated:
		return slog.LevelInfo
	case codes.ResourceExhausted:
		return slog.LevelWarn
	case codes.FailedPrecondition:
		return slog.LevelWarn
	case codes.Aborted:
		return slog.LevelWarn
	case codes.OutOfRange:
		return slog.LevelWarn
	case codes.Unimplemented:
		return slog.LevelError
	case codes.Internal:
		return slog.LevelError
	case codes.Unavailable:
		return slog.LevelWarn
	case codes.DataLoss:
		return slog.LevelError
	default:
		return slog.LevelError
	}
}
