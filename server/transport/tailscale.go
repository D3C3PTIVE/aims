//go:build tailscale

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
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"

	"google.golang.org/grpc"
	"tailscale.com/tsnet"

	"github.com/reeflective/team/server"
	grpcserver "github.com/reeflective/team/transports/grpc/server"
)

// tailscaleTeamserver is unexported since we only need it as
// a reeflective/team/server.Handler interface implementation.
//
// It embeds the shared team gRPC handler to reuse its full server stack
// (buffering, audit/logging, panic recovery, token authentication and the AIMS
// service registration hook) and only overrides how the listener is created:
// instead of a TCP+TLS bind, it stands up a Tailscale/tsnet listener and serves
// the same gRPC stack on it via the handler's exported ServeOn.
type tailscaleTeamserver struct {
	*grpcserver.Handler
}

// newTeamserverTailScale returns an AIMS teamserver backend using Tailscale.
func newTeamserverTailScale(opts ...grpc.ServerOption) server.Handler {
	core := grpcserver.NewListener(opts...)
	core.WithCoreServices()
	core.PostServe(registerServices(core))

	return &tailscaleTeamserver{core}
}

// Name indicates the transport/rpc stack.
func (ts *tailscaleTeamserver) Name() string {
	return "gRPC/TSNet"
}

// Listen implements team/server.Handler.Listen(). Instead of serving a classic
// TCP+TLS listener, we start a tailscale stack and create the listener out of
// it, then reuse the shared gRPC server stack via ServeOn.
func (ts *tailscaleTeamserver) Listen(addr string) (ln net.Listener, err error) {
	tsNetLog := ts.NamedLogger("transport", "tailscale")

	url, err := url.Parse(fmt.Sprintf("ts://%s", addr))
	if err != nil {
		return nil, err
	}

	hostname := url.Hostname()
	port := url.Port()

	if hostname == "" {
		hostname = "aims-server"
		machineName, _ := os.Hostname()
		if machineName != "" {
			hostname = fmt.Sprintf("%s-%s", hostname, machineName)
		}
	}

	tsNetLog.Info("Starting gRPC/tsnet listener", "hostname", hostname, "port", port)

	authKey := os.Getenv("TS_AUTHKEY")
	if authKey == "" {
		tsNetLog.Error("TS_AUTHKEY not set")
		return nil, fmt.Errorf("TS_AUTHKEY not set")
	}

	tsnetDir := filepath.Join(ts.LogsDir(), "tsnet")
	if err := os.MkdirAll(tsnetDir, 0o700); err != nil {
		return nil, err
	}

	tsNetServer := &tsnet.Server{
		Hostname: hostname,
		Dir:      tsnetDir,
		// tsnet expects a printf-style Logf; bridge it onto the slog logger
		// (team's NamedLogger now returns *slog.Logger, which has no Debugf).
		Logf: func(format string, args ...any) {
			tsNetLog.Debug(fmt.Sprintf(format, args...))
		},
		AuthKey: authKey,
	}

	ln, err = tsNetServer.Listen("tcp", fmt.Sprintf(":%s", port))
	if err != nil {
		return nil, err
	}

	ts.ServeOn(ln)

	return ln, nil
}
