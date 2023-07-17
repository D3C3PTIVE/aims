package client

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
	"github.com/maxlandon/aims/proto/rpc/credentials"
	"github.com/maxlandon/aims/proto/rpc/hosts"
	"github.com/maxlandon/aims/proto/rpc/network"
	"github.com/maxlandon/aims/proto/rpc/scans"
	"google.golang.org/grpc"
)

// Client connects to an AIMS database through a gRPC connection.
// The client can be passed around to use the different services
// offered by the AIMS server backend.
type Client struct {
	// Core
	conn *grpc.ClientConn

	// Services
	Hosts    hosts.HostsClient
	Users    hosts.UsersClient
	Services network.ServicesClient
	Creds    credentials.CredentialsClient
	Logins   credentials.LoginsClient
	Scans    scans.ScansClient

	// Interface
	// App    *console.Console
	// printf func(format string, args ...any) (int, error)
	// isCLI  bool
}

func New() (c *Client) {
	c = &Client{}

	return
}

func (c *Client) Init(conn *grpc.ClientConn) error {
	c.conn = conn

	c.Hosts = hosts.NewHostsClient(conn)
	c.Users = hosts.NewUsersClient(conn)
	c.Services = network.NewServicesClient(conn)
	c.Creds = credentials.NewCredentialsClient(conn)
	c.Logins = credentials.NewLoginsClient(conn)
	c.Scans = scans.NewScansClient(conn)

	return nil
}

// New initializes an AIMS client RPC interface with a given gRPC client connection
// (which might have or not have other client services registered onto it).
func NewFrom(conn *grpc.ClientConn) (c *Client, err error) {
	if conn == nil {
		return
	}

	c = &Client{
		conn:     conn,
		Hosts:    hosts.NewHostsClient(conn),
		Users:    hosts.NewUsersClient(conn),
		Services: network.NewServicesClient(conn),
		Creds:    credentials.NewCredentialsClient(conn),
		Logins:   credentials.NewLoginsClient(conn),
		Scans:    scans.NewScansClient(conn),
	}

	return
}
