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
	"google.golang.org/grpc"

	"github.com/maxlandon/aims/proto/gen/go/rpc/credentials"
	"github.com/maxlandon/aims/proto/gen/go/rpc/hosts"
	"github.com/maxlandon/aims/proto/gen/go/rpc/network"
	"github.com/maxlandon/aims/proto/gen/go/rpc/scans"
)

// Client connects to an AIMS database through a gRPC connection.
// The client can be passed around to use the different services
// offered by the AIMS server backend.
type Client struct {
	conn *grpc.ClientConn

	// Services
	hosts.HostsClient
	hosts.UsersClient
	network.ServicesClient
	credentials.CredentialsClient
	credentials.LoginsClient
	scans.ScansClient
}

// New initializes an AIMS client RPC interface.
func New() (c *Client, err error) {
	return
}

// New initializes an AIMS client RPC interface with a given gRPC client connection
// (which might have or not have other client services registered onto it).
func NewFrom(conn *grpc.ClientConn) (c *Client, err error) {
	if conn == nil {
		return
	}

	c = &Client{
		conn:              conn,
		HostsClient:       hosts.NewHostsClient(conn),
		UsersClient:       hosts.NewUsersClient(conn),
		ServicesClient:    network.NewServicesClient(conn),
		CredentialsClient: credentials.NewCredentialsClient(conn),
		LoginsClient:      credentials.NewLoginsClient(conn),
		ScansClient:       scans.NewScansClient(conn),
	}

	return
}

// Hosts returns the service to interact with database hosts.
func Hosts(c *Client) hosts.HostsClient {
	return c.HostsClient
}

// Users returns the service to interact with database users.
func Users(c *Client) hosts.UsersClient {
	return c.UsersClient
}

// Services returns the service to interact with database services.
func Services(c *Client) network.ServicesClient {
	return c.ServicesClient
}

// Credentials returns the service to interact with database credentials.
func Credentials(c *Client) credentials.CredentialsClient {
	return c.CredentialsClient
}

// Logins returns the service to interact with database logins.
func Logins(c *Client) credentials.LoginsClient {
	return c.LoginsClient
}

// Scans returns the service to interact with database scans.
func Scans(c *Client) scans.ScansClient {
	return c.ScansClient
}
