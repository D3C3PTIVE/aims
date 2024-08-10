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
	"errors"

	"github.com/reeflective/team"
	"github.com/reeflective/team/client"
	"github.com/rsteube/carapace"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"

	"github.com/maxlandon/aims/client/transport"
	"github.com/maxlandon/aims/proto/rpc/credentials"
	"github.com/maxlandon/aims/proto/rpc/hosts"
	"github.com/maxlandon/aims/proto/rpc/network"
	"github.com/maxlandon/aims/proto/rpc/scans"
)

// Client connects to an AIMS database through a gRPC connection.
// The client can be passed around to use the different services
// offered by the AIMS server backend.
type Client struct {
	// Teamclient & remotes
	Teamclient *client.Client
	dialer     *transport.TeamClient
	conn       *grpc.ClientConn
    connectHooks []func() error

	// Services
	Hosts    hosts.HostsClient
	users    hosts.UsersClient
	Services network.ServicesClient
	Creds    credentials.CredentialsClient
	Logins   credentials.LoginsClient
	Scans    scans.ScansClient
}

func New(opts ...grpc.DialOption) (con *Client, err error) {
	con = &Client{} // Our reeflective/team.Client needs our gRPC stack.
	con.dialer = transport.NewClient(opts...)

	var clientOpts []client.Options
	clientOpts = append(clientOpts,
		client.WithDialer(con.dialer),
	)

	// Create a new reeflective/team.Client, which is in charge of selecting,
	// and connecting with, remote Sliver teamserver configurations, etc.
	// Includes client backend logging, authentication, core teamclient methods...
	con.Teamclient, err = client.New("aims", con, clientOpts...)
	if err != nil {
		return nil, err
	}

	return con, err
}


// Init registers all gRPC clients to the existing teamclient connection.
func (c *Client) Init() error {
	if c.dialer.Conn == nil {
		return errors.New("No grpc client connection")
	}

	conn := c.dialer.Conn

	c.Hosts = hosts.NewHostsClient(conn)
	c.users = hosts.NewUsersClient(conn)
	c.Services = network.NewServicesClient(conn)
	c.Creds = credentials.NewCredentialsClient(conn)
	c.Logins = credentials.NewLoginsClient(conn)
	c.Scans = scans.NewScansClient(conn)

	return nil
}

// Users returns a list of all users registered with the app teamserver.
// If the gRPC teamclient is not connected or does not have an RPC client,
// an ErrNoRPC is returned.
func (con *Client) Users() (users []team.User, err error) {
	// if con.Rpc == nil {
	// 	return nil, errors.New("No Sliver client RPC")
	// }
	//
	// res, err := con.Rpc.GetUsers(context.Background(), &commonpb.Empty{})
	// if err != nil {
	// 	return nil, con.UnwrapServerErr(err)
	// }
	//
	// for _, user := range res.GetUsers() {
	// 	users = append(users, team.User{
	// 		Name:     user.Name,
	// 		Online:   user.Online,
	// 		LastSeen: time.Unix(user.LastSeen, 0),
	// 	})
	// }
	//
	return
}

func (con *Client) VersionClient() (version team.Version, err error) {
    return con.Teamclient.VersionClient()
}

// VersionServer returns the version information of the server to which
// the client is connected, or nil and an error if it could not retrieve it.
func (con *Client) VersionServer() (version team.Version, err error) {
	// if con.Rpc == nil {
	// 	return version, errors.New("No Sliver client RPC")
	// }
	//
	// ver, err := con.Rpc.GetVersion(context.Background(), &commonpb.Empty{})
	// if err != nil {
	// 	return version, errors.New(status.Convert(err).Message())
	// }

	return team.Version{
		// Major:      ver.Major,
		// Minor:      ver.Minor,
		// Patch:      ver.Patch,
		// Commit:     ver.Commit,
		// Dirty:      ver.Dirty,
		// CompiledAt: ver.CompiledAt,
		// OS:         ver.OS,
		// Arch:       ver.Arch,
	}, nil
}

// ConnectRun is a spf13/cobra-compliant runner function to be included
// in/as any of the runners that such cobra.Commands offer to use.
//
// The function will connect the Sliver teamclient to a remote server,
// register its client RPC interfaces, and start handling events/log streams.
//
// Note that this function will always check if it used as part of a completion
// command execution call, in which case asciicast/logs streaming is disabled.
func (con *Client) ConnectRun(cmd *cobra.Command, _ []string) error {
	// Some commands don't need a remote teamserver connection.
	if con.isOffline(cmd) {
		return nil
	}

	if err := con.runPreConnectHooks(); err != nil {
		return err
	}

	// Let our teamclient connect the transport/RPC stack.
	// Note that this uses a sync.Once to ensure we don't
	// connect more than once.
	if err := con.Teamclient.Connect(); err != nil {
		return err
	}

	// Register our AIMS client services, and monitor events.
	// Also set ourselves up to save our client commands in history.
    if err := con.Init(); err !=  nil {
        return err
    }

	// Never enable asciicasts/logs streaming when this
	// client is used to perform completions. Both of these will tinker
	// with very low-level IO and very often don't work nice together.
	if compCommandCalled(cmd) {
		return nil
	}

    return nil
}

// ConnectComplete is a special connection mode which should be
// called in completer functions that need to use the client RPC.
// It is almost equivalent to client.ConnectRun(), but for completions.
//
// If the connection failed, an error is returned along with a completion
// action include the error as a status message, to be returned by completers.
//
// This function is safe to call regardless of the client being used
// as a closed-loop console mode or in an exec-once CLI mode.
func (con *Client) ConnectComplete() (carapace.Action, error) {
	// This almost only ever runs teamserver-side pre-runs.
	err := con.runPreConnectHooks()
	if err != nil {
		return carapace.ActionMessage("connection error: %s", err), err
	}

	err = con.Teamclient.Connect()
	if err != nil {
		return carapace.ActionMessage("connection error: %s", err), err
	}

	// Register our AIMS client services, and monitor events.
	// Also set ourselves up to save our client commands in history.
    if err := con.Init(); err !=  nil {
        return carapace.ActionMessage("RPC init error: %s", err), err
    }

	return carapace.ActionValues(), nil
}

// Disconnect disconnects the client from its Sliver server,
// closing all its event/log streams and files, then closing
// the core Sliver RPC client connection.
// After this call, the client can reconnect should it want to.
func (con *Client) Disconnect() error {
	return con.Teamclient.Disconnect()
}

// AddConnectHooks should be considered part of the temporary API.
// It is used to all the Sliver client to run hooks before running
// its own pre-connect handlers, and can thus be used to register
// server-only pre-run routines.
func (con *Client) AddConnectHooks(hooks ...func() error) {
	con.connectHooks = append(con.connectHooks, hooks...)
}

func (con *Client) runPreConnectHooks() error {
	for _, hook := range con.connectHooks {
		if hook == nil {
			continue
		}

		if err := hook(); err != nil {
			return err
		}
	}

	return nil
}

func compCommandCalled(cmd *cobra.Command) bool {
	for _, compCmd := range cmd.Root().Commands() {
		if compCmd != nil && compCmd.Name() == "_carapace" && compCmd.CalledAs() != "" {
			return true
		}
	}

	return false
}


func (con *Client) isOffline(cmd *cobra.Command) bool {
	// Teamclient configuration import does not need network.
	ts, _, err := cmd.Root().Find([]string{"teamserver", "client", "import"})
	if err == nil && ts != nil && ts == cmd {
		return true
	}

	tc, _, err := cmd.Root().Find([]string{"teamclient", "import"})
	if err == nil && ts != nil && tc == cmd {
		return true
	}

	return false
}
