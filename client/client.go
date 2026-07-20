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
	"fmt"

	"github.com/carapace-sh/carapace"
	"github.com/reeflective/team"
	"github.com/reeflective/team/client"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"

	grpcclient "github.com/reeflective/team/transports/grpc/client"

	c2 "github.com/d3c3ptive/aims/c2/pb/rpc"
	credentials "github.com/d3c3ptive/aims/credential/pb/rpc"
	hosts "github.com/d3c3ptive/aims/host/pb/rpc"
	network "github.com/d3c3ptive/aims/network/pb/rpc"
	scans "github.com/d3c3ptive/aims/scan/pb/rpc"
)

// Client connects to an AIMS database through a gRPC connection.
// The client can be passed around to use the different services
// offered by the AIMS server backend.
type Client struct {
	// Teamclient & remotes
	Teamclient   *client.Client
	dialer       *grpcclient.Dialer
	serverConfig *client.Config
	connectHooks []func() error

	// Services
	Hosts    hosts.HostsClient
	users    hosts.UsersClient
	Services network.ServicesClient
	Creds    credentials.CredentialsClient
	Logins   credentials.LoginsClient
	Scans    scans.ScansClient
	Agents   c2.AgentsClient
	Channels c2.ChannelsClient
}

func New(opts ...grpc.DialOption) (con *Client, err error) {
	con = &Client{} // Our reeflective/team.Client needs our gRPC stack.
	con.dialer = grpcclient.NewClient(opts...)

	var clientOpts []client.Options
	clientOpts = append(clientOpts,
		client.WithDialer(con.dialer),
	)

	// Create a new reeflective/team.Client, which is in charge of selecting,
	// and connecting with, remote Sliver teamserver configurations, etc.
	// Includes client backend logging, authentication, core teamclient methods...
	con.Teamclient, err = client.New("aims", clientOpts...)
	if err != nil {
		return nil, err
	}

	return con, err
}

// SetServerConfig pins the remote teamserver configuration this client will
// connect to, instead of letting the teamclient auto-select one from disk (or
// prompt for it). It is used by the thin-client boot mode: when the app finds a
// system user config at startup, it pins it here so every subsequent Connect
// reaches that remote server deterministically.
func (con *Client) SetServerConfig(cfg *client.Config) {
	con.serverConfig = cfg
}

// teamConnectOptions returns the teamclient Connect options implied by this
// client's state: a pinned server config when one was set (thin-client mode),
// otherwise none (the teamclient auto-selects / uses the in-memory dialer).
func (con *Client) teamConnectOptions() []client.Options {
	if con.serverConfig == nil {
		return nil
	}

	return []client.Options{client.WithConfig(con.serverConfig)}
}

// Init registers all gRPC clients to the existing teamclient connection.
func (c *Client) Init() error {
	if c.dialer.Conn() == nil {
		return errors.New("No grpc client connection")
	}

	conn := c.dialer.Conn()

	c.Hosts = hosts.NewHostsClient(conn)
	c.users = hosts.NewUsersClient(conn)
	c.Services = network.NewServicesClient(conn)
	c.Creds = credentials.NewCredentialsClient(conn)
	c.Logins = credentials.NewLoginsClient(conn)
	c.Scans = scans.NewScansClient(conn)
	c.Agents = c2.NewAgentsClient(conn)
	c.Channels = c2.NewChannelsClient(conn)

	return nil
}

// Users returns a list of all users registered with the app teamserver. It is
// answered by the shared team gRPC transport's core Team service (enabled with
// WithCoreServices() on the server side), through the teamclient backend.
func (con *Client) Users() (users []team.User, err error) {
	return con.Teamclient.Users()
}

func (con *Client) VersionClient() (version team.Version, err error) {
	return con.Teamclient.VersionClient()
}

// VersionServer returns the version information of the server to which the
// client is connected, via the transport's core Team service.
func (con *Client) VersionServer() (version team.Version, err error) {
	return con.Teamclient.VersionServer()
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
	if err := con.Teamclient.Connect(con.teamConnectOptions()...); err != nil {
		return err
	}

	// Register our AIMS client services, and monitor events.
	// Also set ourselves up to save our client commands in history.
	if err := con.Init(); err != nil {
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

	err = con.Teamclient.Connect(con.teamConnectOptions()...)
	if err != nil {
		return carapace.ActionMessage("connection error: %s", err), err
	}

	// Register our AIMS client services, and monitor events.
	// Also set ourselves up to save our client commands in history.
	if err := con.Init(); err != nil {
		return carapace.ActionMessage("RPC init error: %s", err), err
	}

	return carapace.ActionValues(), nil
}

// CompletionScope returns a stable identifier for the teamserver this client
// talks to (user@host:port), used to namespace on-disk completion caches so a
// multiplayer client never serves one server's objects when completing against
// another. It returns "local" when no remote config is selected (the in-process
// teamserver). Note: the remote config is only populated once Teamclient.Connect()
// has run, so in exec-once CLI mode — where the scope is read before the per-Tab
// connection — this falls back to "local"; segmentation is exact in the persistent
// console. Resolving the selected config's host without a full connect is a follow-up.
func (con *Client) CompletionScope() string {
	if con.Teamclient == nil {
		return "local"
	}
	cfg := con.Teamclient.Config()
	if cfg == nil || cfg.Host == "" {
		return "local"
	}
	return fmt.Sprintf("%s@%s:%d", cfg.User, cfg.Host, cfg.Port)
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
	if err == nil && tc != nil && tc == cmd {
		return true
	}

	return false
}
