package main

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
	"os"
	"strings"

	"github.com/carapace-sh/carapace"
	"github.com/reeflective/team/boot"
	teamclient "github.com/reeflective/team/client"
	"github.com/reeflective/team/server"
	"github.com/reeflective/team/server/commands"
	"github.com/spf13/cobra"

	"github.com/d3c3ptive/aims/client"
	"github.com/d3c3ptive/aims/server/transport"
)

func main() {
	// Resolve the run mode once and dispatch. The teamserver — and thus its
	// database, listeners and server-side filesystem — is built ONLY in the
	// server callback, so a thin client never constructs or touches any of it.
	//
	// A `teamserver ...` invocation (daemon/listen/user, ...) always runs as a
	// server so the local server can be administered even when a system client
	// config is present; otherwise the presence of that config selects client
	// mode.
	err := boot.Run(boot.Boot{
		App:         "aims",
		ForceServer: isTeamserverCommand(os.Args),
		Client:      runClient,
		Server:      runServer,
	})
	if err != nil {
		// Render the error exactly once, cleanly. The root command sets SilenceErrors so cobra
		// does not also print it, and boot/connection errors (which never reach cobra) get the
		// same single line here. std log's timestamped Fatal is deliberately avoided.
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

// runServer builds and runs aims in embedded-server mode. This is the ONLY code
// path that constructs the teamserver (and therefore opens/migrates the AIMS
// database), and it distinguishes two sub-cases:
//
//   - A `teamserver ...` invocation (daemon/listen/user, ...) administers the
//     local server over real network listeners. It must NOT prime an in-memory
//     bufconn — that would make the daemon serve the in-memory pipe instead of
//     binding its TCP address — and needs no in-process console client.
//   - Any other command runs the embedded local console: an in-process
//     teamclient connected to the teamserver over an in-memory bufconn, served
//     on first use.
func runServer() error {
	teamserver, handler, err := transport.NewTeamserver()
	if err != nil {
		return err
	}

	var aimsClient *client.Client

	if isTeamserverCommand(os.Args) {
		// Network server administration: no bufconn, no console client.
		aimsClient, err = client.New()
	} else {
		// Embedded local console: connect an in-process teamclient over an
		// in-memory bufconn, and serve the teamserver on first use.
		aimsClient, err = client.New(transport.InMemoryClientOptions(handler)...)
		if err == nil {
			aimsClient.AddConnectHooks(preRunServer(teamserver, aimsClient))
		}
	}

	if err != nil {
		return err
	}

	bindCommands(aimsCmd, aimsClient)
	aimsCmd.AddCommand(commands.Generate(teamserver, aimsClient.Teamclient))
	bindRunners(aimsCmd, true, aimsClient.ConnectRun)
	carapace.Gen(aimsCmd)

	return aimsCmd.Execute()
}

// runClient builds and runs aims as a thin client of a remote teamserver. No
// teamserver is constructed and no database is opened: the client connects to
// the resolved remote config (cfg), and only data/consumption commands are
// bound — server administration lives under `teamserver`, which forces server
// mode.
func runClient(cfg *teamclient.Config) error {
	aimsClient, err := client.New()
	if err != nil {
		return err
	}

	aimsClient.SetServerConfig(cfg)

	bindCommands(aimsCmd, aimsClient)
	bindRunners(aimsCmd, true, aimsClient.ConnectRun)
	carapace.Gen(aimsCmd)

	return aimsCmd.Execute()
}

var aimsCmd = &cobra.Command{
	Use:   "aims",
	Short: "Manage and consume a database for objects for offensive security",
	// SilenceUsage keeps a runtime error from dumping the full usage text; SilenceErrors keeps
	// cobra from printing "Error: ..." itself, so main() is the single place a command error is
	// rendered (once, without a std-log timestamp). See main().
	SilenceUsage:  true,
	SilenceErrors: true,
}

// isTeamserverCommand reports whether the program was invoked as a teamserver
// administration command (`aims teamserver ...`: daemon, listen, user, ...).
// Those manage the local embedded server, so they must force embedded mode even
// when a system client config would otherwise select thin-client mode. It looks
// at the first positional argument (skipping leading flags).
func isTeamserverCommand(args []string) bool {
	for _, arg := range args[1:] {
		if strings.HasPrefix(arg, "-") {
			continue
		}

		return arg == "teamserver"
	}

	return false
}

// preRunServer is the embedded-console pre-run: it serves the in-memory
// teamserver to the in-process teamclient. The AIMS schema is migrated by the
// transport's serve hook (registerServices), which runs for both the in-memory
// and network serve paths, so nothing else is needed here.
func preRunServer(teamserver *server.Server, con *client.Client) func() error {
	return func() error {
		return teamserver.Serve(con.Teamclient)
	}
}
