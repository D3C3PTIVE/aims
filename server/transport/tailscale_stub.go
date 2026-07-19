//go:build !tailscale

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

package transport

import (
	"google.golang.org/grpc"

	"github.com/reeflective/team/server"
)

// newTeamserverTailScale is a no-op stub for default builds. The real
// Tailscale transport lives in tailscale.go behind the `tailscale` build tag,
// because it pulls in tailscale.com/tsnet (and transitively gvisor), a heavy
// subtree that also breaks on newer Go toolchains at its currently-pinned
// version. Build with `-tags tailscale` to enable the real listener.
//
// Returning nil signals the caller (NewTeamserver) to skip registering a
// Tailscale listener; the mTLS listener remains the default transport.
// server.WithHandler(nil) is a no-op, so the nil is safe to pass through.
func newTeamserverTailScale(opts ...grpc.ServerOption) server.Handler {
	return nil
}
