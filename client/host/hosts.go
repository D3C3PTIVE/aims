package host

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

	"github.com/d3c3ptive/aims/client"
	"github.com/d3c3ptive/aims/proto/host"
	"github.com/d3c3ptive/aims/proto/rpc/hosts"
)

type hostClient struct {
	*client.Client
	h *host.Host
}

func Hosts(c *client.Client) hostClient {
	return hostClient{
		Client: c,
	}
}

// Create creates one or more hosts into the database, and returns their
// updated contents (after all fields initilized and database insertion).
func (c *hostClient) Create(h ...*host.Host) []*host.Host {
	res, _ := c.Hosts.Create(context.Background(), &hosts.CreateHostRequest{
		Hosts: h,
	})

	return res.GetHosts()
}

func (c *hostClient) Read(host *host.Host) *host.Host {
	return nil
}

// ReadByID returns a host by its ID (optionally shortened), or nil if not found in database.
func (c *hostClient) ReadByID(id string) *host.Host {
	return nil
}

// List returns a list of hosts that match one or more properties.
func (c *hostClient) List(host *host.Host) []*host.Host {
	return nil
}

// Update updates one or more hosts in the database.
func (c *hostClient) Update(hosts ...*host.Host) []*host.Host {
	return nil
}

// Delete deletes one or more hosts in the database.
// Provided hosts not yet in the database are ignored.
func (c *hostClient) Delete(host ...*host.Host) {
}

// Delete one or more hosts in database.
func (c *hostClient) DeleteByID(id string) {
}

func (c hostClient) WithHost(h *host.Host) hostClient {
	c.h = h
	return c
}

func (c hostClient) WithHostID(id string) hostClient {
	c.h = &host.Host{Id: id}
	return c
}
