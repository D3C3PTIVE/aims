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

import "github.com/maxlandon/aims/proto/host"

func (c *hostClient) ReadDir(hostID string, paths ...string) []*host.File {
	return nil
}

func (c *hostClient) ReadFile(name string) *host.File {
	return nil
}

func (c *hostClient) UpsertFiles(hostID string, files ...string) {
}

func (c *hostClient) UpsertFilesData(hostID string, files ...*host.File) {
}

func (c *hostClient) ListProcesses(hostID string) []*host.Process {
	return nil
}

func (c *hostClient) ReadProcess(name string) *host.Process {
	return nil
}

func (c *hostClient) UpsertProcesses(hostID string, processes ...*host.Process) {
}
