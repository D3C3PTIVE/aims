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

// ReadDir returns files contained inside one ore directory paths.
func (c *hostClient) ReadDir(hostID string, paths ...string) []*host.File {
	return nil
}

// ReadFile returns the file for the provided path, if its exists.
func (c *hostClient) ReadFile(name string) *host.File {
	return nil
}

// UpsertFiles creates or overwrites a list of file paths in the database.
// This will only update/create them with their pathname.
func (c *hostClient) UpsertFilePaths(hostID string, files ...string) {
}

// UpsertFilesData is like UpsertFilePaths but creating/overwriting files
// with more complete metadata and content.
func (c *hostClient) UpsertFiles(hostID string, files ...*host.File) {
}

// ListProcesses returns the list of processes for the given host.
func (c *hostClient) ListProcesses(hostID string) []*host.Process {
	return nil
}

// ReadProcess returns a single process by its ID (PID used in host).
func (c *hostClient) ReadProcess(id string) *host.Process {
	return nil
}

// UpsertProcesses creates or updates a list processes on the given host.
func (c *hostClient) UpsertProcesses(hostID string, processes ...*host.Process) {
}
