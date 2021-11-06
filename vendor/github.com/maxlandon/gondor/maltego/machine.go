package maltego

/*
   Gondor - Go Maltego Transform Framework
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
	"time"
)

//
// Maltego Machines - Specification & Instantiation ------------------------------------------
//

// MachineRunFunc - A valid Machine script is a Go function that is "self-referencing"
// a Go native Machine type. Having access to that machine allows you to make use of
// any of its features, structured in the function the same way they would be structured
// into a Maltego native Machine script.
// In fact, all functions that you will call in your function are no more than template
// generators, which work together to produce a valid Maltego equivalent of your function.
//
// Therefore, DO NOT USE ANY LANGUAGE CONSTRUCT OTHER THAN FUNCTIONS PROVIDED BY THE MACHINE.
// In the future, the Machine parser will maybe support more advanced logic translation, but
// it will be always limited by the Maltego macro language features.
type MachineRunFunc func(m Machine) error

// Machine - The Go representation of a Maltego Machine, which is nothing
// more than Maltego proprietary Macro language: declare transforms to be
// run under various conditions, in various orders and with varying levels
// of concurrency, with optional logging functionality, nodes and tree
// deletion, automatic Maltego Graph saving & screenshot, and more.
//
// The aim of this type of to make Go users able to write a complete
// machine in Go language, which should be possible given that the
// Maltego macro language hasn't any complicated branching logic.
type Machine struct {
	run func(Machine) error
}

// NewMachineOnce - Returns a Machine that will run all of its user-defined
// actions only once, and return. The type returned contains all the methods
// you need to access the full functionality spectrum of a native Maltego machine.
//
// However, DO NOT USE ANY LANGUAGE CONSTRUCT OTHER THAN FUNCTIONS PROVIDED BY THE MACHINE.
// In the future, the Machine parser will maybe support more advanced logic translation, but
// it will be always limited by the Maltego macro language features.
func NewMachineOnce(run MachineRunFunc) Machine {
	machine := Machine{
		run: run,
	}
	return machine
}

// NewMachinePerpetual - Returns a Machine that will be ran by the Maltego client
// at the specified interval parameter (BEWARE: look at how Go time.Duration works)
//
// Other than this, this Machine is STRICTLY identical to the one returned by
// NewMachineOnce(), and this applies to functionality set it gives you access to.
//
// Therefore, DO NOT USE ANY LANGUAGE CONSTRUCT OTHER THAN FUNCTIONS PROVIDED BY THE MACHINE.
// In the future, the Machine parser will maybe support more advanced logic translation, but
// it will be always limited by the Maltego macro language features.
func NewMachinePerpetual(run MachineRunFunc, interval time.Duration) Machine {
	return Machine{
		run: run,
	}
}

//
// Maltego Machines - User API -------------------------------------------------------------
//

// Log - Print a log message to the Maltego Client Machine run window.
func (m *Machine) Log(format string, args ...interface{}) {
}

// Run - Run a Go native Transform to which you have access in this program,
// (and in addition, that has a state and settings that fit your context).
// TODO: pass a Transform interface as parameter, not a hard type
func (m *Machine) Run() {
}

// RunExtern - The machine runs a Transfrom that is either not
// a native Go type (which you can't thus use in Go code), or
// not a Go Transform that you have access to in this program.
//
// Example of a valid qualified Transform name:
// "paterva.v2.DomainToMXrecord_DNS"
func (m *Machine) RunExtern(qualifiedTransformName string) {
}

//
// Maltego Machines - Internals -------------------------------------------------------------
//

// writeConfig - The Machine creates a file in path/Machines/MachineName,
// and writes itself as an XML message into it.
func (m Machine) writeConfig(path string) (err error) {
	return
}
