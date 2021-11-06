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
	"crypto/tls"
	"net/http"
	"sync"
)

// TransformServer - A server holding all its registered Transforms,
// serving them, either through HTTP or through local invocation.
type TransformServer struct {
	// Information
	Name           string             // Generally you don't need to set the name
	Description    string             // You can set a description for your Transform Server
	URL            string             // Set at runtime when the HTTP server starts, or when config output.
	LastSync       string             // Last time the server whas registered, you don't need to set this.
	Protocol       string             // You don't need to set the protocol yourself
	Authentication AuthenticationType // The default authentication is None
	Enabled        bool               // The transform server is always enabled by default
	Transforms     Transforms         // All user-registered transforms
	Distribution                      // The distribution for this server

	// Runtime HTTP
	hs    http.Server
	mux   *http.ServeMux
	mutex *sync.RWMutex // Concurrency
}

// NewTransformServer - Create a new Transform Server instance,
// optionally passing a Maltego configuration file (for global
// transform settings, HTTP security details, etc)
func NewTransformServer(config interface{}) *TransformServer {
	ts := &TransformServer{
		Name:        "Local",
		Description: "Go Local Transforms, hosted on this machine.",

		Transforms: Transforms{},
		// config: config,
		hs:    http.Server{},
		mux:   http.NewServeMux(),
		mutex: &sync.RWMutex{},
	}

	// Make a default Maltego Distribution holding us
	// as its unique Maltego Server.

	return ts
}

// RegisterTransform - Once you have declared/instantiated a Transform
// in your code, you must register it to a Server with this function.
// The path at which the Transform is available is automatically set
// from its properties, and this should match any exported Config.
func (ts *TransformServer) RegisterTransform(t *Transform) {
	ts.mutex.RLock()
	defer ts.mutex.RUnlock()

	// Map the transform to the server
	ts.Transforms["transform.Namespace"] = t

	// And to the HTTP server
	ts.mux.HandleFunc("transform.Namespace", ts.transformHandler)

	return
}

// ListenAndServe - The Transform Server starts serving its content, pulling from the current
// state of its configuration: target address, TLS configuration, transforms settings, etc.
func (ts *TransformServer) ListenAndServe() (err error) {

	// Bind the mux handler to the server
	ts.hs.Handler = ts.mux

	return
}

// ListenAndServeTLS - The Transform Server starts serving its content, with an optional TLS
// configuration passed as argument. If nil, will default on its present configuration state.
func (ts *TransformServer) ListenAndServeTLS(addr string, tlsConfig *tls.Config) (err error) {

	// Bind the mux handler to the server
	ts.hs.Handler = ts.mux

	return
}

// GetTransform - Find the Transform corresponding to an HTTP URL path.
func (ts *TransformServer) GetTransform(path string) *Transform {
	ts.mutex.Lock()
	defer ts.mutex.Unlock()
	return ts.Transforms[path]
}

//
// Maltego Transform Server - Internal Implementation ------------------------------------------
//

// TransformServer - A transform server outputs a complete Maltego
// configuration file (.mtz) with transforms, sets, entities, settings, etc...
func (ts *TransformServer) marshalConfig() (data []byte, err error) {
	return
}
