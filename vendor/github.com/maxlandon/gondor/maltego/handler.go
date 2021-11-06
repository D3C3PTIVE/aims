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
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/http"
)

// transformHandler - Handle a request to run a Transform from a Maltego Client: unmarshal the Request,
// pass it to a Transform, run the latter and return its output, regardless of the outcome.
func (ts *TransformServer) transformHandler(w http.ResponseWriter, r *http.Request) {

	// Get the transform transform keyed with the request path
	transform := ts.GetTransform(r.URL.Path)
	if transform == nil {
		http.Error(w, "Did not found Transform for required URL path", http.StatusNoContent)
		return
	}

	// Get the request body, and return if failed or empty
	r.ParseForm()
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if len(data) == 0 {
		http.Error(w, "Error: No form Data in Request body", http.StatusBadRequest)
		return
	}

	// Unmarshal the Maltego Request into its type.
	var request = Message{}
	err = xml.Unmarshal(data, &request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Create a new Transform instance based on the model.
	instance := transform.newInstanceFromRequest(request)

	// Run the transform.
	err = transform.run(instance)

	// Marshal its output (success or failure)
	response, err := instance.marshalOutput(err)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Finally, write the output to the HTTP response
	fmt.Fprintf(w, string(response))
}
