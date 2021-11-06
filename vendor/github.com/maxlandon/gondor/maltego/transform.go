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

//
// Maltego Transforms - Specification & Instantiation ------------------------------------------
//

import (
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/maxlandon/gondor/maltego/configuration"
)

// TransformFunc - This type defines what is the valid implementation of a Transform
// in Go code. The transform passed as argument is a "self-reference", which gives you
// access to all the methods for querying, modifying and adding input/output Entities,
// as well as some of the core Transform settings.
// This is another way to register a new valid Maltego transform, without
// wrapping it around a native Go type implementing maltego.ValidTransform.
//
// Any error returned from the function will be translated into a Maltego Transform exception.
// You can return an error at any time within your Tranform function implementation.
type TransformFunc func(t *Transform) (err error)

// Transform - The base Go implementation of a Maltego transform.
// This type holds all the information necessary to the correct registration
// and functioning of an equivalent Maltego Client Transform, and exactly as
// in the Python code, is NOT restricted to any type of output Entity.
type Transform struct {
	// Base Information
	configuration.TransformInfo                   // The user can set this to his wish.
	sets                        []string          // The transform sets to which the transform belongs
	input                       ValidEntity       // The transform is passed a maltego.ValidEntity and populates this with info
	output                      []ValidEntity     // Output entities for this transform
	Settings                    TransformSettings // All settings for this transform, and their local configuration.

	// Operating Parameters
	Request    Message       // The incoming Transform request, input Entity, and all transform settings.
	run        TransformFunc // The transform function implementation, declared and passed by the user
	entities   []Entity      // All entities to be returned as the Transform output.
	messages   []MessageUI   // Transform log messages
	exceptions []Exception   // All errors throwed during execution.
	mutex      *sync.RWMutex // Concurrency
}

// NewTransform - Instantiate a new Transform by passing a valid Transform function
// implementation. This leaves you the choice on where you want to declare this function
// whether it is a type method or a pure function (depends on your needs and code), etc.
//
// The function allows you to pass an optional list of transform settings that you want to
// apply to this transform AND ONLY THIS ONE. If you want global settings (applying to all
// transforms served by an HTTP server), pass this settings to the server itself.
// You can also add settings to the Transform later, through its AddSetting() method. In all
// cases, you should always register them BEFORE serving the Transforms to their client.
func NewTransform(name string, run TransformFunc, settings ...TransformSetting) Transform {
	t := Transform{
		// TODO: set default fields to true when they need
		TransformInfo: configuration.TransformInfo{},
		run:           run,
		mutex:         &sync.RWMutex{},
	}
	t.Description = getTransformDescription(run)

	return t
}

// NewTransformWith - Declare a new Transform, with a Run implementation, an Input entity
// type and any number of OutputEntities. The input/output entities are merely used to check
// that we will be able to unmarshal Maltego entities into them, by verifying both types match.
// You'll still need to perform the unmarshalling operation yourself, with entity.Unmarshal().
func NewTransformWith(run TransformFunc, input ValidEntity, output ...ValidEntity) {
	t := Transform{
		// TODO: set default fields to true when they need
		TransformInfo: configuration.TransformInfo{},
		input:         input,
		output:        output,
		run:           run,
		mutex:         &sync.RWMutex{},
	}
	t.Description = getTransformDescription(run)
}

//
// Maltego Transforms - User API -------------------------------------------------------------
//

// AddToSet - Include your transform in a specific set of Transforms,
// for classification in the Maltego client. You can add your transform
// to multiple sets, thus you can call this function multiple times.
func (t *Transform) AddToSet(set string) {
	t.mutex.RLock()
	defer t.mutex.RUnlock()
	t.sets = append(t.sets, set)
}

// AddSetting - Before registering your transform to a maltego.TransformServer (or before
// serving it or generating its configuration file), you can add Settings (as properties).
func (t *Transform) AddSetting(s TransformSetting) {
	t.mutex.RLock()
	defer t.mutex.RUnlock()
	t.Settings.settings = append(t.Settings.settings, s)
}

// AddEntity - Add an Entity to the list of entities to be sent in the Transform response.
// Generally, you want to call it with either yourGoType.AsEntity() function, or directly
// passing a maltego.Entity type when you can't/don't want to use a native Go type in the Transform.
func (t *Transform) AddEntity(e ValidEntity) (err error) {
	// Do not append the entity if the we topped
	// the maximum allowed number of output entities.
	if t.Request.Slider == len(t.entities) {
		return
	}
	t.mutex.RLock()
	defer t.mutex.RUnlock()
	t.entities = append(t.entities)
	return
}

// Debugf - Log an debug-level message in the Maltego transform window.
func (t *Transform) Debugf(format string, args ...interface{}) {
	t.mutex.RLock()
	defer t.mutex.RUnlock()
	msg := fmt.Sprintf(format, args...)
	t.messages = append(t.messages, MessageUI{Text: msg, Type: "Debug"})
}

// Infof - Log an info-level message in the Maltego transform window.
func (t *Transform) Infof(format string, args ...interface{}) {
	t.mutex.RLock()
	defer t.mutex.RUnlock()
	msg := fmt.Sprintf(format, args...)
	t.messages = append(t.messages, MessageUI{Text: msg, Type: "Inform"})
}

// Warnf - Log an warning-level message in the Maltego transform window.
func (t *Transform) Warnf(format string, args ...interface{}) {
	t.mutex.RLock()
	defer t.mutex.RUnlock()
	msg := fmt.Sprintf(format, args...)
	t.messages = append(t.messages, MessageUI{Text: msg, Type: "Partial"})
}

// Errorf - Log an error-level message in the Maltego transform window.
// This function returns the error, so that if you want to terminate the
// transform because of it, you can "return err" from anywhere.
func (t *Transform) Errorf(format string, args ...interface{}) error {
	t.mutex.RLock()
	defer t.mutex.RUnlock()
	msg := fmt.Sprintf(format, args...)
	t.exceptions = append(t.exceptions, Exception(msg))
	return errors.New(msg)
}

//
// Transform Internal Implementation -----------------------------------------------
//

// newInstanceFromRequest - Instantiate a new transform instance, copying a
// few of the fields from us (the model), and populating with a new Request.
func (t *Transform) newInstanceFromRequest(request Message) (nt *Transform) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return &Transform{
		TransformInfo: t.TransformInfo,
		Request:       request,
		run:           t.run,
		mutex:         &sync.RWMutex{},
	}
}

// marshalOutput - The transform packages the output Entities within an XML string.
func (t *Transform) marshalOutput(runErr error) (out []byte, err error) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	// Message container
	message := Message{
		x: xml.Name{Local: "MaltegoMessage"},
	}

	// We have either failed (and the error is already stored)
	if runErr != nil {
		message.Exception = TransformExceptionMessage{
			Exceptions: t.exceptions,
		}
	}

	// Or succeeded, with output entities and UI messages
	if runErr == nil {
		message.Response = TransformResponseMessage{
			Entities: t.entities,
			Messages: t.messages,
		}
	}

	// Marshal the overall message and its content.
	return xml.Marshal(message)
}

// Check that the Transform Input Entity native type (if any)
// is the same type as the request Entity one.
func (t *Transform) checkInputEntity(input Entity) (err error) {
	tInput := t.input.AsEntity()

	// Always check the string values of our Entities, must be enough
	inputFQN := strings.Join([]string{input.Namespace, input.Type}, ".")
	wantedFQN := strings.Join([]string{tInput.Namespace, tInput.Type}, ".")
	if inputFQN != wantedFQN {
		return fmt.Errorf("Mismatch native Go entity types: wanted %s, got %s",
			wantedFQN, inputFQN)
	}

	return nil
}

// marshalConfig - The transform packages itself into an XML string,
// for inclusion in a Maltego Transform configuration file.
func (*Transform) marshalConfig() (out []byte, err error) {
	return
}

// Transforms - Holds a map of Transforms.
type Transforms map[string]*Transform

// MarshalXML -
func (t Transforms) MarshalXML(e *xml.Encoder, start xml.StartElement) (err error) {
	return
}
