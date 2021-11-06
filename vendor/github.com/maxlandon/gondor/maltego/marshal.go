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
	"reflect"
	"strings"
)

//
// Entity Marshalling ----------------------------------------------------------------------------
//
// All marshalling operations consist in populating the Properties list of a user-facing Entity
// with its Go content: this can includes any number of fields, with any level of nesting, and
// also supports embeding other valid Entities as their Base one.

// GetGoProperties - This function uses reflection to package all valid fields in the struct
// (as interface) stored by the Entity, as properties. We overwrite them directly each time.
func (e *Entity) GetGoProperties() (err error) {
	if e.data == nil {
		return
	}

	// Get the reflect value here. The type is only
	// needed in recursive calls, with entityValue.TypeOf()
	entityValue := reflect.ValueOf(e.data).Elem()
	entityType := reflect.TypeOf(entityValue)

	// switch reflect.ValueOf(e.data).Kind() {
	switch entityValue.Kind() {

	// For everything but structs, we directly package and return.
	default:
		// Simply add the field with fmt.Sprintf representation of the data.
		// This might be big, so people better know what they are passing.
		e.AddProperty(Field{
			Name:         "Go Type: " + entityType.String(),
			MatchingRule: MatchLoose,
			Value:        e.data,
		})

	// But we send structs in a recursive loop, for any embedded structs.
	case reflect.Ptr, reflect.Struct:
		e.marshalStruct("", entityValue, nil)
	}

	return
}

// marshalStruct - Marshal a struct with an arbitrary level of nesting, and package its content as Properties.
func (e *Entity) marshalStruct(namespace string, entityValue reflect.Value, field *reflect.StructField) {

	// Process any base Entities first, for preserving properties order.
	// This also sets all the Entity's inherited fields, like icons, labels, etc.
	e.marshalBaseEntities(entityValue, field)

	// Always add a "root" separation property, with the type as Key and the name as value
	e.AddProperty(Field{
		Name:         getNamespace(namespace, entityValue.Type().Name()),
		Display:      entityValue.String(),
		MatchingRule: MatchLoose,
		Value:        "Go type",
	})

	// Compute the current namespace for this struct
	if field != nil {
		namespace = getNamespace(namespace, field.Name)
	}

	// Then, process the property fields that are specific to this Entity, but
	// which might include any level of struct/type/whatever nesting.
	e.marshalProperties(namespace, entityValue, field)

	return
}

// marshalBaseEntities - Get all the base Entities first, process their
// properties before we deal with the Entity-specific ones.
func (e *Entity) marshalBaseEntities(entityValue reflect.Value, field *reflect.StructField) {

	numFields := entityValue.Type().NumField()
	for fieldCount := 0; fieldCount < numFields; fieldCount++ {

		// The realValue is the dereferenced pointer value
		// if we were passed a pointer to a type. Below, we
		// also make sure to initialize any nil pointers.
		var realValue reflect.Value

		// Get reflect value and type of single field
		fieldValue := entityValue.Field(fieldCount) // Can be nil
		fieldType := entityValue.Type().Field(fieldCount)

		// We can't read unexported fields, nor
		if !fieldType.IsExported() {
			continue
		}

		// Check if field is a pointer. If so, dereference
		// and switch on dereferenced type
		if fieldValue.Kind() == reflect.Ptr && fieldValue.IsNil() {
			fieldValue.Set(reflect.New(fieldValue.Type().Elem()))
			realValue = fieldValue.Elem()
		} else {
			realValue = fieldValue
		}

		// We can't read unexported fields, nor
		if !fieldType.IsExported() {
			continue
		}

		// If the type is marked as a Base entity, check and process it.
		if _, isBaseEntity := fieldType.Tag.Lookup("base"); isBaseEntity {
			e.marshalBaseEntity(realValue, &fieldType)
			continue
		}
	}
}

// marshalBaseEntity - Given a struct field embedded and marked as a Base Entity type,
// check that the type indeed satisfies the maltego.ValidEntity interface, and process it.
func (e *Entity) marshalBaseEntity(entityValue reflect.Value, field *reflect.StructField) {

	// Check the underlying type is a maltego.ValidEntity type.
	// If we have a Maltego Entity type, this is our base.
	validEntity := reflect.TypeOf((*ValidEntity)(nil)).Elem()
	if entityValue.Type().Implements(validEntity) {
		base, ok := entityValue.Interface().(ValidEntity)
		if !ok {
			return
		}

		// Now set those corresponding fields for our entity,
		// which inherits some stuff from the base.
		e.setDisplayProperties(base.AsEntity())
	}
}

// marshalProperties - Wrap all fields specific to this Entity into valid Properties, based on reflection.
func (e *Entity) marshalProperties(namespace string, entityValue reflect.Value, field *reflect.StructField) {

	numFields := entityValue.Type().NumField()
	for fieldCount := 0; fieldCount < numFields; fieldCount++ {

		// The realValue is the dereferenced pointer value
		// if we were passed a pointer to a type. Below, we
		// also make sure to initialize any nil pointers.
		var realValue reflect.Value

		// Get reflect value and type of single field
		fieldVal := entityValue.Field(fieldCount) // Can be nil
		fieldType := entityValue.Type().Field(fieldCount)

		// We can't read unexported fields, nor
		if !fieldType.IsExported() {
			continue
		}

		// Check if field is a pointer. If so, dereference
		// and switch on dereferenced type
		if fieldVal.Kind() == reflect.Ptr && fieldVal.IsNil() {
			fieldVal.Set(reflect.New(fieldVal.Type().Elem()))
			realValue = fieldVal.Elem()
		} else {
			realValue = fieldVal
		}

		// If the field is itself a struct, create a new
		// namespace level and call this func recursively.
		if realValue.Kind() == reflect.Struct {
			e.marshalStruct(namespace, realValue, &fieldType)
			continue
		}

		// The only required is display:"", not nil
		if _, ok := fieldType.Tag.Lookup("display"); !ok {
			continue
		}

		// Process MatchRules and Aliases
		var match = MatchLoose
		value, ok := fieldType.Tag.Lookup("match")
		if ok && value != "" {
			match = MatchStrict
		}
		aliasTag, ok := fieldType.Tag.Lookup("alias")
		if !ok || aliasTag == "" {
			aliasTag = strings.ToLower(fieldType.Name)
		}

		// Else, pick the tags and populate field
		f := Field{
			Name:         getNamespace(namespace, fieldType.Name),
			Value:        entityValue,
			Display:      fieldType.Type.Name(),
			MatchingRule: match,
			Alias:        aliasTag,
		}
		e.AddProperty(f)

		// Finally, if this field is marked as an overlay, create it.
		overlayTag, yes := fieldType.Tag.Lookup("overlay")
		if !yes {
			continue
		}
		e.addFieldAsOverlay(f, overlayTag)
	}
}

// getNamespace - Compute the namespace for a field (or a series of them)
func getNamespace(namespace, name string) string {
	full := strings.Join([]string{namespace, strings.ToLower(name)}, ".")
	return strings.Trim(full, ".")
}

// addFieldAsOverlay - A struct field has been tagged as overlay,
// so validate it, create it and register it to the entity.
func (e *Entity) addFieldAsOverlay(f Field, tag string) {
	infos := strings.Split(tag, ",")
	if len(infos) == 1 && infos[0] == "" {
		return
	}

	// If we have only the position, we're fine,
	// we default the type as text.
	if len(infos) == 1 && isOverlayPosition(infos[0]) {
		e.AddOverlay(f.Name, OverlayPosition(infos[0]), OverlayText)
		return
	}

	// If we have two items, we will be fine in one case, not in the other
	if len(infos) == 2 {
		// If none is good, return
		if !isOverlayPosition(infos[0]) && !isOverlayType(infos[1]) {
			return
		}
		// Type is invalid, use text as default
		if isOverlayPosition(infos[0]) && !isOverlayType(infos[1]) {
			e.AddOverlay(f.Name, OverlayPosition(infos[0]), OverlayText)
			return
		}
		// Both types are valid, populate both
		if isOverlayPosition(infos[0]) && isOverlayType(infos[1]) {
			e.AddOverlay(f.Name, OverlayPosition(infos[0]), OverlayType(infos[1]))
		}
	}
}
