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
	"strconv"
	"strings"
	"time"
)

//
// Entity Unmarshalling ---------------------------------------------------------------------------------
//
// All unmarshalling operations are performed directly on the user-facing Entity type, not on its
// XML configuration type equivelant. All these operations consist in populating the list of Properties
// (themselves marshalled into XML later) with the Entity' native Go code.

// unmarshalStruct - Given a struct value, unmarshal zero or more Entity properties into its fields,
// and do this recursively for all named/embedded structs fields, using the Properties namespaced names.
func (e *Entity) unmarshalStruct(namespace string, realval reflect.Value, sField *reflect.StructField) {

	// Compute the current namespace for this struct
	if sField != nil {
		namespace = getNamespace(namespace, sField.Name)
	}

	// Simply pass the struct to a function that will recursively
	// unpack all the Entity properties in their native Go fields.
	e.unmarshalProperties(namespace, realval)
}

// unmarshalProperties - Populate native Go fields with their equivalent Maltego properties.
// This applies for only the current level of nesting: all embedded structs, or struct fields,
// are being passed down recursively, for fetching their own Properties in another namespace.
func (e *Entity) unmarshalProperties(namespace string, realval reflect.Value) {

	numFields := realval.Type().NumField()
	for fieldCount := 0; fieldCount < numFields; fieldCount++ {
		field := realval.Type().Field(fieldCount)
		fieldKind := field.Type.Kind()
		fieldVal := realval.Field(fieldCount) // Can be nil

		// We can't read unexported fields, nor
		if !field.IsExported() {
			continue
		}

		// The base might be a ValidEntity VALUE, not a pointer to it.
		// If that's the case, get the pointer to check implementation.
		if fieldKind != reflect.Ptr {
			realval = reflect.New(reflect.TypeOf(realval.Interface()))
		}

		// Also, check that we have a working instance, because we will
		// need to call its method, fetch attributes, etc.
		if realval.IsNil() {
			realval = reflect.New(realval.Type().Elem())
		}

		// If the field is itself a struct, create a new
		// namespace level and call this func recursively.
		if field.Type.Kind() == reflect.Struct {
			e.unmarshalStruct(namespace, fieldVal, &field)
			continue
		}

		// The only required is display:"", not nil, so if the field
		// doesn't have it there is nothing to put in it.
		if _, ok := field.Tag.Lookup("display"); !ok {
			continue
		}

		// Else we need to find the corresponding property
		// The value passed by maltego is given as a string here
		fqn := strings.Join([]string{namespace, field.Name}, ".")
		prop := e.Property(fqn)

		// Unmarshal the string value into the field native type.
		convert(prop, realval)
	}
}

// convert - Taken from go-flags library. This function "casts" a string
// representation of an arbitrary value (therefore, an interface) and populates
// the corresponding struct.Field value with it.
func convert(val string, retval reflect.Value) error {
	// if ok, err := convertUnmarshal(val, retval); ok {
	//         return err
	// }

	tp := retval.Type()

	// Support for time.Duration
	if tp == reflect.TypeOf((*time.Duration)(nil)).Elem() {
		parsed, err := time.ParseDuration(val)

		if err != nil {
			return err
		}

		retval.SetInt(int64(parsed))
		return nil
	}

	switch tp.Kind() {
	case reflect.String:
		retval.SetString(val)
	case reflect.Bool:
		if val == "" {
			retval.SetBool(true)
		} else {
			b, err := strconv.ParseBool(val)

			if err != nil {
				return err
			}

			retval.SetBool(b)
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		parsed, err := strconv.ParseInt(val, 10, tp.Bits())

		if err != nil {
			return err
		}

		retval.SetInt(parsed)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		parsed, err := strconv.ParseUint(val, 10, tp.Bits())

		if err != nil {
			return err
		}

		retval.SetUint(parsed)
	case reflect.Float32, reflect.Float64:
		parsed, err := strconv.ParseFloat(val, tp.Bits())

		if err != nil {
			return err
		}

		retval.SetFloat(parsed)
	case reflect.Slice:
		elemtp := tp.Elem()

		elemvalptr := reflect.New(elemtp)
		elemval := reflect.Indirect(elemvalptr)

		if err := convert(val, elemval); err != nil {
			return err
		}

		retval.Set(reflect.Append(retval, elemval))
	case reflect.Map:
		parts := strings.SplitN(val, ":", 2)

		key := parts[0]
		var value string

		if len(parts) == 2 {
			value = parts[1]
		}

		keytp := tp.Key()
		keyval := reflect.New(keytp)

		if err := convert(key, keyval); err != nil {
			return err
		}

		valuetp := tp.Elem()
		valueval := reflect.New(valuetp)

		if err := convert(value, valueval); err != nil {
			return err
		}

		if retval.IsNil() {
			retval.Set(reflect.MakeMap(tp))
		}

		retval.SetMapIndex(reflect.Indirect(keyval), reflect.Indirect(valueval))
	case reflect.Ptr:
		if retval.IsNil() {
			retval.Set(reflect.New(retval.Type().Elem()))
		}

		return convert(val, reflect.Indirect(retval))
	case reflect.Interface:
		if !retval.IsNil() {
			return convert(val, retval.Elem())
		}
	}

	return nil
}
