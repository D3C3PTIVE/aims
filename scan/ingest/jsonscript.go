package ingest

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
	"encoding/json"
	"sort"
	"strconv"

	nmappb "github.com/d3c3ptive/aims/scan/pb/nmap"
)

// jsonToScript maps arbitrary decoded JSON into the recursive nmap NSE Script tree. This is
// the schemaless-extension principle (SCAN.md Part A#4 / Part D) put to work: any JSON
// scanner's bespoke output files itself into the same Script{Table, Element} rows nmap's own
// NSE scripts land in, so adding a JSON tool never means new proto/DB columns. Written once,
// it serves every JSON adapter (all zgrab2 modules, and by extension nuclei/httpx/testssl).
//
// The mapping mirrors nmap's own structure/element grammar:
//
//	object  key:{...}  -> child Table{Key} (recursed)
//	array   key:[...]  -> Table{Key} with index-keyed children
//	scalar  key:value  -> Element{Key, Value}
//
// v is a value decoded by decodeJSON (numbers preserved as json.Number so ints don't become
// floats). Script.Output is filled with a compact JSON rendering, mirroring how nmap puts a
// human-readable summary in Script.Output alongside the structured tree.
func jsonToScript(name string, v any) *nmappb.Script {
	s := &nmappb.Script{Name: name}

	switch val := v.(type) {
	case map[string]any:
		for _, k := range sortedKeys(val) {
			walkInto(k, val[k], &s.Tables, &s.Elements)
		}
	case []any:
		for i, item := range val {
			walkInto(strconv.Itoa(i), item, &s.Tables, &s.Elements)
		}
	case nil:
		// Nothing structured to hang; leave the script bare (name only).
	default:
		s.Elements = append(s.Elements, &nmappb.Element{Value: scalarString(val)})
	}

	if out, err := json.Marshal(v); err == nil {
		s.Output = string(out)
	}

	return s
}

// walkInto appends the child produced by (key, v) onto a container's Tables/Elements slices.
// Script and Table both expose exactly these two slices, so passing pointers to them lets one
// recursion fill either kind of node.
func walkInto(key string, v any, tables *[]*nmappb.Table, elements *[]*nmappb.Element) {
	switch val := v.(type) {
	case map[string]any:
		t := &nmappb.Table{Key: key}
		for _, k := range sortedKeys(val) {
			walkInto(k, val[k], &t.Tables, &t.Elements)
		}
		*tables = append(*tables, t)
	case []any:
		t := &nmappb.Table{Key: key}
		for i, item := range val {
			walkInto(strconv.Itoa(i), item, &t.Tables, &t.Elements)
		}
		*tables = append(*tables, t)
	default:
		*elements = append(*elements, &nmappb.Element{Key: key, Value: scalarString(val)})
	}
}

// scalarString renders a JSON scalar as the string an nmap Element would carry. json.Number
// keeps integers integral; nil becomes empty; everything else falls back to fmt via strconv.
func scalarString(v any) string {
	switch val := v.(type) {
	case nil:
		return ""
	case string:
		return val
	case bool:
		return strconv.FormatBool(val)
	case json.Number:
		return val.String()
	case float64:
		return strconv.FormatFloat(val, 'f', -1, 64)
	default:
		b, _ := json.Marshal(val)
		return string(b)
	}
}

// sortedKeys returns a map's keys in a stable order so the emitted tree is deterministic
// (tests and dedup both depend on stable output for the same input).
func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
