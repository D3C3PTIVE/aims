package completers

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
	"os"
	"path/filepath"
	"testing"
)

// BenchmarkBuildTemplateIndex measures the one cost this whole package exists to amortise: parsing
// the real, locally-installed nuclei-templates corpus (~13k files) into a templateEntry index. It
// only ever runs against an operator's real checkout — there is no fixture standing in for ~13k
// upstream templates — so, like TestNmapScanLive, it is guarded behind an explicit opt-in rather than
// running in CI: set AIMS_NUCLEI_TEMPLATES_IT=1 (and optionally AIMS_NUCLEI_TEMPLATES_DIR to point at
// a non-default checkout; otherwise ~/nuclei-templates, nuclei's documented default, is used).
//
// This is the number templateHeaderBytes's truncation optimisation (see its doc comment) is measured
// against: a full-document yaml.Unmarshal of every file took ~2.7s parallel on the reference corpus
// (13,412 templates, 4 cores); truncating each file to its id/info header first brought that to
// ~1.5s — the gap a large matcher/extractor body (regex lists, DSL expressions) costs to parse and
// then discard.
func BenchmarkBuildTemplateIndex(b *testing.B) {
	if os.Getenv("AIMS_NUCLEI_TEMPLATES_IT") == "" {
		b.Skip("set AIMS_NUCLEI_TEMPLATES_IT=1 to run (requires a local nuclei-templates checkout)")
	}
	root := os.Getenv(templatesRootEnv)
	if root == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			b.Fatalf("resolve home directory: %v", err)
		}
		root = filepath.Join(home, "nuclei-templates")
	}
	if _, err := os.Stat(root); err != nil {
		b.Skipf("templates root %s not found: %v", root, err)
	}

	for b.Loop() {
		entries, err := buildTemplateIndex(root)
		if err != nil {
			b.Fatalf("buildTemplateIndex: %v", err)
		}
		if len(entries) == 0 {
			b.Fatalf("expected a non-empty index under %s", root)
		}
	}
}
