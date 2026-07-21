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

// This file is the engine behind the nuclei template completers (nuclei_templates.go): it locates
// the local nuclei-templates checkout, walks it into a flat metadata index (id/name/severity/tags
// per template), and caches that index on disk so a Tab press never re-parses ~13k YAML files.
//
// This is deliberately NOT built on the aims.CacheCompletion/CompletionCacheTTL convention every
// other completer in this package uses (see plumbing.go, cmd/cache.go). That convention fits a
// DB-backed completion: cheap to rebuild, invalidated by a 10s TTL plus a local-mutation epoch.
// Neither half fits here:
//   - rebuilding is NOT cheap — parsing the whole corpus takes low seconds (see BenchmarkBuildIndex),
//     so a 10s TTL would re-pay that cost every few keystrokes during an active completion session;
//   - there is no "local mutation epoch" — the templates only change via `nuclei -update-templates`,
//     which is nuclei's own concern, not AIMS's.
// nuclei already ships the right invalidation signal: `templates-checksum.txt`, a manifest that
// changes exactly when the template set does. That checksum, not a timer, is the cache key — so the
// index is rebuilt only when the corpus actually changed, and never spuriously in between. Because
// the cached artifact is a flat metadata slice consumed by four different completers (path, tags,
// severities, ids) in four different shapes, it is cached as our own small JSON file (mirroring the
// pattern completionEpochPath already uses for a tiny sentinel) rather than forced into carapace's
// Action-level cache, which caches one rendered candidate list per call site, not raw data.
import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/carapace-sh/carapace/pkg/cache/key"
	"gopkg.in/yaml.v3"
)

// severityOrder fixes the presentation order for every severity-grouped completer: the findings an
// operator cares about most (critical) lead, "unknown" (an empty/unrecognised info.severity) trails.
var severityOrder = []string{"critical", "high", "medium", "low", "info", "unknown"}

// templateEntry is one template's completion-relevant metadata, parsed from its `id:` and `info:`
// header. Everything else in the file (the actual request/matcher logic) is irrelevant to
// completion and deliberately never parsed (see templateHeaderBytes).
type templateEntry struct {
	// Path is the template's location relative to the templates root, forward-slash separated
	// regardless of OS (e.g. "http/technologies/wordpress-eol.yaml") — the candidate value the
	// path-based completer (Templates) assembles segment by segment.
	Path string `json:"path"`
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
	// Author is one or more names — info.author is nuclei's own comma-separated-or-list
	// convention (see templateTagList) — kept as a slice (rather than joined) so the author
	// completer can count each contributor individually.
	Author   []string `json:"author,omitempty"`
	Severity string   `json:"severity,omitempty"`
	Tags     []string `json:"tags,omitempty"`
}

// templateIndex is the full parsed corpus plus the manifest checksum it was built from — the unit
// this package caches on disk (see readCachedIndex/writeCachedIndex).
type templateIndex struct {
	Root     string          `json:"root"`
	Checksum string          `json:"checksum"`
	Entries  []templateEntry `json:"entries"`
}

// templatesRootEnv lets a caller (chiefly tests) point completion at a fixture directory instead of
// the real ~/nuclei-templates, and is also the escape hatch for an operator with a non-default
// install. AIMS-owned — nuclei itself has no such variable; its own source of truth is the
// `.templates-config.json` this falls back to reading.
const templatesRootEnv = "AIMS_NUCLEI_TEMPLATES_DIR"

// templatesRoot locates the local nuclei-templates checkout: an explicit override, then nuclei's own
// `.templates-config.json` (written by `nuclei -update-templates`, the authoritative source since an
// operator can point nuclei at a custom directory), then the documented default `~/nuclei-templates`.
func templatesRoot() (string, error) {
	if dir := os.Getenv(templatesRootEnv); dir != "" {
		return dir, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	if dir := templatesDirFromConfig(filepath.Join(home, ".config", "nuclei", ".templates-config.json")); dir != "" {
		return dir, nil
	}
	return filepath.Join(home, "nuclei-templates"), nil
}

// templatesDirFromConfig reads nuclei's own config for the "nuclei-templates-directory" key. Any
// failure (missing file, bad JSON, empty value) is silently absorbed — the caller falls back to the
// documented default, which is the right degrade for a nuclei install that predates this file or a
// config that has moved on.
func templatesDirFromConfig(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var cfg struct {
		Dir string `json:"nuclei-templates-directory"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return ""
	}
	return cfg.Dir
}

// manifestChecksum is the cache-invalidation signal for the whole index: nuclei writes
// templates-checksum.txt on every `-update-templates`, so its content hash changes exactly when the
// corpus does. A directory with no such manifest (a hand-rolled or very old templates checkout) falls
// back to the root directory's own mtime — coarser (a touch without content change still invalidates)
// but still correct: it never serves a stale index past an actual update.
func manifestChecksum(root string) (string, error) {
	manifest := filepath.Join(root, "templates-checksum.txt")
	if _, err := os.Stat(manifest); err == nil {
		return key.FileChecksum(manifest)()
	}
	return key.FileStats(root)()
}

// templateIndexCachePath is the on-disk home for the cached index, alongside the completion epoch
// sentinel this package's sibling (cmd.CacheCompletion) uses — both live under the user's cache dir
// so a `rm -rf ~/.cache/aims` clears every AIMS completion cache uniformly.
func templateIndexCachePath() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "aims", "nuclei-templates-index.json"), nil
}

// loadTemplateIndex is the single entry point every template completer calls: resolve the templates
// root, check the on-disk cache against the current manifest checksum, and rebuild only on a miss.
// The rebuild (buildTemplateIndex) is the only expensive path here — a cache hit is a single small
// JSON read, cheap enough to pay on every keystroke.
func loadTemplateIndex() (*templateIndex, error) {
	root, err := templatesRoot()
	if err != nil {
		return nil, err
	}
	checksum, err := manifestChecksum(root)
	if err != nil {
		// No manifest and an unreadable root: nothing to index, but not a hard error — the
		// completers degrade to "no templates found" rather than an opaque failure.
		return &templateIndex{Root: root}, nil
	}

	if cached, ok := readCachedIndex(root, checksum); ok {
		return cached, nil
	}

	entries, err := buildTemplateIndex(root)
	if err != nil {
		return nil, err
	}
	idx := &templateIndex{Root: root, Checksum: checksum, Entries: entries}
	writeCachedIndex(idx) // best-effort: a failed write only means the next Tab rebuilds too
	return idx, nil
}

func readCachedIndex(root, checksum string) (*templateIndex, bool) {
	path, err := templateIndexCachePath()
	if err != nil {
		return nil, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	var idx templateIndex
	if err := json.Unmarshal(data, &idx); err != nil {
		return nil, false
	}
	if idx.Root != root || idx.Checksum != checksum {
		return nil, false
	}
	return &idx, true
}

func writeCachedIndex(idx *templateIndex) {
	path, err := templateIndexCachePath()
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return
	}
	data, err := json.Marshal(idx)
	if err != nil {
		return
	}
	_ = os.WriteFile(path, data, 0o600)
}

// buildTemplateIndex walks root for every *.yaml/*.yml template and parses its header, fanned out
// across a bounded worker pool — the corpus is ~13k small files, and parsing them one at a time is
// the whole cost this package exists to amortise (see the file-level comment).
func buildTemplateIndex(root string) ([]templateEntry, error) {
	var paths []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil // best-effort: an unreadable entry is skipped, not a fatal walk error
		}
		if d.IsDir() {
			switch {
			case path != root && strings.HasPrefix(d.Name(), "."):
				return filepath.SkipDir
			case d.Name() == "helpers":
				// Wordlists and includes, not templates — no id/info header to parse.
				return filepath.SkipDir
			}
			return nil
		}
		switch filepath.Ext(path) {
		case ".yaml", ".yml":
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	entries := make([]templateEntry, len(paths))
	workers := max(runtime.NumCPU(), 1)
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for i, p := range paths {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, p string) {
			defer wg.Done()
			defer func() { <-sem }()
			entries[i] = parseTemplateFile(root, p)
		}(i, p)
	}
	wg.Wait()

	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return entries, nil
}

// parseTemplateFile parses one template's id/info header into a templateEntry. A file that fails to
// read or parse still yields an entry carrying just its Path — it stays completable by the
// path-based completer even without metadata, rather than vanishing from the index entirely.
func parseTemplateFile(root, path string) templateEntry {
	rel := filepath.ToSlash(strings.TrimPrefix(path, root+string(filepath.Separator)))
	entry := templateEntry{Path: rel}

	data, err := os.ReadFile(path)
	if err != nil {
		return entry
	}
	var header templateHeader
	if err := yaml.Unmarshal(templateHeaderBytes(data), &header); err != nil {
		return entry
	}
	entry.ID = header.ID
	entry.Name = header.Info.Name
	entry.Author = header.Info.Author
	entry.Severity = strings.ToLower(strings.TrimSpace(header.Info.Severity))
	entry.Tags = header.Info.Tags
	return entry
}

// templateHeader is the only slice of a template's YAML this package ever unmarshals.
type templateHeader struct {
	ID   string `yaml:"id"`
	Info struct {
		Name     string          `yaml:"name"`
		Author   templateTagList `yaml:"author"`
		Severity string          `yaml:"severity"`
		Tags     templateTagList `yaml:"tags"`
	} `yaml:"info"`
}

// templateTagList decodes nuclei's info.tags/info.author convention, which is a comma-separated
// scalar string in every template in the wild (verified against the full upstream corpus) but is
// decoded leniently as a YAML sequence too — a defensive fallback, not a documented format, so a
// future or third-party template that lists tags as a block sequence still parses instead of
// silently dropping the whole header.
type templateTagList []string

func (t *templateTagList) UnmarshalYAML(node *yaml.Node) error {
	var scalar string
	if err := node.Decode(&scalar); err == nil {
		*t = splitTagList(scalar)
		return nil
	}
	var list []string
	if err := node.Decode(&list); err == nil {
		*t = list
		return nil
	}
	// Neither shape: leave the field empty rather than failing the whole template's parse over one
	// malformed sub-field.
	return nil
}

func splitTagList(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// templateHeaderBytes trims a template file down to the bytes worth handing to the YAML decoder: the
// leading `id:` line plus the whole `info:` block, stopping at the next top-level key (the protocol
// block — http/dns/network/…, or workflows/matchers). Templates routinely carry large matcher/
// extractor bodies (regex lists, DSL expressions) that a full-document unmarshal would parse only to
// discard; skipping them roughly halves index-build time on the full corpus (see
// BenchmarkBuildIndex) for zero loss, since nothing outside id/info feeds a templateEntry.
func templateHeaderBytes(data []byte) []byte {
	var out strings.Builder
	sawInfo := false
	for line := range strings.SplitSeq(string(data), "\n") {
		if key, isTop := topLevelKey(line); isTop {
			switch key {
			case "info":
				sawInfo = true
			case "id":
				// still part of the header, keep going
			default:
				if sawInfo {
					return []byte(out.String())
				}
			}
		}
		out.WriteString(line)
		out.WriteByte('\n')
	}
	return []byte(out.String())
}

// topLevelKey reports whether line opens a new top-level YAML mapping key (column 0, not a comment)
// and, if so, the key name.
func topLevelKey(line string) (key string, ok bool) {
	if line == "" || line[0] == ' ' || line[0] == '\t' || line[0] == '#' {
		return "", false
	}
	i := strings.IndexByte(line, ':')
	if i <= 0 {
		return "", false
	}
	return line[:i], true
}
