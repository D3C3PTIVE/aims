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
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// writeFile is the fixture helper every test in this file uses to lay out a synthetic
// nuclei-templates checkout under t.TempDir().
func writeFile(t *testing.T, root, rel, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

const sampleTemplate = `id: wordpress-eol
info:
  name: WordPress End-of-Life - Detect
  author: Shivam Kamboj
  severity: info
  description: |
    Detected WordPress versions that have reached End-of-Life.
  tags: tech,wordpress,eol

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: word
        words:
          - "wordpress"
`

// TestTemplateHeaderBytes pins the truncation contract: everything through the info: block is
// kept, the first sibling top-level key (here "http:") is where it stops — so the large
// matcher/request body below is never handed to the YAML decoder.
func TestTemplateHeaderBytes(t *testing.T) {
	header := templateHeaderBytes([]byte(sampleTemplate))
	if !strings.Contains(string(header), "id: wordpress-eol") {
		t.Fatalf("header dropped the id line: %q", header)
	}
	if !strings.Contains(string(header), "tags: tech,wordpress,eol") {
		t.Fatalf("header dropped the info block: %q", header)
	}
	if strings.Contains(string(header), "http:") || strings.Contains(string(header), "matchers:") {
		t.Fatalf("header did not stop before the protocol block: %q", header)
	}
}

// TestTemplateHeaderBytesNoTrailingBlock covers a header with nothing after info: (some
// workflows/profiles) — the whole file is kept, not truncated away.
func TestTemplateHeaderBytesNoTrailingBlock(t *testing.T) {
	src := "id: only-header\ninfo:\n  name: Only Header\n  severity: info\n"
	header := templateHeaderBytes([]byte(src))
	if strings.TrimRight(string(header), "\n") != strings.TrimRight(src, "\n") {
		t.Fatalf("expected header-only file to pass through unchanged, got %q", header)
	}
}

// TestTopLevelKey checks the column-0/non-comment/has-colon classification the truncator relies on.
func TestTopLevelKey(t *testing.T) {
	cases := []struct {
		line   string
		key    string
		isTop  bool
		reason string
	}{
		{"id: foo", "id", true, "simple top-level key"},
		{"  name: foo", "", false, "indented, not top-level"},
		{"# id: foo", "", false, "comment line"},
		{"", "", false, "blank line"},
		{"info:", "info", true, "bare key with no inline value"},
		{"just text no colon", "", false, "no colon at all"},
	}
	for _, c := range cases {
		key, isTop := topLevelKey(c.line)
		if key != c.key || isTop != c.isTop {
			t.Errorf("%s: topLevelKey(%q) = (%q, %v), want (%q, %v)", c.reason, c.line, key, isTop, c.key, c.isTop)
		}
	}
}

// TestTemplateTagListUnmarshal covers both shapes info.tags/info.author appear in: the documented
// comma-separated scalar (every real template) and the defensive block-sequence fallback.
func TestTemplateTagListUnmarshal(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want []string
	}{
		{"comma scalar", "tags: cve,wordpress,rce", []string{"cve", "wordpress", "rce"}},
		{"comma scalar with spaces", "tags: cve, wordpress , rce", []string{"cve", "wordpress", "rce"}},
		{"empty scalar", "tags: \"\"", nil},
		{"block sequence", "tags:\n  - cve\n  - wordpress", []string{"cve", "wordpress"}},
		{"single value", "tags: cve", []string{"cve"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var v struct {
				Tags templateTagList `yaml:"tags"`
			}
			if err := yaml.Unmarshal([]byte(c.yaml), &v); err != nil {
				t.Fatalf("unmarshal %q: %v", c.yaml, err)
			}
			if !reflect.DeepEqual([]string(v.Tags), c.want) {
				t.Errorf("got %#v, want %#v", []string(v.Tags), c.want)
			}
		})
	}
}

// TestParseTemplateFile exercises the real read+truncate+unmarshal path end to end against a
// realistic template on disk, including the relative, forward-slash Path the path completer needs.
func TestParseTemplateFile(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "http/technologies/wordpress-eol.yaml", sampleTemplate)

	entry := parseTemplateFile(root, filepath.Join(root, "http", "technologies", "wordpress-eol.yaml"))
	if entry.Path != "http/technologies/wordpress-eol.yaml" {
		t.Errorf("Path = %q, want forward-slash relative path", entry.Path)
	}
	if entry.ID != "wordpress-eol" {
		t.Errorf("ID = %q", entry.ID)
	}
	if entry.Name != "WordPress End-of-Life - Detect" {
		t.Errorf("Name = %q", entry.Name)
	}
	if entry.Severity != "info" {
		t.Errorf("Severity = %q", entry.Severity)
	}
	if !reflect.DeepEqual(entry.Tags, []string{"tech", "wordpress", "eol"}) {
		t.Errorf("Tags = %#v", entry.Tags)
	}
	if !reflect.DeepEqual(entry.Author, []string{"Shivam Kamboj"}) {
		t.Errorf("Author = %#v", entry.Author)
	}
}

// TestParseTemplateFileMissingOrMalformed proves a file that cannot be read or parsed still yields a
// Path-only entry — it stays completable by the path-based completer rather than vanishing from the
// index entirely.
func TestParseTemplateFileMissingOrMalformed(t *testing.T) {
	root := t.TempDir()

	missing := parseTemplateFile(root, filepath.Join(root, "http", "gone.yaml"))
	if missing.Path == "" || missing.ID != "" {
		t.Errorf("missing file: got %#v, want Path set and metadata empty", missing)
	}

	writeFile(t, root, "http/bad.yaml", "id: [this is not valid: yaml: :::")
	bad := parseTemplateFile(root, filepath.Join(root, "http", "bad.yaml"))
	if bad.Path != "http/bad.yaml" || bad.ID != "" {
		t.Errorf("malformed file: got %#v, want Path set and metadata empty", bad)
	}
}

// TestBuildTemplateIndex covers the walk itself: nested directories are found, non-template
// extensions and the helpers/ tree (wordlists, not templates) are excluded, and results are sorted.
func TestBuildTemplateIndex(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "http/technologies/wordpress-eol.yaml", sampleTemplate)
	writeFile(t, root, "dns/generic-nameserver-fingerprint.yaml", "id: dns-tpl\ninfo:\n  name: DNS\n  severity: low\n")
	writeFile(t, root, "workflows/smb-workflow.yaml", "id: smb-workflow\ninfo:\n  name: SMB Checks\n  author: x\n")
	writeFile(t, root, "helpers/wordlists/users.txt", "admin\nroot\n")
	writeFile(t, root, "profiles/default-login.yml", "templates:\n  - http/default-logins/\n")
	writeFile(t, root, "README.md", "not a template")
	writeFile(t, root, ".git/HEAD", "ref: refs/heads/main")

	entries, err := buildTemplateIndex(root)
	if err != nil {
		t.Fatalf("buildTemplateIndex: %v", err)
	}

	var paths []string
	for _, e := range entries {
		paths = append(paths, e.Path)
	}
	want := []string{
		"dns/generic-nameserver-fingerprint.yaml",
		"http/technologies/wordpress-eol.yaml",
		"profiles/default-login.yml",
		"workflows/smb-workflow.yaml",
	}
	if !reflect.DeepEqual(paths, want) {
		t.Fatalf("paths = %#v, want %#v (sorted, helpers/.git/README excluded)", paths, want)
	}
	if !sort.StringsAreSorted(paths) {
		t.Errorf("entries not sorted by path")
	}
}

// TestTemplatesRootEnvOverride proves the AIMS-owned override wins over everything else — the escape
// hatch tests (and non-default installs) rely on.
func TestTemplatesRootEnvOverride(t *testing.T) {
	t.Setenv(templatesRootEnv, "/fixture/templates")
	root, err := templatesRoot()
	if err != nil {
		t.Fatalf("templatesRoot: %v", err)
	}
	if root != "/fixture/templates" {
		t.Errorf("root = %q, want override honoured", root)
	}
}

// TestTemplatesDirFromConfig covers reading nuclei's own .templates-config.json, and that a missing
// or malformed config degrades to "" (letting the caller fall back) rather than erroring.
func TestTemplatesDirFromConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, ".templates-config.json")

	if got := templatesDirFromConfig(cfgPath); got != "" {
		t.Errorf("missing config: got %q, want empty", got)
	}

	if err := os.WriteFile(cfgPath, []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := templatesDirFromConfig(cfgPath); got != "" {
		t.Errorf("malformed config: got %q, want empty", got)
	}

	cfg, _ := json.Marshal(map[string]string{"nuclei-templates-directory": "/opt/nuclei-templates"})
	if err := os.WriteFile(cfgPath, cfg, 0o644); err != nil {
		t.Fatal(err)
	}
	if got := templatesDirFromConfig(cfgPath); got != "/opt/nuclei-templates" {
		t.Errorf("got %q, want /opt/nuclei-templates", got)
	}
}

// TestManifestChecksumTracksManifestContent proves the primary invalidation path: two roots with
// identical templates-checksum.txt content hash identically, and editing the manifest (as
// `nuclei -update-templates` would) changes the checksum.
func TestManifestChecksumTracksManifestContent(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "templates-checksum.txt", "http/foo.yaml:abc123\n")

	sum1, err := manifestChecksum(root)
	if err != nil {
		t.Fatalf("manifestChecksum: %v", err)
	}

	writeFile(t, root, "templates-checksum.txt", "http/foo.yaml:def456\n")
	sum2, err := manifestChecksum(root)
	if err != nil {
		t.Fatalf("manifestChecksum: %v", err)
	}

	if sum1 == sum2 {
		t.Errorf("checksum did not change when manifest content changed")
	}
}

// TestManifestChecksumFallsBackWithoutManifest covers a templates root with no
// templates-checksum.txt (a hand-rolled or non-standard checkout): it must still produce a usable
// key rather than erroring the whole index load.
func TestManifestChecksumFallsBackWithoutManifest(t *testing.T) {
	root := t.TempDir()
	sum, err := manifestChecksum(root)
	if err != nil {
		t.Fatalf("manifestChecksum without manifest: %v", err)
	}
	if sum == "" {
		t.Errorf("expected a non-empty fallback checksum")
	}
}

// TestLoadTemplateIndexCachesUntilManifestChanges is the integration proof of the whole engine's
// point: a rebuild only happens when templates-checksum.txt changes, not on every call.
func TestLoadTemplateIndexCachesUntilManifestChanges(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	root := t.TempDir()
	t.Setenv(templatesRootEnv, root)

	writeFile(t, root, "templates-checksum.txt", "v1\n")
	writeFile(t, root, "http/one.yaml", "id: one\ninfo:\n  name: One\n  severity: info\n")

	idx1, err := loadTemplateIndex()
	if err != nil {
		t.Fatalf("first load: %v", err)
	}
	if len(idx1.Entries) != 1 {
		t.Fatalf("first load: got %d entries, want 1", len(idx1.Entries))
	}

	// Add a template WITHOUT bumping the manifest — this must NOT appear yet (cache hit).
	writeFile(t, root, "http/two.yaml", "id: two\ninfo:\n  name: Two\n  severity: info\n")
	idx2, err := loadTemplateIndex()
	if err != nil {
		t.Fatalf("second load: %v", err)
	}
	if len(idx2.Entries) != 1 {
		t.Fatalf("second load: got %d entries, want 1 (should be served from cache, manifest unchanged)", len(idx2.Entries))
	}

	// Bump the manifest, as `nuclei -update-templates` would — now the new template must appear.
	writeFile(t, root, "templates-checksum.txt", "v2\n")
	idx3, err := loadTemplateIndex()
	if err != nil {
		t.Fatalf("third load: %v", err)
	}
	if len(idx3.Entries) != 2 {
		t.Fatalf("third load: got %d entries, want 2 (manifest changed, must rebuild)", len(idx3.Entries))
	}
}

// TestLoadTemplateIndexNoRoot covers a templates root that does not exist at all (nuclei never
// installed / never updated): the completers must degrade to an empty index, not a hard error.
func TestLoadTemplateIndexNoRoot(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	t.Setenv(templatesRootEnv, filepath.Join(t.TempDir(), "does-not-exist"))

	idx, err := loadTemplateIndex()
	if err != nil {
		t.Fatalf("loadTemplateIndex on missing root: %v", err)
	}
	if len(idx.Entries) != 0 {
		t.Errorf("expected no entries for a missing templates root, got %d", len(idx.Entries))
	}
}
