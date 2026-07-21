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

// The nuclei template completers. Like Interface/SourceAddr (values.go), these are local-only — a
// nuclei template is a file on the machine running the CLI, not a DB object, so there is no
// *client.Client, no agent-context promotion, no teamserver round-trip. The shared engine (index
// build + on-disk cache + templates-root discovery) lives in nuclei_index.go; this file is just the
// per-flag rendering, one function per nuclei flag family:
//
//   - Templates             -t/-templates, -it/-include-templates, -et/-exclude-templates
//   - WorkflowTemplates     -w/-workflows — Templates scoped to the workflows/ subdirectory
//   - TemplateTags          -tags, -etags/-exclude-tags, -itags/-include-tags
//   - TemplateSeverities    -s/-severity, -es/-exclude-severity
//   - TemplateIDs           -id/-template-id, -eid/-exclude-id
//   - TemplateAuthors       -a/-author
//   - TemplateProtocolTypes -pt/-type, -ept/-exclude-type
//
// Every completer sub-groups its candidates by a meaningful axis (directory vs. severity, frequent
// vs. long-tail, severity rank) rather than presenting one flat list — the standing project
// preference (CLAUDE.md "sub-categorized completions") applied to the axis each flag actually has.
import (
	"fmt"
	"sort"
	"strings"

	"github.com/carapace-sh/carapace"
)

// noTemplatesMessage is the shared degrade when the index is empty — an uninstalled or not-yet-
// updated nuclei-templates checkout, not a code error, so it reads as an instruction rather than a
// stack of Go plumbing.
func noTemplatesMessage(root string) carapace.Action {
	return carapace.ActionMessage("no nuclei templates found under %s (run `nuclei -update-templates`?)", root)
}

//
// [ Templates — path-based, multipart directory-by-directory completion ] -----------------------
//

// Templates completes a template/workflow path slot by walking the local nuclei-templates tree one
// path segment at a time (carapace.ActionMultiParts, the same primitive ActionFiles/ActionDirectories
// are built on — see internalActions.go). Each level renders two sub-groups:
//
//   - "directories": the next path segment for every subdirectory still below the typed prefix,
//     described by how many templates it contains, so `-t http/<TAB>` conveys "cves/ (2841
//     templates)" without opening a shell;
//   - "<severity> severity": the template files directly in this directory, grouped and ordered by
//     severity (critical first) and described by name — so a directory mixing a critical RCE
//     detector with a dozen "info" tech-fingerprint templates surfaces the one that matters first.
//
// Directory candidates end in "/", which ActionMultiParts's shared NoSpace('/') handling (see its
// doc comment) lets the shell continue typing into rather than treating as a finished argument;
// template files have no trailing "/" and take a normal trailing space, since they are a complete,
// terminal value for the flag.
func Templates() carapace.Action {
	return carapace.ActionMultiParts("/", func(c carapace.Context) carapace.Action {
		idx, err := loadTemplateIndex()
		if err != nil {
			return carapace.ActionMessage("nuclei templates: %s", err)
		}
		if len(idx.Entries) == 0 {
			return noTemplatesMessage(idx.Root)
		}

		prefix := ""
		if len(c.Parts) > 0 {
			prefix = strings.Join(c.Parts, "/") + "/"
		}
		dirCounts, files := childrenAt(idx.Entries, prefix)
		if len(dirCounts) == 0 && len(files) == 0 {
			return carapace.ActionMessage("no templates under %s", prefix)
		}

		actions := make([]carapace.Action, 0, len(severityOrder)+1)
		if len(dirCounts) > 0 {
			actions = append(actions, carapace.ActionValuesDescribed(dirLabels(dirCounts)...).Tag("directories"))
		}

		bySeverity := make(map[string][]string, len(severityOrder))
		for _, f := range files {
			name := strings.TrimPrefix(f.Path, prefix)
			sev := f.Severity
			if sev == "" {
				sev = "unknown"
			}
			bySeverity[sev] = append(bySeverity[sev], name, templateDescription(f))
		}
		for _, sev := range severityOrder {
			if pairs, ok := bySeverity[sev]; ok {
				actions = append(actions, carapace.ActionValuesDescribed(pairs...).Tag(sev+" severity"))
			}
		}

		return carapace.Batch(actions...).ToA()
	})
}

// WorkflowTemplates completes `-w`/`-workflows` scoped to the workflows/ subdirectory: the operator
// never has to type "workflows/" themselves — completion behaves as if it were already typed — but
// the value nuclei receives still carries it, since nuclei resolves -w paths relative to the
// templates root/CWD the same way it does -t.
//
// The trick is a context rewrite rather than a second index or a parallel rendering path: prepending
// "workflows/" to c.Value before delegating to Templates() makes carapace's own ActionMultiParts
// split it into c.Parts=["workflows", ...] exactly as if the operator had typed it, so every other
// mechanic (directory counts, severity grouping, the NoSpace('/') continuation) is inherited for
// free. c.Args is untouched — Templates never reads it.
func WorkflowTemplates() carapace.Action {
	return carapace.ActionCallback(func(c carapace.Context) carapace.Action {
		c.Value = "workflows/" + c.Value
		return Templates().Invoke(c).ToA()
	})
}

// childrenAt splits the flat index into what a path completer needs to show for one directory level:
// the immediate subdirectories below prefix (each counted, not listed, since only the count is
// shown) and the template entries that are direct children (leaf files, no further "/").
func childrenAt(entries []templateEntry, prefix string) (dirCounts map[string]int, files []templateEntry) {
	dirCounts = make(map[string]int)
	for _, e := range entries {
		rest := e.Path
		if prefix != "" {
			if !strings.HasPrefix(e.Path, prefix) {
				continue
			}
			rest = e.Path[len(prefix):]
		}
		if rest == "" {
			continue
		}
		if dir, _, ok := strings.Cut(rest, "/"); ok {
			dirCounts[dir]++
		} else {
			files = append(files, e)
		}
	}
	return dirCounts, files
}

// dirLabels renders a directory's (name, template count) pairs, sorted alphabetically, each name
// suffixed with "/" for the multipart NoSpace continuation.
func dirLabels(dirCounts map[string]int) []string {
	names := make([]string, 0, len(dirCounts))
	for name := range dirCounts {
		names = append(names, name)
	}
	sort.Strings(names)
	pairs := make([]string, 0, len(names)*2)
	for _, name := range names {
		pairs = append(pairs, name+"/", templateCountLabel(dirCounts[name]))
	}
	return pairs
}

// templateDescription is a template file candidate's description: its severity (restated even though
// severity is also the Tag group, since a shell without Tag-group rendering, e.g. bash, only ever
// shows the description) followed by its human name.
func templateDescription(e templateEntry) string {
	name := e.Name
	if name == "" {
		name = e.ID
	}
	if name == "" {
		name = e.Path
	}
	sev := e.Severity
	if sev == "" {
		sev = "unknown"
	}
	return fmt.Sprintf("[%s] %s", sev, name)
}

func templateCountLabel(n int) string {
	if n == 1 {
		return "1 template"
	}
	return fmt.Sprintf("%d templates", n)
}

//
// [ Tags / Authors — frequency-bucketed, the long-tail-vocabulary shape ] ------------------------
//

// templateFrequencyCutoff is how many of the most-used values (tags, authors) surface under
// "common …" ahead of the long tail under "other …". The corpus carries thousands of one-off tags
// (a single CVE id used as its own tag, a one-time contributor); without this split, the handful an
// operator actually reaches for (cve, wordpress, rce, …) would be buried alphabetically among them.
const templateFrequencyCutoff = 30

// TemplateTags completes a `-tags`/`-etags`/`-exclude-tags`/`-itags` value with every tag seen across
// the indexed corpus, frequency-bucketed (see templateFrequencyCutoff). No descriptions: a tag's name
// already says what it is, and with ~8k of them a description column buys nothing worth the noise.
func TemplateTags() carapace.Action {
	idx, err := loadTemplateIndex()
	if err != nil {
		return carapace.ActionMessage("nuclei templates: %s", err)
	}
	if len(idx.Entries) == 0 {
		return noTemplatesMessage(idx.Root)
	}
	counts := make(map[string]int)
	for _, e := range idx.Entries {
		for _, t := range e.Tags {
			counts[t]++
		}
	}
	return bucketedByFrequency(counts, "tags", false)
}

// TemplateAuthors completes a `-a`/`-author` value with every contributor credited across the
// indexed corpus, frequency-bucketed the same way as TemplateTags — described by template count,
// since a name alone (unlike a tag) doesn't convey how prolific/relevant an author is.
func TemplateAuthors() carapace.Action {
	idx, err := loadTemplateIndex()
	if err != nil {
		return carapace.ActionMessage("nuclei templates: %s", err)
	}
	if len(idx.Entries) == 0 {
		return noTemplatesMessage(idx.Root)
	}
	counts := make(map[string]int)
	for _, e := range idx.Entries {
		for _, a := range e.Author {
			counts[a]++
		}
	}
	return bucketedByFrequency(counts, "authors", true)
}

// bucketedByFrequency renders a value->count map as two carapace tag groups, "common <noun>" (the
// top templateFrequencyCutoff values) and "other <noun>" (the long tail), each sorted by count
// descending then alphabetically. describe controls whether each candidate carries a "N templates"
// description (TemplateAuthors) or just the bare value (TemplateTags) — the only other difference
// between the two flags is which field is counted.
func bucketedByFrequency(counts map[string]int, noun string, describe bool) carapace.Action {
	ranked := rankByFrequency(counts)

	build := carapace.ActionValues
	if describe {
		build = carapace.ActionValuesDescribed
	}

	var common, rest []string
	for i, value := range ranked {
		entry := []string{value}
		if describe {
			entry = append(entry, templateCountLabel(counts[value]))
		}
		if i < templateFrequencyCutoff {
			common = append(common, entry...)
		} else {
			rest = append(rest, entry...)
		}
	}

	var actions []carapace.Action
	if len(common) > 0 {
		actions = append(actions, build(common...).Tag("common "+noun))
	}
	if len(rest) > 0 {
		actions = append(actions, build(rest...).Tag("other "+noun))
	}
	if len(actions) == 0 {
		return carapace.ActionValues()
	}
	return carapace.Batch(actions...).ToA()
}

// rankByFrequency orders counts' keys by count descending, then alphabetically — the pure ranking
// logic behind bucketedByFrequency's common/other split, pulled out so it is testable without going
// through carapace.Action (which has no exported way to inspect its rendered candidates). Empty keys
// are dropped: they mean "no tag"/"no author" recorded, not a real value to offer.
func rankByFrequency(counts map[string]int) []string {
	type ranked struct {
		value string
		n     int
	}
	all := make([]ranked, 0, len(counts))
	for v, n := range counts {
		if v == "" {
			continue
		}
		all = append(all, ranked{v, n})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].n != all[j].n {
			return all[i].n > all[j].n
		}
		return all[i].value < all[j].value
	})
	out := make([]string, len(all))
	for i, r := range all {
		out[i] = r.value
	}
	return out
}

//
// [ Severities / IDs — severity-grouped ] ---------------------------------------------------------
//

// TemplateSeverities completes a `-s`/`-severity`/`-es`/`-exclude-severity` value with nuclei's own
// closed severity vocabulary (info/low/medium/high/critical/unknown — see severityOrder), each
// described by how many indexed templates currently carry it. This is exactly the "vocab is
// stable/small" case COMPLETERS.md calls out for a static described list — except the counts are
// live against the operator's actual installed corpus rather than hand-maintained, so they stay
// correct across `nuclei -update-templates` for free.
func TemplateSeverities() carapace.Action {
	idx, err := loadTemplateIndex()
	if err != nil {
		return carapace.ActionMessage("nuclei templates: %s", err)
	}
	if len(idx.Entries) == 0 {
		return noTemplatesMessage(idx.Root)
	}
	counts := make(map[string]int, len(severityOrder))
	for _, e := range idx.Entries {
		sev := e.Severity
		if sev == "" {
			sev = "unknown"
		}
		counts[sev]++
	}
	pairs := make([]string, 0, len(severityOrder)*2)
	for _, sev := range severityOrder {
		if n, ok := counts[sev]; ok {
			pairs = append(pairs, sev, templateCountLabel(n))
		}
	}
	if len(pairs) == 0 {
		return carapace.ActionValues()
	}
	return carapace.ActionValuesDescribed(pairs...)
}

// TemplateIDs completes a `-id`/`-template-id`/`-eid`/`-exclude-id` value with every template id in
// the indexed corpus, grouped by severity (critical first — see severityOrder) and described by the
// template's human name, so `-id <TAB>` lets an operator browse "what critical-severity checks does
// nuclei even have" rather than needing to already know an id.
func TemplateIDs() carapace.Action {
	idx, err := loadTemplateIndex()
	if err != nil {
		return carapace.ActionMessage("nuclei templates: %s", err)
	}
	if len(idx.Entries) == 0 {
		return noTemplatesMessage(idx.Root)
	}
	bySeverity := make(map[string][]string, len(severityOrder))
	for _, e := range idx.Entries {
		if e.ID == "" {
			continue
		}
		sev := e.Severity
		if sev == "" {
			sev = "unknown"
		}
		desc := e.Name
		if desc == "" {
			desc = e.Path
		}
		bySeverity[sev] = append(bySeverity[sev], e.ID, desc)
	}

	actions := make([]carapace.Action, 0, len(severityOrder))
	for _, sev := range severityOrder {
		if pairs, ok := bySeverity[sev]; ok {
			actions = append(actions, carapace.ActionValuesDescribed(pairs...).Tag(sev+" severity"))
		}
	}
	if len(actions) == 0 {
		return carapace.ActionValues()
	}
	return carapace.Batch(actions...).ToA()
}

//
// [ Protocol types — nuclei's own closed vocabulary, no index needed ] ---------------------------
//

// templateProtocolTypes is nuclei's documented `-pt`/`-type` vocabulary (from `nuclei -h`, FILTERING
// section). Unlike severity this is not derived from the index: nuclei validates it against this
// exact closed set regardless of which templates happen to be installed, so hardcoding it (the
// COMPLETERS.md "stable/small vocab" case) is both correct and avoids paying for an index load on a
// flag whose value set never depends on the corpus.
var templateProtocolTypes = []string{
	"dns", "Templates using the DNS protocol",
	"file", "Templates matching against local files",
	"http", "Templates using the HTTP(S) protocol",
	"headless", "Templates driving a headless browser",
	"tcp", "Templates using raw TCP/network protocols",
	"workflow", "Templates that are workflows chaining other templates",
	"ssl", "Templates probing TLS/SSL configuration",
	"websocket", "Templates using the WebSocket protocol",
	"whois", "Templates using the WHOIS protocol",
	"code", "Templates executing local code snippets",
	"javascript", "Templates executing embedded JavaScript",
}

// TemplateProtocolTypes completes a `-pt`/`-type`/`-ept`/`-exclude-type` value.
func TemplateProtocolTypes() carapace.Action {
	return carapace.ActionValuesDescribed(templateProtocolTypes...)
}
