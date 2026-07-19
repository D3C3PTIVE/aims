package credential

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
	"fmt"
	"strings"

	"github.com/fatih/color"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/d3c3ptive/aims/cmd/display"
	credential "github.com/d3c3ptive/aims/credential/pb"
	provpb "github.com/d3c3ptive/aims/provenance/pb"
)

// Reveal controls whether Private secrets are printed in clear text. It is off by default (list
// views mask secrets); the CLI flips it on for `info` / when `--reveal` is passed.
var Reveal bool

//
// [ Display Contracts ] --------------------------------------------------
//

// DisplayHeaders returns the weighted table headers for a list of credentials.
func DisplayHeaders() (headers []display.Options) {
	add := func(n string, w int) { headers = append(headers, display.WithHeader(n, w)) }

	add("ID", 1)
	add("Public", 1)
	add("Private", 1)
	add("Realm", 1)

	add("Type", 2)
	add("Logins", 2)
	add("Origin", 2)

	add("Updated", 3)

	return headers
}

// DisplayDetails returns the weighted headers for a single-credential `info` view. Weight groups
// become blank-line-separated sections (Identity / Provenance / Classification / Timestamps).
func DisplayDetails() (headers []display.Options) {
	add := func(n string, w int) { headers = append(headers, display.WithHeader(n, w)) }

	// Identity
	add("Public", 1)
	add("Private", 1)
	add("Realm", 1)

	// Provenance
	add("Origin", 2)
	add("Session", 2)
	add("Discovered", 2)

	// Classification
	add("Type", 3)

	// Timestamps
	add("Updated", 4)

	return headers
}

// Completions returns the columns combined into completion candidates and their descriptions.
// Whichever column is chosen as the candidate (via WithCandidateValue) is inserted; the remaining
// columns form the aligned description shown next to it — so a user completing an opaque ID still
// sees who/what/where it is.
func Completions() (headers []display.Options) {
	add := func(n string, w int) { headers = append(headers, display.WithHeader(n, w)) }

	add("ID", 1)
	add("Public", 1)
	add("Private", 2)
	add("Type", 2)
	add("Realm", 3)
	add("Origin", 3)

	return headers
}

// DisplayFields maps column names to per-credential value generators. This is the single source
// of truth feeding the table, the `info` detail view, and completions.
var DisplayFields = map[string]func(c *credential.Core) string{
	"ID": func(c *credential.Core) string {
		// A credential with a usable secret is "loot"; colour it. A bare partial stays dim.
		if c.GetPrivate() != nil {
			return color.HiGreenString(display.FormatSmallID(c.Id))
		}
		return display.FormatSmallID(c.Id)
	},
	"Public":  func(c *credential.Core) string { return publicLabel(c) },
	"Private": func(c *credential.Core) string { return privateLabel(c) },
	"Realm":   func(c *credential.Core) string { return realmLabel(c.GetRealm()) },
	"Type":    func(c *credential.Core) string { return typeLabel(c) },
	"Logins": func(c *credential.Core) string {
		if n := c.GetLoginsCount(); n > 0 {
			return fmt.Sprint(n)
		}
		return ""
	},
	"Origin":     func(c *credential.Core) string { return originLabel(primarySource(c)) },
	"Session":    func(c *credential.Core) string { return primarySource(c).GetSessionId() },
	"Discovered": func(c *credential.Core) string { return fmtTime(c.GetCreatedAt()) },
	"Updated":    func(c *credential.Core) string { return fmtTime(c.GetUpdatedAt()) },
}

//
// [ Derived Insights ] ---------------------------------------------------
//

// Insights returns the cross-set observations for a single credential (see CREDENTIALS.md §5):
// secret reuse, replayability, cracked-from lineage, and validation. `all` is the full set the
// credential is being viewed within (reuse cannot be computed from one credential alone).
func Insights(target *credential.Core, all []*credential.Core) (lines []string) {
	priv := target.GetPrivate()

	if priv != nil {
		switch priv.Type {
		case credential.PrivateType_ReplayableHash,
			credential.PrivateType_NTLMHash,
			credential.PrivateType_PostgresMD5:
			lines = append(lines, "⚡ replayable secret (pass-the-hash capable)")
		}

		// Reuse: the same secret value appearing on other credentials is the highest-signal
		// derived field for a pentester.
		if priv.Data != "" {
			seen := map[string]bool{}
			var others []string
			for _, c := range all {
				if c == target || c.GetPrivate() == nil || c.GetPrivate().Data != priv.Data {
					continue
				}
				label := publicLabel(c)
				if label == "" || seen[label] {
					continue
				}
				seen[label] = true
				others = append(others, label)
			}
			if len(others) > 0 {
				lines = append(lines, fmt.Sprintf("⚠ secret reused by %d other credential(s): %s",
					len(others), strings.Join(others, ", ")))
			}
		}

		// Crackable-but-not-cracked: a hash whose JtR format is known but with no plaintext yet.
		if priv.Type != credential.PrivateType_Password && priv.Type != credential.PrivateType_BlankPassword && priv.JTRFormat != "" {
			lines = append(lines, fmt.Sprintf("crackable (JtR format %q)", priv.JTRFormat))
		}
	}

	// Lineage: cracked from an originating credential.
	if o := primarySource(target); o != nil && o.Type == provpb.SourceType_Cracked {
		if o.Cracker != "" {
			lines = append(lines, fmt.Sprintf("↳ cracked with %s", o.Cracker))
		} else {
			lines = append(lines, "↳ cracked from another credential")
		}
	}

	if target.GetLoginsCount() > 0 {
		lines = append(lines, fmt.Sprintf("✓ used in %d login(s)", target.GetLoginsCount()))
	}

	return lines
}

//
// [ Detail View ] --------------------------------------------------------
//

// Detail assembles the full `info` view for a single credential: the identity banner, the
// side-by-side info panes, and the derived insights (which need the whole set `all` to compute
// secret reuse). It hands these to the shared display.Detail renderer, so a credential's detail
// view is laid out identically to every other domain's.
func Detail(c *credential.Core, all []*credential.Core) display.Detail {
	return display.Detail{
		Title:    bannerTitle(c),
		Badges:   bannerBadges(c),
		Panes:    InfoPanes(c),
		Insights: Insights(c, all),
	}
}

// bannerTitle is the credential identity shown in the banner: "<public> @ <realm>", bold.
func bannerTitle(c *credential.Core) string {
	title := publicLabel(c)
	if r := realmLabel(c.GetRealm()); r != "" {
		title += display.Dim + " @ " + display.Reset + r
	}
	return display.Bold + title + display.Reset
}

// bannerBadges are the credential's status badges (replayable / login count) for the banner.
func bannerBadges(c *credential.Core) (badges []string) {
	if p := c.GetPrivate(); p != nil && isReplayable(p.Type) {
		badges = append(badges, color.HiYellowString("⚡ replayable"))
	}
	if n := c.GetLoginsCount(); n > 0 {
		badges = append(badges, color.HiGreenString("✓ %d login(s)", n))
	}
	return badges
}

// InfoPanes returns the credential's detail grouped into titled panes, for side-by-side layout
// via display.Columns. The grouping mirrors the Details weight-sections (Identity / Provenance /
// Classification) but renders them as columns that pack to the terminal width.
func InfoPanes(c *credential.Core) []display.Pane {
	identity := paneLines([]kvPair{
		{"Public", publicLabel(c)},
		{"Private", privateLabel(c)},
		{"Realm", realmLabel(c.GetRealm())},
	})
	provenance := paneLines([]kvPair{
		{"Origin", originLabel(primarySource(c))},
		{"Session", primarySource(c).GetSessionId()},
		{"Discovered", fmtTime(c.GetCreatedAt())},
	})
	classification := paneLines([]kvPair{
		{"Type", typeLabel(c)},
		{"Updated", fmtTime(c.GetUpdatedAt())},
	})

	return []display.Pane{
		{Title: "Identity", Lines: identity},
		{Title: "Provenance", Lines: provenance},
		{Title: "Classification", Lines: classification},
	}
}

type kvPair struct{ k, v string }

// paneLines renders key/value pairs into aligned "key : value" lines via the shared display
// renderer, so credential detail keys look identical to every other domain's.
func paneLines(pairs []kvPair) []string {
	kv := make([][2]string, len(pairs))
	for i, p := range pairs {
		kv[i] = [2]string{p.k, p.v}
	}
	return display.KVLines(kv)
}

//
// [ Field Formatters ] ---------------------------------------------------
//

func publicLabel(c *credential.Core) string {
	p := c.GetPublic()
	if p == nil {
		return ""
	}
	// Prefer the actual identifier (username, key/cert subject); the kind is carried by the Type
	// column, so we never discard the name for a placeholder.
	if p.Username != "" {
		return p.Username
	}
	switch p.Type {
	case credential.PublicType_PublicKey:
		return "‹public-key›"
	case credential.PublicType_Certificate:
		return "‹certificate›"
	case credential.PublicType_BlankUsername:
		return "(blank)"
	default:
		return ""
	}
}

// privateLabel renders only the (masked) secret; its kind lives in the Type column.
func privateLabel(c *credential.Core) string {
	p := c.GetPrivate()
	if p == nil {
		return color.HiBlackString("—")
	}

	switch p.Type {
	case credential.PrivateType_BlankPassword:
		return "(blank)"
	case credential.PrivateType_Key:
		return "‹key›"
	case credential.PrivateType_JWT:
		return "‹jwt›"
	case credential.PrivateType_NTLMHash:
		return maskNTLM(p.Data)
	case credential.PrivateType_ReplayableHash,
		credential.PrivateType_NonReplayableHash,
		credential.PrivateType_PostgresMD5:
		return maskHash(p.Data)
	default: // Password
		return maskPassword(p.Data)
	}
}

func realmLabel(r *credential.Realm) string {
	if r == nil {
		return ""
	}
	if r.Value != "" {
		return r.Value
	}
	return r.Key
}

// typeLabel is a short classification of the credential, with a ⚡ appended when the secret is
// replayable (pass-the-hash capable). Replayability is folded in here so the list needs no
// separate column.
func typeLabel(c *credential.Core) string {
	if p := c.GetPrivate(); p != nil {
		label := shortPrivateType(p.Type)
		if isReplayable(p.Type) {
			label += " " + color.HiYellowString("⚡")
		}
		return label
	}
	if p := c.GetPublic(); p != nil {
		switch p.Type {
		case credential.PublicType_PublicKey:
			return "pubkey"
		case credential.PublicType_Certificate:
			return "cert"
		}
	}
	return color.HiBlackString("—")
}

// shortPrivateType maps a PrivateType to a compact, column-friendly label.
func shortPrivateType(t credential.PrivateType) string {
	switch t {
	case credential.PrivateType_BlankPassword:
		return "blank"
	case credential.PrivateType_ReplayableHash, credential.PrivateType_NonReplayableHash:
		return "hash"
	case credential.PrivateType_NTLMHash:
		return "ntlm"
	case credential.PrivateType_PostgresMD5:
		return "pg-md5"
	case credential.PrivateType_Key:
		return "key"
	case credential.PrivateType_JWT:
		return "jwt"
	default:
		return "password"
	}
}

// isReplayable reports whether a private secret can be replayed to authenticate elsewhere.
func isReplayable(t credential.PrivateType) bool {
	switch t {
	case credential.PrivateType_ReplayableHash,
		credential.PrivateType_NTLMHash,
		credential.PrivateType_PostgresMD5:
		return true
	}
	return false
}

// primarySource is the single provenance.Source shown where the credential model used to
// carry one Origin. A Core now holds a UNION of Sources (one per contributing tool); for the
// compact "Origin" column and the detail Provenance pane we surface the first (primary) one.
// Safe on a nil/childless Core — returns nil, and the generated getters no-op on nil.
func primarySource(c *credential.Core) *provpb.Source {
	if srcs := c.GetSources(); len(srcs) > 0 {
		return srcs[0]
	}
	return nil
}

func originLabel(o *provpb.Source) string {
	if o == nil {
		return ""
	}
	switch o.Type {
	case provpb.SourceType_Import:
		if o.Filename != "" {
			return fmt.Sprintf("import (%s)", o.Filename)
		}
		return "import"
	case provpb.SourceType_Cracked:
		if o.Cracker != "" {
			return fmt.Sprintf("cracked (%s)", o.Cracker)
		}
		return "cracked"
	case provpb.SourceType_Service:
		// The service is a soft ServiceId reference now (no embedded Service object), so the
		// label can't resolve the service name without a lookup; show the tool if present.
		if o.Tool != "" {
			return fmt.Sprintf("service (%s)", o.Tool)
		}
		return "service"
	case provpb.SourceType_Scan:
		if o.Tool != "" {
			return fmt.Sprintf("scan (%s)", o.Tool)
		}
		return "scan"
	default:
		return "manual"
	}
}

//
// [ Secret Masking ] -----------------------------------------------------
//

func maskPassword(data string) string {
	if Reveal {
		return data
	}
	switch n := len([]rune(data)); {
	case n == 0:
		return ""
	case n <= 2:
		return strings.Repeat("•", n)
	default:
		r := []rune(data)
		dots := n - 2
		if dots > 6 {
			dots = 6
		}
		return string(r[0]) + strings.Repeat("·", dots) + string(r[n-1])
	}
}

func maskHash(data string) string {
	if Reveal {
		return data
	}
	return truncMiddle(data)
}

// maskNTLM shows only the NT half of an "LM:NT" digest — the LM half is almost always the empty
// sentinel and just wastes width — truncated.
func maskNTLM(data string) string {
	if Reveal {
		return data
	}
	if _, nt, ok := strings.Cut(data, ":"); ok {
		return truncMiddle(nt)
	}
	return truncMiddle(data)
}

// truncMiddle shortens a long hex digest to "head…tail" while keeping short values intact.
func truncMiddle(data string) string {
	if len(data) <= 10 {
		return data
	}
	return data[:4] + "…" + data[len(data)-4:]
}

func fmtTime(t *timestamppb.Timestamp) string {
	if t == nil {
		return ""
	}
	tt := t.AsTime()
	if tt.IsZero() {
		return ""
	}
	return tt.Format("2006-01-02 15:04")
}
