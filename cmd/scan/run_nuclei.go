package scan

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

// `scan run nuclei` is deliberately NOT the server-side, DB-folding shape nmap/masscan are
// (runNmapCommand/runMasscanCommand in run.go, driven by drive.Scanner over the streaming Run RPC):
// nuclei has no drive.Scanner or ingest.Ingestor yet. jsonscript.go's schemaless Script mapping
// already anticipates one ("all zgrab2 modules, and by extension nuclei/httpx/testssl" — see
// scan/scanners.go's ScannerNuclei comment), but building it — deciding how a nuclei finding folds
// into Host/Port, writing the ingestor, wiring `scan import --scanner nuclei` — is real, separate
// work this change does not do.
//
// What nuclei has TODAY is the hardest, highest-cardinality argument surface of any scanner AIMS
// touches: ~13k templates, addressed by path, tag, severity, id, author or protocol type (see
// cmd/completers/nuclei_templates.go). This command is a thin local passthrough purely to give that
// completer a genuine, testable home: it execs the local `nuclei` binary with every token forwarded
// verbatim (the same DisableFlagParsing raw-passthrough contract nmap/masscan use), streaming its
// stdout/stderr straight to the terminal — no server round-trip, no DB write, nothing stored. Once a
// real driver/ingestor exists, this RunE is what gets replaced by the server-side runScanner path.
import (
	"os"
	"os/exec"
	"strings"

	"github.com/carapace-sh/carapace"
	"github.com/spf13/cobra"

	"github.com/d3c3ptive/aims/client"
	"github.com/d3c3ptive/aims/cmd/completers"
	scandomain "github.com/d3c3ptive/aims/scan"
)

// runNucleiCommand wires `aims scan run nuclei [nuclei args...]`. See the file-level comment for why
// this executes locally instead of going through con (the *client.Client is accepted only so this
// leaf's signature matches every other `scan run <scanner>` command, and so it is ready to switch to
// the server-side path the moment a real driver lands — nothing here touches the teamclient yet).
func runNucleiCommand(con *client.Client) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "nuclei [nuclei args...]",
		Short: "Run nuclei locally, forwarding arguments straight through",
		Long: "Run nuclei by passing arguments straight through to the local `nuclei` binary. Unlike\n" +
			"`scan run nmap`/`masscan`, this does NOT run server-side and does NOT store results —\n" +
			"nuclei has no ingest/driver wiring yet (see run_nuclei.go). Everything after `nuclei` is\n" +
			"forwarded verbatim (no `--` needed), with rich completion for templates, tags, severities,\n" +
			"ids, authors and protocol types:\n\n" +
			"    aims scan run nuclei -u https://example.com -t http/technologies/ -severity critical,high\n",
		DisableFlagParsing: true,
		RunE: func(command *cobra.Command, args []string) error {
			return runNucleiLocal(command, args)
		},
	}

	carapace.Gen(cmd).PositionalAnyCompletion(completeRunNuclei(con))

	return cmd
}

// runNucleiLocal execs the local nuclei binary with args forwarded verbatim, inheriting stdio (the
// same passthrough shape cmd/bring/caps.go uses for setcap) so nuclei's own live output — findings,
// progress, colouring — reaches the terminal exactly as a bare `nuclei ...` invocation would.
func runNucleiLocal(command *cobra.Command, args []string) error {
	if len(args) == 0 || (len(args) == 1 && (args[0] == "-h" || args[0] == "--help")) {
		return command.Help()
	}
	if _, err := exec.LookPath(scandomain.ScannerNuclei); err != nil {
		return err
	}

	c := exec.CommandContext(command.Context(), scandomain.ScannerNuclei, args...)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	return c.Run()
}

// nucleiFlagKind classifies a nuclei value-taking flag by what its value's shape is, so
// completeRunNuclei knows what to offer after it — including, deliberately, "nothing": a numeric,
// duration or other free-form flag (e.g. -concurrency) must resolve to an explicit empty action, not
// fall through to the positional-target completer. That fallthrough was a real bug: with no case
// classifying -concurrency, completion after it hit the same "not a flag prefix, so it must be a
// target" fallback the bare positional slot uses, and started proposing hosts.
type nucleiFlagKind int

const (
	nucleiKindFreeform nucleiFlagKind = iota // value-taking, no sensible completion — offer nothing
	nucleiKindEnum                           // a small closed vocabulary, see nucleiEnumValues
	nucleiKindEnumList                       // like nucleiKindEnum, but comma-separated (string[])
	nucleiKindFile
	nucleiKindDir
	nucleiKindTemplates
	nucleiKindWorkflows
	nucleiKindTags
	nucleiKindSeverity
	nucleiKindID
	nucleiKindAuthor
	nucleiKindProtocolType
	nucleiKindProfile
	nucleiKindTarget
	nucleiKindInterface
	nucleiKindSourceAddr
	nucleiKindProxy
)

// nucleiFlagKinds classifies every value-taking nuclei flag — every short and long alias, sourced
// from `nuclei -h` — so completeRunNuclei has a definite answer for any of them. Boolean flags
// (-silent, -debug, …) are deliberately absent: after one of those the next slot is a fresh
// flag/target, which the existing fallthrough already handles correctly; only flags that consume the
// NEXT token as a value need an entry here.
var nucleiFlagKinds = map[string]nucleiFlagKind{
	// templates / workflows / profiles path
	"-t": nucleiKindTemplates, "-templates": nucleiKindTemplates,
	"-it": nucleiKindTemplates, "-include-templates": nucleiKindTemplates,
	"-et": nucleiKindTemplates, "-exclude-templates": nucleiKindTemplates,
	"-w": nucleiKindWorkflows, "-workflows": nucleiKindWorkflows,
	"-tp": nucleiKindProfile, "-profile": nucleiKindProfile,

	// filtering
	"-tags":  nucleiKindTags,
	"-etags": nucleiKindTags, "-exclude-tags": nucleiKindTags,
	"-itags": nucleiKindTags, "-include-tags": nucleiKindTags,
	"-s": nucleiKindSeverity, "-severity": nucleiKindSeverity,
	"-es": nucleiKindSeverity, "-exclude-severity": nucleiKindSeverity,
	"-id": nucleiKindID, "-template-id": nucleiKindID,
	"-eid": nucleiKindID, "-exclude-id": nucleiKindID,
	"-a": nucleiKindAuthor, "-author": nucleiKindAuthor,
	"-pt": nucleiKindProtocolType, "-type": nucleiKindProtocolType,
	"-ept": nucleiKindProtocolType, "-exclude-type": nucleiKindProtocolType,

	// target
	"-u": nucleiKindTarget, "-target": nucleiKindTarget,
	"-eh": nucleiKindTarget, "-exclude-hosts": nucleiKindTarget,

	// local networking
	"-i": nucleiKindInterface, "-interface": nucleiKindInterface,
	"-sip": nucleiKindSourceAddr, "-source-ip": nucleiKindSourceAddr,
	"-p": nucleiKindProxy, "-proxy": nucleiKindProxy,

	// small closed vocabularies (from `nuclei -h`'s own "Possible values"/parenthetical lists)
	"-im": nucleiKindEnum, "-input-mode": nucleiKindEnum,
	"-at": nucleiKindEnum, "-attack-type": nucleiKindEnum,
	"-ft": nucleiKindEnum, "-fuzzing-type": nucleiKindEnum,
	"-fm": nucleiKindEnum, "-fuzzing-mode": nucleiKindEnum,
	"-fa": nucleiKindEnum, "-fuzz-aggression": nucleiKindEnum,
	"-ss": nucleiKindEnum, "-scan-strategy": nucleiKindEnum,
	"-uf": nucleiKindEnum, "-uncover-field": nucleiKindEnum,
	"-iv": nucleiKindEnumList, "-ip-version": nucleiKindEnumList,
	"-te": nucleiKindEnumList, "-track-error": nucleiKindEnumList,
	"-ue": nucleiKindEnumList, "-uncover-engine": nucleiKindEnumList,

	// files (existing readable/writable paths — see cmd/scan's masscan -oX/-oJ precedent)
	"-l": nucleiKindFile, "-list": nucleiKindFile,
	"-r": nucleiKindFile, "-resolvers": nucleiKindFile,
	"-rc": nucleiKindFile, "-report-config": nucleiKindFile,
	"-config": nucleiKindFile,
	"-rdb":    nucleiKindFile, "-report-db": nucleiKindFile,
	"-o": nucleiKindFile, "-output": nucleiKindFile,
	"-vfp": nucleiKindFile, "-var-file-paths": nucleiKindFile,
	"-cc": nucleiKindFile, "-client-cert": nucleiKindFile,
	"-ck": nucleiKindFile, "-client-key": nucleiKindFile,
	"-ca": nucleiKindFile, "-client-ca": nucleiKindFile,
	"-resume": nucleiKindFile,
	"-sf":     nucleiKindFile, "-secret-file": nucleiKindFile,
	"-je": nucleiKindFile, "-json-export": nucleiKindFile,
	"-se": nucleiKindFile, "-sarif-export": nucleiKindFile,
	"-jle": nucleiKindFile, "-jsonl-export": nucleiKindFile,
	"-pe": nucleiKindFile, "-pdf-export": nucleiKindFile,
	"-tlog": nucleiKindFile, "-trace-log": nucleiKindFile,
	"-elog": nucleiKindFile, "-error-log": nucleiKindFile,
	"-profile-mem": nucleiKindFile,

	// directories
	"-srd": nucleiKindDir, "-store-resp-dir": nucleiKindDir,
	"-me": nucleiKindDir, "-markdown-export": nucleiKindDir,
	"-project-path": nucleiKindDir,
	"-ud":           nucleiKindDir, "-update-template-dir": nucleiKindDir,

	// everything else nuclei documents as value-taking has no sensible completion (numeric,
	// duration, free text, a URL nuclei itself will fetch, …). Listed explicitly — rather than left
	// to default through the map's zero value, which happens to also be nucleiKindFreeform, that
	// would be an accident, not a decision — so a reader can tell "considered, no completer" from
	// "not yet considered".
	"-targets-inline": nucleiKindFreeform, "-ai": nucleiKindFreeform, "-prompt": nucleiKindFreeform,
	"-turl": nucleiKindFreeform, "-template-url": nucleiKindFreeform,
	"-wurl": nucleiKindFreeform, "-workflow-url": nucleiKindFreeform,
	"-ntv": nucleiKindFreeform, "-new-templates-version": nucleiKindFreeform,
	"-em": nucleiKindFreeform, "-exclude-matchers": nucleiKindFreeform,
	"-tc": nucleiKindFreeform, "-template-condition": nucleiKindFreeform,
	"-mr": nucleiKindFreeform, "-max-redirects": nucleiKindFreeform,
	"-H": nucleiKindFreeform, "-header": nucleiKindFreeform, // inline "Header: value" or "@file" — no single shape
	"-V": nucleiKindFreeform, "-var": nucleiKindFreeform,
	"-sni": nucleiKindFreeform,
	"-dka": nucleiKindFreeform, "-dialer-keep-alive": nucleiKindFreeform,
	"-rsr": nucleiKindFreeform, "-response-size-read": nucleiKindFreeform,
	"-rss": nucleiKindFreeform, "-response-size-save": nucleiKindFreeform,
	"-hae": nucleiKindFreeform, "-http-api-endpoint": nucleiKindFreeform,
	"-iserver": nucleiKindFreeform, "-interactsh-server": nucleiKindFreeform,
	"-itoken": nucleiKindFreeform, "-interactsh-token": nucleiKindFreeform,
	"-interactions-cache-size": nucleiKindFreeform, "-interactions-eviction": nucleiKindFreeform,
	"-interactions-poll-duration": nucleiKindFreeform, "-interactions-cooldown-period": nucleiKindFreeform,
	"-dtst": nucleiKindFreeform, "-dast-server-token": nucleiKindFreeform,
	"-dtsa": nucleiKindFreeform, "-dast-server-address": nucleiKindFreeform,
	"-fuzz-param-frequency": nucleiKindFreeform,
	"-cs":                   nucleiKindFreeform, "-fuzz-scope": nucleiKindFreeform,
	"-cos": nucleiKindFreeform, "-fuzz-out-scope": nucleiKindFreeform,
	"-uq": nucleiKindFreeform, "-uncover-query": nucleiKindFreeform,
	"-ul": nucleiKindFreeform, "-uncover-limit": nucleiKindFreeform,
	"-ur": nucleiKindFreeform, "-uncover-ratelimit": nucleiKindFreeform,
	"-rl": nucleiKindFreeform, "-rate-limit": nucleiKindFreeform,
	"-rld": nucleiKindFreeform, "-rate-limit-duration": nucleiKindFreeform,
	"-rlm": nucleiKindFreeform, "-rate-limit-minute": nucleiKindFreeform,
	"-bs": nucleiKindFreeform, "-bulk-size": nucleiKindFreeform,
	"-c": nucleiKindFreeform, "-concurrency": nucleiKindFreeform,
	"-hbs": nucleiKindFreeform, "-headless-bulk-size": nucleiKindFreeform,
	"-headc": nucleiKindFreeform, "-headless-concurrency": nucleiKindFreeform,
	"-jsc": nucleiKindFreeform, "-js-concurrency": nucleiKindFreeform,
	"-pc": nucleiKindFreeform, "-payload-concurrency": nucleiKindFreeform,
	"-prc": nucleiKindFreeform, "-probe-concurrency": nucleiKindFreeform,
	"-tlc": nucleiKindFreeform, "-template-loading-concurrency": nucleiKindFreeform,
	"-timeout": nucleiKindFreeform, "-retries": nucleiKindFreeform,
	"-mhe": nucleiKindFreeform, "-max-host-error": nucleiKindFreeform,
	"-irt": nucleiKindFreeform, "-input-read-timeout": nucleiKindFreeform,
	"-page-timeout": nucleiKindFreeform,
	"-ho":           nucleiKindFreeform, "-headless-options": nucleiKindFreeform,
	"-cdpe": nucleiKindFreeform, "-cdp-endpoint": nucleiKindFreeform,
	"-vdl": nucleiKindFreeform, "-var-dump-limit": nucleiKindFreeform,
	"-hpt": nucleiKindFreeform, "-honeypot-threshold": nucleiKindFreeform,
	"-si": nucleiKindFreeform, "-stats-interval": nucleiKindFreeform,
	"-mp": nucleiKindFreeform, "-metrics-port": nucleiKindFreeform,
	"-tid": nucleiKindFreeform, "-team-id": nucleiKindFreeform,
	"-sid": nucleiKindFreeform, "-scan-id": nucleiKindFreeform,
	"-sname": nucleiKindFreeform, "-scan-name": nucleiKindFreeform,
	"-pdu": nucleiKindFreeform, "-dashboard-upload": nucleiKindFreeform,
	"-rd": nucleiKindFreeform, "-redact": nucleiKindFreeform,
}

// nucleiEnumValuesByFlag holds the closed value set for the small, stable vocabularies nuclei
// documents directly in `nuclei -h` (its own "Possible values" / parenthetical lists) — the
// COMPLETERS.md "vocab is stable/small" case, applied to nuclei's own filtering/runtime flags rather
// than AIMS's. No descriptions: each token is short and self-explanatory (the same "don't
// over-describe a small closed set" call made for TemplateTags). Keyed by every alias directly
// (rather than indirecting through nucleiFlagKind) since several kinds share the same "small enum"
// shape but not the same vocabulary.
var nucleiEnumValuesByFlag = map[string][]string{
	"-im":              {"list", "burp", "jsonl", "yaml", "openapi", "swagger"},
	"-input-mode":      {"list", "burp", "jsonl", "yaml", "openapi", "swagger"},
	"-at":              {"batteringram", "pitchfork", "clusterbomb"},
	"-attack-type":     {"batteringram", "pitchfork", "clusterbomb"},
	"-ft":              {"replace", "prefix", "postfix", "infix"},
	"-fuzzing-type":    {"replace", "prefix", "postfix", "infix"},
	"-fm":              {"multiple", "single"},
	"-fuzzing-mode":    {"multiple", "single"},
	"-fa":              {"low", "medium", "high"},
	"-fuzz-aggression": {"low", "medium", "high"},
	"-ss":              {"auto", "host-spray", "template-spray"},
	"-scan-strategy":   {"auto", "host-spray", "template-spray"},
	"-uf":              {"ip", "port", "host"},
	"-uncover-field":   {"ip", "port", "host"},
	"-iv":              {"4", "6"},
	"-ip-version":      {"4", "6"},
	"-te":              {"standard", "file"},
	"-track-error":     {"standard", "file"},
	"-ue": {
		"shodan", "censys", "fofa", "shodan-idb", "quake", "hunter", "zoomeye", "netlas",
		"criminalip", "publicwww", "hunterhow", "google", "odin", "binaryedge", "onyphe",
		"driftnet", "greynoise", "daydaymap", "nerdydata",
	},
	"-uncover-engine": {
		"shodan", "censys", "fofa", "shodan-idb", "quake", "hunter", "zoomeye", "netlas",
		"criminalip", "publicwww", "hunterhow", "google", "odin", "binaryedge", "onyphe",
		"driftnet", "greynoise", "daydaymap", "nerdydata",
	},
}

// completeRunNuclei is the positional-tail completer for `scan run nuclei`, dispatching on the
// preceding token via nucleiFlagKinds — the same DisableFlagParsing shape completeRunNmap/
// completeRunMasscan use. Every flag that takes a template-corpus value reuses the shared completers
// (cmd/completers/nuclei_templates.go); `-u`/`-eh` reuse the DB target completer (con), `-i`/`-sip`
// the local interface/source-address completers, and `-p`/`-proxy` the DB web-URL completer (a proxy
// is URL-shaped, and known web services are a reasonable — if imperfect — set of candidates) — the
// only places this otherwise-local command still touches the teamclient.
func completeRunNuclei(con *client.Client) carapace.Action {
	return carapace.ActionCallback(completers.Guard(scandomain.ScannerNuclei, func(c carapace.Context) carapace.Action {
		if n := len(c.Args); n > 0 {
			if kind, ok := nucleiFlagKinds[c.Args[n-1]]; ok {
				return completeNucleiValue(con, c.Args[n-1], kind)
			}
		}
		if strings.HasPrefix(c.Value, "-") {
			return nucleiFlagCompletions()
		}
		return completers.Targets(con)
	}))
}

// completeNucleiValue renders the completion for one nuclei flag's value, given its classified kind.
func completeNucleiValue(con *client.Client, flag string, kind nucleiFlagKind) carapace.Action {
	switch kind {
	case nucleiKindTemplates:
		return carapace.ActionMultiParts(",", func(carapace.Context) carapace.Action { return completers.Templates() })
	case nucleiKindWorkflows:
		return carapace.ActionMultiParts(",", func(carapace.Context) carapace.Action { return completers.WorkflowTemplates() })
	case nucleiKindTags:
		return carapace.ActionMultiParts(",", func(carapace.Context) carapace.Action { return completers.TemplateTags() })
	case nucleiKindSeverity:
		return carapace.ActionMultiParts(",", func(carapace.Context) carapace.Action { return completers.TemplateSeverities() })
	case nucleiKindID:
		return carapace.ActionMultiParts(",", func(carapace.Context) carapace.Action { return completers.TemplateIDs() })
	case nucleiKindAuthor:
		return carapace.ActionMultiParts(",", func(carapace.Context) carapace.Action { return completers.TemplateAuthors() })
	case nucleiKindProtocolType:
		return carapace.ActionMultiParts(",", func(carapace.Context) carapace.Action { return completers.TemplateProtocolTypes() })
	case nucleiKindProfile:
		return carapace.ActionFiles(".yml", ".yaml")
	case nucleiKindTarget:
		return completers.Targets(con)
	case nucleiKindInterface:
		return completers.Interface()
	case nucleiKindSourceAddr:
		return completers.SourceAddr()
	case nucleiKindProxy:
		return completers.WebURL(con)
	case nucleiKindFile:
		return carapace.ActionFiles()
	case nucleiKindDir:
		return carapace.ActionDirectories()
	case nucleiKindEnum:
		return carapace.ActionValues(nucleiEnumValuesByFlag[flag]...)
	case nucleiKindEnumList:
		values := nucleiEnumValuesByFlag[flag]
		return carapace.ActionMultiParts(",", func(carapace.Context) carapace.Action {
			return carapace.ActionValues(values...)
		})
	default: // nucleiKindFreeform: a value-taking flag with no knowable value set — offer nothing,
		// deliberately, rather than falling through to the target completer.
		return carapace.ActionValues()
	}
}

// nucleiFlagCompletions completes a nuclei `-flag` from nuclei's own full flag catalog
// (curatedNucleiFlags), grouped by classifyNucleiFlag — the same shape masscanFlagCompletions
// uses (no zsh `_nuclei` bridge worth tapping).
func nucleiFlagCompletions() carapace.Action {
	return carapace.ActionValuesDescribed(curatedNucleiFlags()...).TagF(classifyNucleiFlag)
}

// curatedNucleiFlags is nuclei's full flag catalog (name, description), transcribed from
// `nuclei -h` — every flag, not a hand-picked subset. The earlier hand-picked ~30-flag list left
// gaps where a flag's VALUE completed correctly (via nucleiFlagKinds) but its NAME never showed up
// under `-<TAB>` (-input-mode was the reported case) — transcribing the whole catalog once removes
// that class of gap entirely rather than patching it flag by flag. Long forms only (short forms
// exist for nearly all of these — see `nuclei -h` — but the long form is what a reader of a saved
// command line understands without looking it up), sorted alphabetically for easy diffing against
// a future nuclei -h.
func curatedNucleiFlags() []string {
	return []string{
		"-allow-local-file-access", "allows file (payload) access anywhere on the system",
		"-attack-type", "type of payload combinations to perform (batteringram,pitchfork,clusterbomb)",
		"-auth", "configure projectdiscovery cloud (pdcp) api key (default true)",
		"-author", "templates to run based on authors (comma-separated, file)",
		"-automatic-scan", "automatic web scan using wappalyzer technology detection to tags mapping",
		"-bulk-size", "maximum number of hosts to be analyzed in parallel per template (default 25)",
		"-cdp-endpoint", "use remote browser via Chrome DevTools Protocol (CDP) endpoint",
		"-client-ca", "client certificate authority file (PEM-encoded) used for authenticating against scanned hosts",
		"-client-cert", "client certificate file (PEM-encoded) used for authenticating against scanned hosts",
		"-client-key", "client key file (PEM-encoded) used for authenticating against scanned hosts",
		"-cloud-upload", "upload scan results to pdcp dashboard [DEPRECATED use -dashboard]",
		"-code", "enable loading code protocol-based templates",
		"-concurrency", "maximum number of templates to be executed in parallel (default 25)",
		"-config", "path to the nuclei configuration file",
		"-dashboard", "upload / view nuclei results in projectdiscovery cloud (pdcp) UI dashboard",
		"-dashboard-upload", "upload / view nuclei results file (jsonl) in projectdiscovery cloud (pdcp) UI dashboard",
		"-dast", "enable / run dast (fuzz) nuclei templates",
		"-dast-report", "write dast scan report to file",
		"-dast-server", "enable dast server mode (live fuzzing)",
		"-dast-server-address", "dast server address (default \"localhost:9055\")",
		"-dast-server-token", "dast server token (optional)",
		"-debug", "show all requests and responses",
		"-debug-req", "show all sent requests",
		"-debug-resp", "show all received responses",
		"-dialer-keep-alive", "keep-alive duration for network requests.",
		"-disable-clustering", "disable clustering of requests",
		"-disable-redirects", "disable redirects for http templates",
		"-disable-unsigned-templates", "disable running unsigned templates or templates with mismatched signature",
		"-disable-update-check", "disable automatic nuclei/templates update check",
		"-display-fuzz-points", "display fuzz points in the output for debugging",
		"-enable-global-matchers", "enable loading global matchers templates",
		"-enable-pprof", "enable pprof debugging server",
		"-enable-self-contained", "enable loading self-contained templates",
		"-env-vars", "enable environment variables to be used in template",
		"-error-log", "file to write sent requests error log",
		"-exclude-hosts", "hosts to exclude to scan from the input list (ip, cidr, hostname)",
		"-exclude-id", "templates to exclude based on template ids (comma-separated, file)",
		"-exclude-matchers", "template matchers to exclude in result",
		"-exclude-severity", "templates to exclude based on severity. Possible values: info, low, medium, high, critical, unknown",
		"-exclude-tags", "templates to exclude based on tags (comma-separated, file)",
		"-exclude-templates", "path to template file or directory to exclude (comma-separated, file)",
		"-exclude-type", "templates to exclude based on protocol type. Possible values: dns, file, http, headless, tcp, workflow, ssl, websocket, whois, code, javascript",
		"-file", "enable loading file templates",
		"-follow-host-redirects", "follow redirects on the same host",
		"-follow-redirects", "enable following redirects for http templates",
		"-force-http2", "force http2 connection on requests",
		"-fuzz", "enable loading fuzzing templates (Deprecated: use -dast instead)",
		"-fuzz-aggression", "fuzzing aggression level controls payload count for fuzz (low, medium, high) (default \"low\")",
		"-fuzz-out-scope", "out of scope url regex to be excluded by fuzzer",
		"-fuzz-param-frequency", "frequency of uninteresting parameters for fuzzing before skipping (default 10)",
		"-fuzz-scope", "in scope url regex to be followed by fuzzer",
		"-fuzzing-mode", "overrides fuzzing mode set in template (multiple, single)",
		"-fuzzing-type", "overrides fuzzing type set in template (replace, prefix, postfix, infix)",
		"-hang-monitor", "enable nuclei hang monitoring",
		"-header", "custom header/cookie to include in all http request in header:value format (cli, file)",
		"-headless", "enable templates that require headless browser support (root user on Linux will disable sandbox)",
		"-headless-bulk-size", "maximum number of headless hosts to be analyzed in parallel per template (default 10)",
		"-headless-concurrency", "maximum number of headless templates to be executed in parallel (default 10)",
		"-headless-options", "start headless chrome with additional options",
		"-health-check", "run diagnostic check up",
		"-honeypot-detect", "detect potential honeypot hosts based on match concentration",
		"-honeypot-threshold", "number of distinct template IDs required to flag a honeypot host (default 15)",
		"-http-api-endpoint", "experimental http api endpoint",
		"-http-stats", "enable http status capturing (experimental)",
		"-include-rr", "include request/response pairs in the JSON, JSONL, and Markdown outputs (for findings only) [DEPRECATED use -omit-raw] (default true)",
		"-include-tags", "tags to be executed even if they are excluded either by default or configuration",
		"-include-templates", "path to template file or directory to be executed even if they are excluded either by default or configuration",
		"-input-mode", "mode of input file (list, burp, jsonl, yaml, openapi, swagger) (default \"list\")",
		"-input-read-timeout", "timeout on input read (default 3m0s)",
		"-interactions-cache-size", "number of requests to keep in the interactions cache (default 5000)",
		"-interactions-cooldown-period", "extra time for interaction polling before exiting (default 5)",
		"-interactions-eviction", "number of seconds to wait before evicting requests from cache (default 60)",
		"-interactions-poll-duration", "number of seconds to wait before each interaction poll request (default 5)",
		"-interactsh-server", "interactsh server url for self-hosted instance (default: oast.pro,oast.live,oast.site,oast.online,oast.fun,oast.me)",
		"-interactsh-token", "authentication token for self-hosted interactsh server",
		"-interface", "network interface to use for network scan",
		"-ip-version", "IP version to scan of hostname (4,6) - (default 4)",
		"-js-concurrency", "maximum number of javascript runtimes to be executed in parallel (default 120)",
		"-json-export", "file to export results in JSON format",
		"-jsonl", "write output in JSONL(ines) format",
		"-jsonl-export", "file to export results in JSONL(ine) format",
		"-leave-default-ports", "leave default HTTP/HTTPS ports (eg. host:80,host:443)",
		"-list", "path to file containing a list of target URLs/hosts to scan (one per line)",
		"-list-dsl-function", "list all supported DSL function signatures",
		"-list-headless-action", "list available headless actions",
		"-markdown-export", "directory to export results in markdown format",
		"-matcher-status", "display match failure status",
		"-max-host-error", "max errors for a host before skipping from scan (default 30)",
		"-max-redirects", "max number of redirects to follow for http templates (default 10)",
		"-metrics-port", "port to expose nuclei metrics on (default 9092)",
		"-new-templates", "run only new templates added in latest nuclei-templates release",
		"-new-templates-version", "run new templates added in specific version",
		"-no-color", "disable output content coloring (ANSI escape codes)",
		"-no-httpx", "disable httpx probing for non-url input",
		"-no-interactsh", "disable interactsh server for OAST testing, exclude OAST based templates",
		"-no-meta", "disable printing result metadata in cli output",
		"-no-mhe", "disable skipping host from scan based on errors",
		"-no-stdin", "disable stdin processing",
		"-no-strict-syntax", "disable strict syntax check on templates",
		"-omit-raw", "omit request/response pairs in the JSON, JSONL, Markdown, and PDF outputs (for findings only)",
		"-omit-template", "omit encoded template in the JSON, JSONL output",
		"-output", "output file to write found issues/vulnerabilities",
		"-page-timeout", "seconds to wait for each page in headless mode (default 20)",
		"-passive", "enable passive HTTP response processing mode",
		"-payload-concurrency", "max payload concurrency for each template (default 25)",
		"-pdf-export", "file to export results in PDF format",
		"-per-host-rate-limit", "enable per-host rate limiting (global rate limit becomes unlimited when enabled)",
		"-prefetch-secrets", "prefetch secrets from the secrets file",
		"-preflight-portscan", "run preflight resolve + TCP portscan and filter targets before scanning (disabled by default)",
		"-probe-concurrency", "http probe concurrency with httpx (default 50)",
		"-profile", "template profile config file to run",
		"-profile-list", "list community template profiles",
		"-profile-mem", "generate memory (heap) profile & trace files",
		"-project", "use a project folder to avoid sending same request multiple times",
		"-project-path", "set a specific project path (default \"/tmp\")",
		"-prompt", "generate and run template using ai prompt",
		"-proxy", "list of http/socks5 proxy to use (comma separated or file input)",
		"-proxy-internal", "proxy all internal requests",
		"-rate-limit", "maximum number of requests to send per second (default 150)",
		"-rate-limit-duration", "maximum number of requests to send per second (default 1s)",
		"-rate-limit-minute", "maximum number of requests to send per minute (DEPRECATED)",
		"-redact", "redact given list of keys from query parameter, request header and body",
		"-report-config", "nuclei reporting module configuration file",
		"-report-db", "nuclei reporting database (always use this to persist report data)",
		"-required-only", "use only required fields in input format when generating requests",
		"-reset", "reset removes all nuclei configuration and data files (including nuclei-templates)",
		"-resolvers", "file containing resolver list for nuclei",
		"-response-size-read", "max response size to read in bytes",
		"-response-size-save", "max response size to read in bytes (default 1048576)",
		"-restrict-local-network-access", "blocks connections to the local / private network",
		"-resume", "resume scan from and save to specified file (clustering will be disabled)",
		"-retries", "number of times to retry a failed request (default 1)",
		"-sarif-export", "file to export results in SARIF format",
		"-scan-all-ips", "scan all the IP's associated with dns record",
		"-scan-id", "upload scan results to existing scan id (optional)",
		"-scan-name", "scan name to set (optional)",
		"-scan-strategy", "strategy to use while scanning(auto/host-spray/template-spray) (default auto)",
		"-secret-file", "path to config file containing secrets for nuclei authenticated scan",
		"-severity", "templates to run based on severity. Possible values: info, low, medium, high, critical, unknown",
		"-show-browser", "show the browser on the screen when running templates with headless mode",
		"-show-match-line", "show match lines for file templates, works with extractors only",
		"-show-var-dump", "show variables dump for debugging",
		"-sign", "signs the templates with the private key defined in NUCLEI_SIGNATURE_PRIVATE_KEY env variable",
		"-silent", "display findings only",
		"-skip-format-validation", "skip format validation (like missing vars) when parsing input file",
		"-sni", "tls sni hostname to use (default: input domain name)",
		"-source-ip", "source ip address to use for network scan",
		"-stats", "display statistics about the running scan",
		"-stats-interval", "number of seconds to wait between showing a statistics update (default 5)",
		"-stats-json", "display statistics in JSONL(ines) format",
		"-stop-at-first-match", "stop processing HTTP requests after the first match (may break template/workflow logic)",
		"-store-resp", "store all request/response passed through nuclei to output directory",
		"-store-resp-dir", "store all request/response passed through nuclei to custom directory (default \"output\")",
		"-stream", "stream mode - start elaborating without sorting the input",
		"-suppress-honeypot", "suppress output for flagged honeypot hosts",
		"-system-chrome", "use local installed Chrome browser instead of nuclei installed",
		"-system-resolvers", "use system DNS resolving as error fallback",
		"-tags", "templates to run based on tags (comma-separated, file)",
		"-target", "target URLs/hosts to scan",
		"-targets-inline", "inline multiline target list (for use in template profiles)",
		"-team-id", "upload scan results to given team id (optional) (default \"none\")",
		"-template-condition", "templates to run based on expression condition",
		"-template-display", "displays the templates content",
		"-template-id", "templates to run based on template ids (comma-separated, file, allow-wildcard)",
		"-template-loading-concurrency", "maximum number of concurrent template loading operations (default 50)",
		"-template-url", "template url or list containing template urls to run (comma-separated, file)",
		"-templates", "list of template or template directory to run (comma-separated, file)",
		"-templates-version", "shows the version of the installed nuclei-templates",
		"-tgl", "list all available tags",
		"-timeout", "time to wait in seconds before timeout (default 10)",
		"-timestamp", "enables printing timestamp in cli output",
		"-tl", "list all templates matching current filters",
		"-tls-impersonate", "enable experimental client hello (ja3) tls randomization",
		"-trace-log", "file to write sent requests trace log",
		"-track-error", "adds given error to max-host-error watchlist (standard, file)",
		"-type", "templates to run based on protocol type. Possible values: dns, file, http, headless, tcp, workflow, ssl, websocket, whois, code, javascript",
		"-uncover", "enable uncover engine",
		"-uncover-engine", "uncover search engine (shodan,censys,fofa,shodan-idb,quake,hunter,zoomeye,netlas,criminalip,publicwww,hunterhow,google,odin,binaryedge,onyphe,driftnet,greynoise,daydaymap,nerdydata) (default shodan)",
		"-uncover-field", "uncover fields to return (ip,port,host) (default \"ip:port\")",
		"-uncover-limit", "uncover results to return (default 100)",
		"-uncover-query", "uncover search query",
		"-uncover-ratelimit", "override ratelimit of engines with unknown ratelimit (default 60 req/min) (default 60)",
		"-update", "update nuclei engine to the latest released version",
		"-update-template-dir", "custom directory to install / update nuclei-templates",
		"-update-templates", "update nuclei-templates to latest released version",
		"-validate", "validate the passed templates to nuclei",
		"-var", "custom vars in key=value format",
		"-var-dump-limit", "limit the number of characters displayed in var dump (default 255)",
		"-var-file-paths", "list of yaml file contained vars to inject into yaml input",
		"-vars-text-templating", "enable text templating for vars in input file (only for yaml input mode)",
		"-verbose", "show verbose output",
		"-version", "show nuclei version",
		"-vv", "display templates loaded for scan",
		"-workflow-url", "workflow url or list containing workflow urls to run (comma-separated, file)",
		"-workflows", "list of workflow or workflow directory to run (comma-separated, file)",
		"-ztls", "use ztls library with autofallback to standard one for tls13 [Deprecated] autofallback to ztls is enabled by default",
	}
}

// nucleiFlagSections maps each curatedNucleiFlags entry to the section header nuclei's own -h
// groups it under (target, templates, filtering, output, configurations, interactsh, fuzzing,
// uncover, rate limit, optimizations, headless, debug, update, honeypot, statistics, cloud,
// authentication). Reusing nuclei's own grouping is more accurate — and needs no upkeep judgment
// calls — than re-deriving groups from keyword heuristics.
var nucleiFlagSections = map[string]string{
	"-allow-local-file-access":       "configurations",
	"-attack-type":                   "configurations",
	"-auth":                          "cloud",
	"-author":                        "filtering",
	"-automatic-scan":                "templates",
	"-bulk-size":                     "rate limit",
	"-cdp-endpoint":                  "headless",
	"-client-ca":                     "configurations",
	"-client-cert":                   "configurations",
	"-client-key":                    "configurations",
	"-cloud-upload":                  "cloud",
	"-code":                          "templates",
	"-concurrency":                   "rate limit",
	"-config":                        "configurations",
	"-dashboard":                     "cloud",
	"-dashboard-upload":              "cloud",
	"-dast":                          "fuzzing",
	"-dast-report":                   "fuzzing",
	"-dast-server":                   "fuzzing",
	"-dast-server-address":           "fuzzing",
	"-dast-server-token":             "fuzzing",
	"-debug":                         "debug",
	"-debug-req":                     "debug",
	"-debug-resp":                    "debug",
	"-dialer-keep-alive":             "configurations",
	"-disable-clustering":            "configurations",
	"-disable-redirects":             "configurations",
	"-disable-unsigned-templates":    "templates",
	"-disable-update-check":          "update",
	"-display-fuzz-points":           "fuzzing",
	"-enable-global-matchers":        "templates",
	"-enable-pprof":                  "debug",
	"-enable-self-contained":         "templates",
	"-env-vars":                      "configurations",
	"-error-log":                     "debug",
	"-exclude-hosts":                 "target",
	"-exclude-id":                    "filtering",
	"-exclude-matchers":              "filtering",
	"-exclude-severity":              "filtering",
	"-exclude-tags":                  "filtering",
	"-exclude-templates":             "filtering",
	"-exclude-type":                  "filtering",
	"-file":                          "templates",
	"-follow-host-redirects":         "configurations",
	"-follow-redirects":              "configurations",
	"-force-http2":                   "configurations",
	"-fuzz":                          "fuzzing",
	"-fuzz-aggression":               "fuzzing",
	"-fuzz-out-scope":                "fuzzing",
	"-fuzz-param-frequency":          "fuzzing",
	"-fuzz-scope":                    "fuzzing",
	"-fuzzing-mode":                  "fuzzing",
	"-fuzzing-type":                  "fuzzing",
	"-hang-monitor":                  "debug",
	"-header":                        "configurations",
	"-headless":                      "headless",
	"-headless-bulk-size":            "rate limit",
	"-headless-concurrency":          "rate limit",
	"-headless-options":              "headless",
	"-health-check":                  "debug",
	"-honeypot-detect":               "honeypot",
	"-honeypot-threshold":            "honeypot",
	"-http-api-endpoint":             "configurations",
	"-http-stats":                    "statistics",
	"-include-rr":                    "output",
	"-include-tags":                  "filtering",
	"-include-templates":             "filtering",
	"-input-mode":                    "target format",
	"-input-read-timeout":            "optimizations",
	"-interactions-cache-size":       "interactsh",
	"-interactions-cooldown-period":  "interactsh",
	"-interactions-eviction":         "interactsh",
	"-interactions-poll-duration":    "interactsh",
	"-interactsh-server":             "interactsh",
	"-interactsh-token":              "interactsh",
	"-interface":                     "configurations",
	"-ip-version":                    "target",
	"-js-concurrency":                "rate limit",
	"-json-export":                   "output",
	"-jsonl":                         "output",
	"-jsonl-export":                  "output",
	"-leave-default-ports":           "optimizations",
	"-list":                          "target",
	"-list-dsl-function":             "debug",
	"-list-headless-action":          "headless",
	"-markdown-export":               "output",
	"-matcher-status":                "output",
	"-max-host-error":                "optimizations",
	"-max-redirects":                 "configurations",
	"-metrics-port":                  "statistics",
	"-new-templates":                 "templates",
	"-new-templates-version":         "templates",
	"-no-color":                      "output",
	"-no-httpx":                      "optimizations",
	"-no-interactsh":                 "interactsh",
	"-no-meta":                       "output",
	"-no-mhe":                        "optimizations",
	"-no-stdin":                      "optimizations",
	"-no-strict-syntax":              "templates",
	"-omit-raw":                      "output",
	"-omit-template":                 "output",
	"-output":                        "output",
	"-page-timeout":                  "headless",
	"-passive":                       "configurations",
	"-payload-concurrency":           "rate limit",
	"-pdf-export":                    "output",
	"-per-host-rate-limit":           "rate limit",
	"-prefetch-secrets":              "authentication",
	"-preflight-portscan":            "optimizations",
	"-probe-concurrency":             "rate limit",
	"-profile":                       "configurations",
	"-profile-list":                  "configurations",
	"-profile-mem":                   "debug",
	"-project":                       "optimizations",
	"-project-path":                  "optimizations",
	"-prompt":                        "templates",
	"-proxy":                         "debug",
	"-proxy-internal":                "debug",
	"-rate-limit":                    "rate limit",
	"-rate-limit-duration":           "rate limit",
	"-rate-limit-minute":             "rate limit",
	"-redact":                        "output",
	"-report-config":                 "configurations",
	"-report-db":                     "output",
	"-required-only":                 "target format",
	"-reset":                         "configurations",
	"-resolvers":                     "configurations",
	"-response-size-read":            "configurations",
	"-response-size-save":            "configurations",
	"-restrict-local-network-access": "configurations",
	"-resume":                        "target",
	"-retries":                       "optimizations",
	"-sarif-export":                  "output",
	"-scan-all-ips":                  "target",
	"-scan-id":                       "cloud",
	"-scan-name":                     "cloud",
	"-scan-strategy":                 "optimizations",
	"-secret-file":                   "authentication",
	"-severity":                      "filtering",
	"-show-browser":                  "headless",
	"-show-match-line":               "configurations",
	"-show-var-dump":                 "debug",
	"-sign":                          "templates",
	"-silent":                        "output",
	"-skip-format-validation":        "target format",
	"-sni":                           "configurations",
	"-source-ip":                     "configurations",
	"-stats":                         "statistics",
	"-stats-interval":                "statistics",
	"-stats-json":                    "statistics",
	"-stop-at-first-match":           "optimizations",
	"-store-resp":                    "output",
	"-store-resp-dir":                "output",
	"-stream":                        "optimizations",
	"-suppress-honeypot":             "honeypot",
	"-system-chrome":                 "headless",
	"-system-resolvers":              "configurations",
	"-tags":                          "filtering",
	"-target":                        "target",
	"-targets-inline":                "target",
	"-team-id":                       "cloud",
	"-template-condition":            "filtering",
	"-template-display":              "templates",
	"-template-id":                   "filtering",
	"-template-loading-concurrency":  "rate limit",
	"-template-url":                  "templates",
	"-templates":                     "templates",
	"-templates-version":             "debug",
	"-tgl":                           "templates",
	"-timeout":                       "optimizations",
	"-timestamp":                     "output",
	"-tl":                            "templates",
	"-tls-impersonate":               "configurations",
	"-trace-log":                     "debug",
	"-track-error":                   "optimizations",
	"-type":                          "filtering",
	"-uncover":                       "uncover",
	"-uncover-engine":                "uncover",
	"-uncover-field":                 "uncover",
	"-uncover-limit":                 "uncover",
	"-uncover-query":                 "uncover",
	"-uncover-ratelimit":             "uncover",
	"-update":                        "update",
	"-update-template-dir":           "update",
	"-update-templates":              "update",
	"-validate":                      "templates",
	"-var":                           "configurations",
	"-var-dump-limit":                "debug",
	"-var-file-paths":                "target format",
	"-vars-text-templating":          "target format",
	"-verbose":                       "debug",
	"-version":                       "debug",
	"-vv":                            "debug",
	"-workflow-url":                  "templates",
	"-workflows":                     "templates",
	"-ztls":                          "configurations",
}

// classifyNucleiFlag buckets a nuclei flag into its nuclei -h section (nucleiFlagSections),
// falling back to a generic group for anything unrecognised — should not happen, since
// nucleiFlagSections covers every entry curatedNucleiFlags lists.
func classifyNucleiFlag(flag string) string {
	if section, ok := nucleiFlagSections[flag]; ok {
		return section
	}
	return "other nuclei flags"
}
