# AIMS — Deduplication & Merge Contract

> Written 2026-07-19 by the scan-domain agent, *for the agent(s) implementing CRUD on
> scanner-produced objects*. Companion to [`CLAUDE.md`](./CLAUDE.md) (architecture),
> [`SCAN.md`](./SCAN.md) (scan model & scanner-plug substrate) and
> [`CREDENTIALS.md`](./CREDENTIALS.md) (the credential domain's own merge model, which this
> generalizes). This file answers: *when a scanner pushes objects into the DB, how do we avoid
> duplicates without ever destroying real data?*
>
> This is a **contract and a rationale**, not an API spec. It tells you the invariants every
> Create/Upsert path must honor and why. Implement it per-domain following the shapes here.

## 0. The prime directive

**Ingest is additive and idempotent, never destructive.** Re-importing the same scan must be a
no-op. Importing an *overlapping* scan must produce the **union** of what both scans observed —
never the intersection, never "last writer wins the whole row." The word *delete* should not
appear anywhere in an ingest path. Deletion is a separate, explicit, user-driven operation.

If you remember one sentence from this document, make it this asymmetry:

> **A missed dedup is a duplicate row — a cosmetic nuisance a user can merge later.
> A wrong merge is silent data loss — two different real-world objects collapsed into one,
> unrecoverable. Bias every threshold, every tie-break, and every ambiguous case toward
> _keep both / keep more_.**

Everything below is a consequence of that asymmetry.

## 1. Two problems, do not conflate them: *match* vs *merge*

Today the code conflates them, and that is the core defect to fix.

- **Match** — "do these two records denote the *same real-world thing*?" Answered by the
  `AreXIdentical` comparators (`host/identical.go:30`, `scan/identical.go:29`,
  `network/identical.go`) — weighted-score-over-threshold booleans.
- **Merge** — "given they are the same, how do I combine their fields without losing evidence?"
  Answered *properly* only in `credential/merge.go:36` (`MergeCore`, the four field-classes).

The problem: `internal/db.FilterNew` (`internal/db/db.go:27`) is wired as **match-then-drop**.
`server/host/host.go:101` does `db.FilterNew(new, existing, AreHostsIdentical)` and then only
`Create`s the survivors. So a new observation that *matches* an existing host is **discarded
whole** — every port, script, and OS guess it carried is thrown away, even the fields the old
row lacked. That is the exact "deletes data it should not" failure the CRUD agent must avoid.

**The fix in one line:** `FilterNew` should partition into *(new, matched)* pairs, and the
matched pairs must go through a **merge** step, not the bin. Drop is only correct when merge
proves the incoming record is a strict subset of the stored one (i.e. `changed == false`).

## 2. Matching: keyed-first, fuzzy-as-candidate-only, always scoped

Two ways to decide identity; use them in this order:

1. **Natural key (preferred).** When an object has a stable natural key, key on it and let the
   DB enforce uniqueness. Examples:
   - Host: MAC, else the set of addresses.
   - Port: `(hostID, protocol, number)`.
   - Service: `(hostID, port, protocol)`.
   - Credential: the identity triple `(public?, private?, realm?)` — see `CREDENTIALS.md §2`.
   - Opaque script/blob: `(parentScope, scriptID, sha256(normalizedContent))` — see §6.
   Keyed matching is O(1) per object, exact, and pushes down into a DB unique index / `ON
   CONFLICT`. Prefer it wherever a key exists.

2. **Fuzzy weighted score (fallback only).** The `AreXIdentical` scorers exist because some
   objects have *no* reliable key (a host seen only by an idle-scan with no MAC, no hostname).
   Fuzzy matching is legitimate — but treat its output as a **candidate**, not a verdict:
   - Use it only to narrow a *bucket* of plausible matches (see §7 blocking), never as a global
     O(n·m) sweep.
   - **Tune the threshold for false-split, not false-merge.** Per §0, when the score is near the
     line, *do not merge*. A duplicate host is recoverable; a merged pair of distinct hosts is
     not. The current thresholds (`host` ≥10, `scan` ≥ maxScore/2) were set for convenience —
     re-derive them against the no-false-merge test (§10) before trusting them at scale.

**Both kinds of match are scoped (see §3).** You never match a port against every port in the
DB — only against ports of the *already-matched host*.

## 3. The unit of ingest is a graph — dedup it scoped and recursively

A scan `Result` is not a flat row. It is a tree:

```
Host ── Ports ── Service
  │        └──── Scripts ── Elements / Tables ── (extracted: credentials, certs, vulns, …)
  ├── OS / OSMatch[]
  ├── Trace ── Hops
  └── HostScripts ── …
```

Dedup must walk this tree with a strict rule:

> **A child is only ever matched within the scope of its matched parent.**
> Match the Host first. *Then*, inside that host, match each Port. *Then*, inside each Port,
> match each Script. A port `443/tcp` from scan B is the same row as `443/tcp` in the DB **only
> because they hang off the same matched host** — never because two hosts both happen to expose
> 443.

This is precisely what a flat `FilterNew(allNewPorts, allExistingPorts, …)` gets wrong.
Consequences for the CRUD agent:

- **Decide top-down, merge bottom-up.** Resolve the host identity first (it scopes everything
  under it); then recurse. But apply field merges from the leaves up, so a parent's "changed"
  bit correctly reflects changes in its children.
- **New parent ⇒ everything under it is new.** If the host is genuinely new, skip all child
  matching — insert the subtree wholesale. Child matching only matters when the parent matched.
- **Use GORM associations deliberately.** `FullSaveAssociations` / `clause.OnConflict` can do a
  lot, but the default association upsert will *replace* a has-many set, not union it. Do the
  scoped match in Go, assemble the merged subtree, then persist — don't hand a half-merged tree
  to GORM and hope.

## 4. The field-merge contract (generalize the credential model)

Once two records are matched, merge field-by-field by **field class**. The credential domain
already defines four classes (`CREDENTIALS.md §3`, `credential/merge.go`). Adopt them verbatim
and add two that scan data forces on us. Every merge function returns `changed bool` (skip
no-op writes — cheap, and it kills field churn):

| Class | Rule on conflict | Examples |
|---|---|---|
| **Identity** | Cannot conflict — if it differs, it's a *different object* (goes back to §2 match, not merge). Set once. | Host addresses/MAC, `(host,proto,port)`, credential triple |
| **Fill-only** | Known value is never clobbered by empty; empty is filled from the incoming. | `Private.JTRFormat`, `OS.Vendor`, service `Product`/`Version` when one scan left it blank |
| **First-wins (provenance)** | Preserve the *original* discovery; don't overwrite "cracked by john" with a later "seen on service". | `Origin`, `CreatedAt`, first-seen Run |
| **Derived** | Never taken from the wire; recomputed from children after merge. | `LoginsCount`, host up/down tallies, `Stats.Hosts` |
| **Observation (append-only)** — *added for scan data* | **Never overwrite; append.** Each observation keeps its own evidence + Run provenance. This is the nmap philosophy (see §5). | port `Status{state,reason,reason_ttl}`, `OSMatch[]` accuracies, `ExtraPort.Reasons[]`, every NSE `Script` output |
| **Latest-wins-with-history** — *added for scan data* | Current value is the newest *by observation timestamp* (not by arrival order), but the prior value is retained as an Observation. | "current" port state, "current" hostname |

The two new classes are the whole reason scan ingest is harder than credential ingest: scanners
report **evidence about volatile state**, and the model was built (from nmap) to keep that
evidence, not flatten it.

## 5. State is a reduction over an append-only observation log (the nmap philosophy)

nmap's model — which AIMS inherits — is that **every assertion carries its evidence and
confidence**: a port is `open` *because* `reason=syn-ack reason_ttl=64`; the OS is not a string
but a ranked `OSMatch[]` with accuracies. SCAN.md §A calls this out; the merge path is where it
lives or dies.

Therefore, when two scans disagree — scan A at 10:00 says `443/tcp open (syn-ack)`, scan B at
14:00 says `443/tcp filtered (no-response)`:

- **Do not overwrite.** Overwriting is the data loss §0 forbids. The disagreement *is
  information* (the service went down, a firewall rule changed, someone's blocking you).
- Keep **both** observations, each tagged with its Run and timestamp.
- The object's *current* `Status` is a **reduction** (newest-by-timestamp, or
  highest-confidence) over that observation log — a derived value, not the stored truth.
- A contradiction across observations is a first-class signal: surface it (a `--history` view,
  a "state changed" flag), don't erase it.

Practically, `Status` / `OSMatch` / script outputs behave like the **Observation** class in §4.
If the current proto can't hold multiple observations per field, that's a `.proto` gap to flag
(add a Run reference + timestamp to the observation-bearing messages, regenerate) — *not* a
license to overwrite. Until then, the conservative fallback is: keep the higher-confidence
observation and record in provenance that a conflicting one was seen.

## 6. The schemaless frontier: NSE scripts, `Result.Data`, and extracted objects

This is the user's hard case: *"scanners may gather very different things such as credentials as
NSE script elements."* An NSE `Script` (`scan/pb/nmap/nmap.proto:11`) is a recursive
`Elements[]` / `Tables[]` tree of arbitrary key/values, and `Result.Data` is an opaque blob.
You cannot write a typed comparator for every possible payload. Two rules resolve it:

### 6.1 Route typed extractions to their home domain — dedup there, not at the blob

If an NSE script (or a zgrab module, or `Result.Data`) yields something that **is a first-class
AIMS object** — a credential, a certificate, a host, a service — do **not** dedup it as script
text. **Extract it, construct the real object, and route it through that domain's own matcher
and merger.** A password found by `ssh-brute` and the same password found by a Metasploit login
are the *same credential* and must converge on one `credential.Core` via the triple identity
(`CREDENTIALS.md §2`) — regardless of which script's blob carried it. Dedup happens at the
identity of the *extracted thing*, never at the wrapper that transported it.

This keeps the schemaless frontier thin: the generic `jsonToScript()` walker (SCAN.md §D) is for
*storage of unstructured evidence*; the moment a payload has a real identity, it leaves the blob
world and becomes a normal domain object with a normal keyed merge.

### 6.2 Genuinely opaque content ⇒ content-hash identity, never fuzzy-merge

For evidence that has no first-class home (raw `ssl-cert` dump text, an `http-title`, an
arbitrary tool's JSON): treat it as an **Observation** (§4, append-only) whose identity is

```
scriptIdentity = ( parentScope, script.Id/Name, sha256(normalize(content)) )
```

- Same hash under the same parent ⇒ same observation ⇒ idempotent no-op (this is what makes
  re-import free).
- Different hash ⇒ a *different* observation ⇒ **keep both**. Two script runs that produced
  different output are two facts, not a conflict to resolve. Never fuzzy-merge opaque blobs and
  never "update" one script's output with another's — you'd be inventing a fact no scanner
  reported.
- `normalize()` should strip only provably-insignificant noise (trailing whitespace, timestamp
  lines the scanner injects) so that a genuinely-identical re-scan hashes equal. Be conservative:
  when unsure whether a difference is significant, treat it as significant (keep both).

## 7. Provenance & reversible ingest

Because ingest is additive and objects are *shared* across scans, deletion needs care too — the
same asymmetry applies in reverse. If host H was observed by scans A, B, and C, "delete scan B"
must **not** delete H (A and C still assert it). Achieve this by making merges provenance-aware:

- Every merged assertion/observation records **which Run contributed it** (a Run reference on the
  Observation, or a join row). This is already latent in the model — `Result` carries a Run ref,
  `Run` owns `Targets`/`Results`.
- "Delete scan B" then means **subtract B's contributions**: remove observations whose only
  provenance was B; leave anything A or C also asserted. An object with zero remaining
  observations becomes eligible for GC — never force-deleted while another Run still vouches.
- This makes ingest auditable and reversible, which is the honest way to let users undo a bad
  import without nuking shared truth.

## 8. Efficiency (so "reliable" doesn't mean "quadratic")

Reliability first, but the current `FilterNew` is an O(n·m) nested loop running the *full*
weighted comparator on every pair (`internal/db/db.go:32`). That is fine for a 5-host import and
falls over on a /16 masscan. Make it fast without weakening it:

1. **Block, then compare.** Bucket incoming *and* candidate objects by a cheap natural key
   (address, `(host,proto,port)`, content-hash) into a map. Only run the expensive fuzzy
   comparator *within a bucket*. This turns O(n·m) into ~O(n) with small buckets, and it's
   strictly more reliable (you never compare a host against an obviously-unrelated one).
2. **Load candidates by key, not the whole table.** `server/host/host.go:100` preloads and
   `Find`s existing rows to diff in memory. At scale, query only the candidate set (`WHERE
   address IN (…)`), don't table-scan.
3. **Push exact identity into the DB.** For keyed objects, a unique index + `clause.OnConflict{
   DoNothing / DoUpdates }` makes the DB enforce idempotency atomically and handles the race
   where two scans ingest the same host concurrently. In-Go matching still owns the *fuzzy* and
   *merge-by-field-class* logic the DB can't express.
4. **The `changed` bit is an optimization too.** Every merge returns whether it altered anything
   (`credential/merge.go` already does); skip the UPDATE when nothing changed. Re-importing an
   identical scan should issue *zero* writes.
5. **One transaction per Result subtree.** Match + merge + persist a host and its children
   atomically, so a crash mid-ingest can't leave a half-merged host.

## 9. Reliability test posture (the invariants, as tests)

These properties are the definition of "correct dedup." Write them as tests before trusting the
engine on real scans:

- **Idempotence.** `import X; import X` ⇒ DB byte-identical to `import X` (same row counts, no
  field churn, zero writes on the second import). This is the single most important test.
- **Union / monotonic enrichment.** Import a host with only ports, then the same host with only
  an OS guess ⇒ **one** host carrying *both*. Nothing that was present disappears. Ever.
- **No false merge.** Two genuinely distinct hosts with coincidental overlap (same one open
  port, no MAC) stay **two** hosts. Tune §2 thresholds against this test, not vibes.
- **Order independence.** `import A; import B` and `import B; import A` ⇒ identical final DB for
  everything except Latest-wins fields — and those must resolve by **observation timestamp**, not
  arrival order, so they're deterministic too. (Merge should be commutative/associative for the
  append-only and fill-only classes; verify it.)
- **Conflict retention.** Ingest contradicting port states from two timestamps ⇒ both
  observations retained, current state = newest, history queryable (§5).
- **Extraction convergence.** The same credential arriving via an NSE script blob and via the
  credential domain ⇒ one `Core` (§6.1).

## 10. What to tell the CRUD agent, concretely

Do:
- Split `FilterNew` into **match → {new, merge-pairs}**; send merge-pairs through a field-class
  merger, insert only true-new. Never drop a matched record without first merging its fields in.
- Give every domain a `MergeX(dst, src) (changed bool)` alongside its `AreXIdentical`, modeled on
  `credential/merge.go`. Classify **every** field into one of the six classes in §4 — no field
  gets merged by accident.
- Scope child dedup by matched parent (§3). Decide top-down, merge bottom-up.
- Route extracted first-class objects to their domain (§6.1); content-hash the rest (§6.2).
- Make merges provenance-aware so deletes can subtract, not nuke (§7).
- Bucket before you fuzzy-compare (§8.1); return and honor the `changed` bit.

Don't:
- Don't overwrite a non-empty field with an empty or a contradicting one — append or keep-both.
- Don't fuzzy-match across parent scopes, and don't fuzzy-merge opaque blobs.
- Don't let a near-threshold fuzzy score cause a merge — split instead (§0 asymmetry).
- Don't put `delete`/`replace` semantics anywhere in the ingest path.
- Don't hand a partially-merged has-many set to GORM's association upsert expecting a union.

### Suggested first slice
1. Refactor `internal/db.FilterNew` → a match/merge partition that also returns the matched
   pairs (keep the keyed-identity path the credential agent is adding in `internal/db`,
   `CREDENTIALS.md §8.2`, as the fast path; fuzzy as fallback).
2. Implement `host.MergeHost` (the richest graph — ports/OS/scripts) as the reference, exactly as
   `server/host/host.go` Create is the reference today. Wire it into `Create`/`Upsert`.
3. Implement `scan.Run.AddResult` (`scan/scan.go:89`, currently a stub) as the folding entry
   point that runs the scoped match/merge for an ingested `Result` and attaches Run provenance.
4. Land the §9 idempotence + union + no-false-merge tests first; they're the safety net for
   everything above.

---

## Addendum — worked Port/Service example & credential-reference caveats (2026-07-19, CRUD/CLI agent)

> Added while picking **Services** as the second dedup guinea pig (after credentials). This
> grounds §2–§5 against the *actual* proto and reports what the credential slice does and does
> not already give an implementer. It refines, it does not override, anything above.

### A. The CLI "Service" is `host.Port`, not `network.Service`

The `services` command renders **`host.Port`** objects — it reads hosts and flattens `h.Ports`
(`cmd/services/services.go:180`). `network.Service` is a sub-message hanging off the port
(`Port.Service`, single, `belongs_to`), carrying Product/Version/ExtraInfo/Method/Name. So §2's
two separate keys — Port `(hostID,proto,number)` and Service `(hostID,port,proto)` — **collapse
onto one key in practice**: the Port *is* the service, and its `Service` sub-message is
enrichment, not a separately-identified row. Dedup Services = dedup Ports.

### B. Worked field-class table for `host.Port` (fills the §4/§10 "classify every field" duty)

Field homes are from `host/pb/port.proto`:

| Proto field | Cardinality | §4 class | Note |
|---|---|---|---|
| `Port.Number`, `Port.Protocol` (+ parent `hostID`) | single | **Identity** | the natural key; never merged |
| `Port.Service.Product/Version/Name/Method/ExtraInfo` | single msg | **Fill-only** | one scan blank, another populated → fill; genuine *conflict* (two different products) is rare but must **keep higher-confidence + record the other**, never clobber |
| `Port.State{State,Reason,ReasonIP,ReasonTTL}` | **single msg** | **Observation / Latest-wins-with-history** | ⚠️ see proto gap C1 — cannot hold history today |
| `Port.Scripts[]` (`many_to_many`) | **repeated** | **Observation (append)** | append works natively; identity = content-hash per §6.2 |
| `Port.Reasons[]`, `ExtraPort.Reasons[]` | repeated | **Observation (append)** | extra closed/filtered reasons — union |
| `Port.Owner`, `Port.Count` | single | Fill-only | |
| `Port.CreatedAt` | single | **First-wins** | |

### C. Proto gaps this exposes (per §5's "flag it, don't overwrite")

- **C1 — `Port.State` is a single message, so port-state history is not representable.** Two
  scans disagreeing (`open syn-ack` at 10:00 vs `filtered no-response` at 14:00) cannot both be
  stored on the port as §5 wants. Until the proto grows a repeated observation (a `State` with a
  Run ref + timestamp, or a `StateObservation[]`), apply §5's conservative fallback: **keep the
  newer-by-timestamp state, and record in provenance that a conflicting observation was seen** —
  do not silently overwrite. This is the single most important scan-merge proto change to make.
- **C2 — no Run/timestamp provenance on `Port.State` or `Script`.** §7 (subtractable deletes)
  and the Latest-wins-*by observation timestamp* rule (§4/§9 order-independence) both need each
  observation to carry which Run produced it and when. Not present today.

### D. Current-state findings for the implementer (greenfield warnings)

- **`host/identical.go` never scores `Ports`.** It weights ExtraPorts, host `Status`, Trace,
  Hops, Users, Processes, addresses, hostnames — but not the open-port set. So the §3 scoped
  "match host → match each port → match each script" recursion is **entirely unimplemented**;
  there is no `comparePorts`, no `MergePort`. This is the reference work item (§ suggested-first-
  slice #2).
- **The credential slice is a *partial* reference — know what you're copying.** `credential/
  merge.go` (`MergeCore`) implements only **two of the six** §4 classes: Fill-only and
  First-wins. It has **no** Derived recompute (LoginsCount is a documented TODO), and — because
  credentials are not volatile-state observations — **no** Observation-append or
  Latest-wins-with-history. Ports need exactly those two missing classes (C1), which are the hard
  part. Copy `MergeCore`'s *shape* (per-field, returns `changed bool`, fill-only helper), not its
  coverage.
- **The §1 match→{new, merge-pairs} partition is already realized once — out of band.**
  `server/credential/credential.go` `Upsert` does not use `internal/db.FilterNew`; it hand-rolls
  `findIdentical` (keyed) → `MergeCore` + `Save` → else insert, exactly the partition §1/§10 ask
  for. So the pattern is proven; the remaining refactor is **generalizing it back into
  `internal/db.FilterNew`** (first-slice #1) so host/port ingest gets it too, instead of each
  domain re-implementing the loop.

### E. Consequence for sequencing

Port dedup is not a standalone "port merge" — per §3 it lives **inside host ingest**, scoped to
the matched host. So the honest order is: (1) `comparePorts` + `host.MergePort`; (2) fold both
into a `host.MergeHost` that walks Host→Ports→Scripts; (3) wire `MergeHost` into
`server/host` Create/Upsert replacing the match-then-drop `FilterNew`; (4) the §9 tests. The
`services` **display** slice (grouped list, real column weights, redesigned `info`) is
independent of all that and can land first without touching the ingest path.
