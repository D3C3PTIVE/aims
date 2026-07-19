# AIMS — Credential Slice (Phase 2 guinea pig)

> Design doc for the first *complete* object vertical slice. Companion to
> [`ROADMAP.md`](./ROADMAP.md) (Phase 2/3) and [`DISPLAY.md`](./DISPLAY.md) (engine).
> Written 2026-07-19.
>
> **Thesis:** don't code CRUD for 7 objects mechanically. Nail **one** object's full
> function set — identity, merge policy, display, CLI — and extract the reusable *merge
> engine* + display contract from it. Credentials are the guinea pig because their
> identity model is explicit (Metasploit heritage) and their sparse→enriched lifecycle
> (*username only → +password → +where-it-works*) is exactly the hard case.

---

## 1. The model (what we're deduping)

A `credential.Core` is a **combination** of up to three identity-bearing parts plus provenance:

```
Core ─┬─ Public   (Type, Username | Data[key/cert], Claims)      ← the "who"   (optional)
      ├─ Private  (Type, Data[secret/hash], JTRFormat)           ← the "secret"(optional)
      ├─ Realm    (Key, Value)                                   ← the "where" (optional)
      ├─ Origin   (Type, SessionId, Filename, Cracker, Service)  ← provenance  (REQUIRED)
      └─ LoginsCount (derived)

Login  (separate table, references Core) ─ (Core, Service, HostId) + Status, AccessLevel, LastAttemptedAt
```

Rules from the proto: a Core **must** have an Origin, and **at least one** of Public / Private /
Realm. `Public`/`Private`/`Realm`/`Origin`/`Login` are each their own ORM table; a Core points
at the sub-rows. `Logins` point *at* a Core (not embedded); `LoginsCount` is a denormalized counter.

This structure is the whole reason credentials are the right first object: **the four merge
classes fall out naturally because the sub-entities already are the classes.**

---

## 2. Identity model — the key that degrades gracefully

The core problem the user named: *"how to avoid duplication even with very few info?"* The answer
is **value-identity per sub-entity, shared across Cores, with the Core keyed on the triple.**

### 2.1 Per-sub-entity value identity (dedup these independently, then reuse the row)

| Sub-entity | Identity key (value-based, pre-ID) | Notes |
|---|---|---|
| **Public** | `(Type, Username)` — or `(Type, fingerprint(Data))` for `PublicKey`/`Certificate` | one "admin" row, reused everywhere |
| **Private** | `(Type, Data)` — `Data` is the secret/hash itself; fingerprint for `Key` | one "hunter2" row, reused everywhere |
| **Realm** | `(Key, Value)` | one "CORP.LOCAL" row |

Enumerating 50 bare usernames creates 50 Public-only Cores; when `admin` later gets a password,
we make a **new Core** and **absorb** the bare `admin` partial (§2.3), so the username never
duplicates. Re-importing the same set matches each by identity and enriches in place.

> **Schema reality (model gap #5).** In the *current generated schema* `Public`/`Private`/
> `Realm`/`Origin` are **owned one-to-one children of Core** (each has a `CoreId` back-reference),
> not shared reference tables as in Metasploit. So identical values are *duplicated across rows*
> rather than a single shared row reused by many Cores. Dedup **behaviour** is preserved (Core-level
> value-triple + absorption), but the storage isn't normalized. Normalizing Public/Private/Realm
> into shared `belongs_to` tables is a `.proto`/gorm change — flagged, not done in this slice.

### 2.2 Core identity = the triple

```
CoreIdentity = ( publicIdent?, privateIdent?, realmIdent? )   // any component may be null
```

Two Cores are the **same** iff:
1. they share ≥1 present identity component, **and**
2. every component present in *both* is equal, **and**
3. no present component *conflicts* (differing non-null public/private/realm ⇒ different Core).

This is the graceful-degradation rule: **match on what's known, never require what's unknown.**
`admin/‹no-priv›` and `admin/hunter2` share the Public but differ in Private → by strict reading
they're two Cores that share one Public. That's correct Metasploit semantics, and it's also what
you *want*: "we knew the user before we had the password" is itself information.

### 2.3 Partial absorption (the one real judgment call)

A **Public-only Core** (no Private, no Realm) is a *partial observation* — "this username exists."
When a richer Core with the same Public gains a Private, do we keep the partial or fold it in?

- **Keep** → the username list survives as first-class rows (good for "who exists" queries), but
  the table grows noisy: `admin` appears once bare and once with a password.
- **Absorb** → the partial is collapsed into the first richer Core that subsumes its Public,
  *unless* the partial carries its own Logins or a distinct Origin worth preserving.

**Recommendation: absorb, conservatively.** Collapse a Public-only Core into a richer sibling
when (a) same Public, (b) the partial has zero Logins, and (c) its Origin is not a distinct
manual/import event you'd lose. Otherwise keep and mark `superseded`. This keeps the list clean
while never silently dropping provenance. *(This is decision #1 to confirm — see §7.)*

---

## 3. Merge policy — the four field classes

Every field is one of: **Identity** (set once; differing ⇒ different object) · **Fill-only**
(write if empty, never clobber known with empty) · **Append** (accumulate, never overwrite) ·
**Latest-wins** (newest observation replaces). This table *is* the per-object custom logic; the
generic engine just applies it.

### Public
| Field | Class | Rationale |
|---|---|---|
| `Type`, `Username`, `Data`(key) | **Identity** | defines the Public |
| `Claims` (JWT) | **Fill-only** | a later parse may add claims; don't wipe |
| `CreatedAt` | first-wins | discovery time |
| `UpdatedAt` | latest-wins | |

### Private
| Field | Class | Rationale |
|---|---|---|
| `Type`, `Data` | **Identity** | the secret/hash |
| `JTRFormat` | **Fill-only** | a cracker may identify the format later; fill if blank |
| timestamps | first / latest | |

### Realm
| Field | Class |
|---|---|
| `Key`, `Value` | **Identity** |

### Origin (currently 1 per Core — see model gap §7)
| Field | Class | Rationale |
|---|---|---|
| `Type`, `SessionId`, `Filename`, `Cracker`, `Service` | **first-wins** | preserve the *discovery* origin; don't overwrite "cracked by john" with a later "seen on service" |

### Core
| Field | Class | Rationale |
|---|---|---|
| `Public`/`Private`/`Realm` refs | **Identity** | the triple |
| `Origin` | first-wins (append once model allows) | provenance |
| `LoginsCount` | **derived** | recompute from Logins, never trust the wire value |
| timestamps | first / latest | |

### Login (append relative to Core; identity = `(Core, Service, HostId)`)
| Field | Class | Rationale |
|---|---|---|
| `(Core, Service, HostId)` | **Identity** | one Login row per cred×service×host |
| `Status` | **Latest-wins** | `Untried → DeniedAccess → Successful` transitions overwrite |
| `LastAttemptedAt` | **Latest-wins** | |
| `AccessLevel` | Fill-only / latest | keep highest known if newer is blank |

Re-testing a credential updates the existing Login's status+timestamp; it never inserts a duplicate.

---

## 4. Upsert algorithm

```
Upsert(core):
  1. Resolve/insert each sub-entity by VALUE identity (§2.1):
       pub  := findOrCreate(Public,  publicIdent)      // reuse shared row
       priv := findOrCreate(Private, privateIdent)     // fill-only merge on hit
       realm:= findOrCreate(Realm,   realmIdent)
  2. Find existing Core by the triple (pub.id, priv.id, realm.id) per §2.2.
  3. If none:
       - if Private/Realm present and a Public-only partial exists for this Public → absorb (§2.3)
       - else INSERT new Core (first-wins Origin).
     If one exists:
       - MERGE by field class (§3): fill-only sub-fields, first-wins Origin, ignore wire LoginsCount.
  4. Recompute LoginsCount from the Logins table.
  5. Return the resolved Core (with a `created|merged|absorbed` outcome for the CLI to report).
```

**Contrast with the existing host dedup.** `host.AreHostsIdentical` is a *fuzzy weighted score*
(`score >= 10`) because hosts have no stable natural key. Credentials **do** have a natural key
(the triple), so we use *deterministic identity*, not scoring — cheaper and exact. The reusable
engine should support **both** strategies: `Identity(obj) → key` for keyed objects, falling back
to `Score(a,b) → bool` (the existing `FilterNew`/`AreXIdentical` path) for keyless ones.

---

## 5. Derived insights (the "unsuspected combinations" from Phase 2)

Fields that don't exist on the object but emerge from the *set*, and are worth surfacing:

- **Reuse / spray value** — a `Private` shared across N Publics or Realms ⇒ *"password reused ×N"*.
  The single highest-signal derived field for a pentester.
- **Replayable** — `PrivateType ∈ {ReplayableHash, NTLMHash, PostgresMD5}` ⇒ pass-the-hash capable;
  flag prominently even without a cracked plaintext.
- **Validation** — from Logins: ever `Successful`? where? highest `AccessLevel`? ⇒ *"✓ admin on dc01"*.
- **Crackability** — hash with a known `JTRFormat` but no linked plaintext ⇒ *"crackable, not cracked"*.
- **Lineage** — `Origin.Type == CrackedPassword` links a plaintext back to the hash it came from.

These become the `Valid`, `Type`, and `Insights` columns/sections below.

---

## 6. CLI appearance proposals

Command surface: `credentials list` (table) · `credentials info <id>` (single-entity detail;
alias `show`) · `add` · `rm` · `import` · `export`. Secrets are **masked by default**, revealed
in `info` and with a global `--reveal/-r` flag.

### 6.1 List table

Weighted columns (engine drops high-weight ones on narrow terminals). Masking: passwords →
`first·····len`, hashes → `head…:head…`, keys → `SSH-FP`.

**Weight 1 (≤80 cols) — the irreducible view:**

```
 ID        Public         Private                     Realm         Valid   Logins
 ========  =============  ==========================  ============  ======  ======
 a1f3c2d9  admin          h·····7  (password)         CORP.LOCAL    ✓ 2     3
 7b2e9f04  svc_backup     aad3b4…:8846f7…  (ntlm)      CORP.LOCAL    ✓ 1     1
 c9d81a55  j.doe          —  (username only)           CORP.LOCAL    ?       0
 e4a70b12  root           SHA256:nTh…q4  (ssh-key)     —             ✓ 1     1
 2f6c33ab  postgres       md5f3a…9c  (postgres-md5)    —             ✗       4
```

**Weight 2–3 (≥160 cols) — add context:**

```
 ID        Public       Private                    Realm        Type          Valid  Access  Origin           Logins  Updated
 ========  ===========  =========================  ===========  ============  =====  ======  ===============  ======  ==========
 a1f3c2d9  admin        h·····7                    CORP.LOCAL   password      ✓ 2    admin   cracked (john)   3       07-14 09:10
 7b2e9f04  svc_backup   aad3b4…:8846f7…            CORP.LOCAL   ntlm ⚡       ✓ 1    user    service smb/445  1       07-13 22:03
 c9d81a55  j.doe        —                          CORP.LOCAL   username      ?      —       import (ldap)    0       07-12 10:01
 e4a70b12  root         SHA256:nTh…q4              —            ssh-key       ✓ 1    root    loot /home       1       07-13 15:20
 2f6c33ab  postgres     md5f3a…9c ⚡                —            postgres-md5  ✗      —       service pg/5432  4       07-14 08:55
```

- `⚡` marks **replayable** secrets (pass-the-hash capable).
- `Valid`: `✓ N` = successful on N hosts · `✗` = tried, all denied · `?` = untried.
- ID colored green when validated, dim when untried (reuse host's up-state coloring convention).

### 6.2 `info <id>` — single-entity detail (rich)

Grouped by weight (blank line between groups, per the `Details` engine). Secrets revealed here.
The **Logins** block is a nested table; **Insights** is the derived-fields payoff.

```
 admin @ CORP.LOCAL                                         ✓ validated · admin
 ─────────────────────────────────────────────────────────────────────────────

  Identity
        Public : admin                          (username)
       Private : hunter2                         (password)
         Realm : CORP.LOCAL                       (Active Directory domain)

  Provenance
        Origin : cracked                          (john  ·  from hash 7b2e9f04)
    Discovered : 2026-07-12 14:22
       Session : msf-session-4

  Logins  (3)
        STATUS     HOST             SERVICE      ACCESS   LAST ATTEMPT
        ✓ success  dc01  10.0.0.5   smb/445      admin    2026-07-14 09:10
        ✓ success  web01 10.0.0.9   ssh/22       user     2026-07-13 18:44
        ✗ denied   fs01  10.0.0.7   smb/445      —        2026-07-13 18:40

  Insights
     ⚠  password reused by 2 other credentials  (svc_web, j.smith)
     ↳  cracked from NTLM hash 7b2e9f04  (svc_backup)
     ✓  grants admin on 1 host, user on 1
```

### 6.3 `info <id>` — compact alternative (one screen, no nested table)

For when you want density / piping. Logins collapse to a summary line.

```
 a1f3c2d9  admin : hunter2  @ CORP.LOCAL
 ─────────────────────────────────────────────────────────────
   type      password              origin    cracked (john ← 7b2e9f04)
   valid     ✓ admin@dc01, user@web01, ✗ fs01
   reuse     ⚠ 2 other creds share this password
```

*(§6.2 vs §6.3 is decision #2 — which becomes the default `info` layout; the other can hide
behind `--compact`/`--wide`.)*

---

## 7. Open decisions to confirm before coding

1. **Partial absorption default** (§2.3) — absorb Public-only Cores into richer siblings
   (recommended), or always keep them as distinct rows?
2. **Default `info` layout** (§6.2 rich vs §6.3 compact).
3. **Model gap — `Origin` is singular on `Core`** (`Origin Origin = 10`). To truly *accumulate*
   provenance (same cred found via import *and* via a service) we'd want `repeated Origin` or a
   join table — a `.proto` change + `make gen`. Ship first-wins-Origin now, flag the enhancement?
4. **Secret masking default** — mask in `list`, reveal in `info` (recommended); or mask everywhere
   until `--reveal`?

## 8. What to build (the slice)

1. `credential/identity.go` — `CoreIdentity`, per-sub-entity value-identity, the triple matcher.
2. `internal/db` — extend the dedup engine to support **keyed identity** (`Identity(obj)→key`)
   alongside the existing **scored** path (`FilterNew`/`AreXIdentical`).
3. `credential/merge.go` — the four-class field-merge applied via a declared policy per sub-entity.
4. `server/credential/credential.go` — real `Create`/`Upsert`/`Delete` using §4.
5. `credential/core.go` — `DisplayFields` / `DisplayHeaders` / `DisplayDetails` / `Completions`
   (currently absent), plus the derived-insight generators (§5).
6. `cmd/credentials/credentials.go` — wire `list` → Table, `info` → Details, `add`/`rm`, and
   hook `cmd/export` `import` (nmap/msf/CSV creds → `Upsert`).
7. **Tests** — round-trip `ToORM`/`ToPB`; **double-import** (import same creds twice ⇒ enrich,
   not duplicate); partial-then-full (username, then username+password ⇒ correct absorb/keep);
   reuse-detection insight.

The reusable extractions for the *next* object (Services): the keyed+scored dedup engine (#2) and
the four-class merge engine (#3). Services then only declare their identity key and field classes.

---

## 9. Status (implemented 2026-07-19)

Vertical slice built and green (`GOWORK=off go build ./...` on the core; 11 unit tests pass):

- `credential/identity.go` — value-identity per sub-entity, the `CoreIdentity` triple,
  `AreCredentialsIdentical`, `AbsorbsPartial`.
- `credential/merge.go` — `MergeCore` (fill-only enrichment, first-wins Origin).
- `credential/display.go` — `DisplayFields`/`DisplayHeaders`/`DisplayDetails`/`Completions`,
  secret masking (`Reveal` toggle), and `Insights` (reuse / replayable / lineage / validation).
- `server/credential/credential.go` — real `Create` / `Upsert` (identity match → merge → absorb →
  insert) / `Delete` (by Id or resolved identity), with association preloads.
- `cmd/credentials/credentials.go` — `list` (table), `info`/`show` (detail + insights),
  `add` (build-from-flags → Upsert), `rm` (resolve-by-ID → Delete), `import` (JSON → Upsert),
  `--reveal`.
- `credential/{identity,merge}_test.go` — double-import idempotence, partial-vs-full,
  conflicting-secret, case-insensitive username, absorption preconditions, fill-only, first-wins.
- `testdata/credentials.json` — a 12-credential CORP.LOCAL mock set, importable via
  `credentials import testdata/credentials.json` (verified against the real import parser).

**Deferred (need a DB test harness or a `.proto` change):** DB-level double-import test (no
sqlite `gorm.Open` harness in-tree yet); the per-login sub-table in `info` and the list `Valid`
column (need the Core↔Login relation untangled — a Logins-service task); `repeated Origin`
(gap #3) and shared sub-entity tables (gap #5).

### Decisions locked
1 absorb partials · 2 rich `info` default · 3 ship first-wins Origin (flag `repeated Origin`) ·
4 mask in list / reveal in `info`.
