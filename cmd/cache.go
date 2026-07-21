package cmd

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
	"strconv"
	"time"

	"github.com/carapace-sh/carapace"
	"github.com/carapace-sh/carapace/pkg/cache/key"

	"github.com/d3c3ptive/aims/client"
)

// CompletionCacheTTL bounds how long a live-DB completion result is reused from
// carapace's on-disk cache before the teamclient is queried again. Deliberately
// short: it collapses the per-keystroke query storm of exec-once CLI mode — where
// every Tab reconnects and re-fetches (and re-formats) the whole object set with
// no server-side prefix match or cap (see cmd/aims/BENCH_COMPLETIONS.md) — into
// roughly one query per typing burst, while keeping candidates fresh. The cached
// snapshot is client-side, so a change made by another operator, or by a
// server-side scan, is invisible until the TTL lapses (or until a local mutation
// bumps the epoch — see InvalidateCompletionCache).
const CompletionCacheTTL = 10 * time.Second

// CacheCompletion wraps a live-DB completion action with carapace's on-disk cache.
// carapace still filters the cached full candidate set against what the user typed,
// so caching the whole set (which these completions already fetch) is correct: fetch
// once, filter many. The cache is namespaced by three keys:
//   - scope — the teamserver identity, so a multiplayer client never serves one
//     server's objects when completing against another (see Client.CompletionScope);
//   - name  — so distinct completions don't collide, since they share this wrapper's
//     call site (carapace derives the cache directory from the call site);
//   - epoch — the local mutation sentinel, so an add/import invalidates the cache
//     immediately rather than after the TTL (see completionEpochKey).
//
// Only callback actions are cached; a failed connection returns an ActionMessage and
// is not cached.
func CacheCompletion(con *client.Client, name string, action carapace.Action) carapace.Action {
	scope := key.Key(func() (string, error) { return con.CompletionScope(), nil })
	return action.Cache(CompletionCacheTTL, scope, key.String(name), completionEpochKey())
}

// CacheCompletionByPrefix is CacheCompletion for prefix-filtered completions: the word being
// completed is folded into the cache key so each distinct prefix is its own entry. This is what
// makes a server-side prefix filter safe to cache — unlike the whole-set completions (one cached
// snapshot carapace filters locally for every prefix), a prefix-scoped read returns only that
// prefix's candidates, so reusing it under a different prefix would drop valid matches. Keying by
// prefix keeps the read-once-filter-many win per prefix while a longer prefix re-queries (a small
// result each time) instead of transferring the whole table on the first keystroke.
func CacheCompletionByPrefix(con *client.Client, name, prefix string, action carapace.Action) carapace.Action {
	scope := key.Key(func() (string, error) { return con.CompletionScope(), nil })
	return action.Cache(CompletionCacheTTL, scope, key.String(name), key.String("prefix\x00"+prefix), completionEpochKey())
}

// completionEpochPath is the location of the completion "epoch" sentinel — a tiny
// file under the user cache dir whose content is bumped on every local DB mutation.
// It honours XDG_CACHE_HOME (via os.UserCacheDir), so it sits alongside carapace's
// own cache and is trivially isolated in tests.
func completionEpochPath() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "aims", "completion.epoch"), nil
}

// completionEpochKey returns a carapace cache key derived from the epoch sentinel's
// content. Including it in every completion's cache key means a single bump (by
// InvalidateCompletionCache) invalidates all cached completions at once, so results
// of a local `add`/`import` show up on the very next Tab instead of waiting out
// CompletionCacheTTL. The sentinel is created on first use; if it cannot be
// created/read the key errors, which makes carapace bypass the cache entirely
// (always fresh) — a safe failure mode. FileChecksum (content hash) is used rather
// than FileStats so a bump is detected regardless of filesystem mod-time resolution.
func completionEpochKey() key.Key {
	return func() (string, error) {
		path, err := completionEpochPath()
		if err != nil {
			return "", err
		}
		if _, statErr := os.Stat(path); os.IsNotExist(statErr) {
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				return "", err
			}
			if err := os.WriteFile(path, []byte("0"), 0o600); err != nil {
				return "", err
			}
		}
		return key.FileChecksum(path)()
	}
}

// InvalidateCompletionCache bumps the completion epoch so every on-disk completion
// cache (see CacheCompletion) is treated as stale on the next Tab. Call it after a
// command successfully mutates the database (add / import / any Create/Upsert) so
// completions reflect the change immediately instead of after CompletionCacheTTL.
// Best-effort: an error only means completions stay cached until the TTL lapses.
func InvalidateCompletionCache() error {
	path, err := completionEpochPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	// A fresh nonce guarantees the FileChecksum key changes on every call.
	nonce := strconv.FormatInt(time.Now().UnixNano(), 10)
	return os.WriteFile(path, []byte(nonce), 0o600)
}
