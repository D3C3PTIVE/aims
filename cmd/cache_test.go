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
	"testing"

	"github.com/carapace-sh/carapace"

	"github.com/d3c3ptive/aims/client"
)

// TestCacheCompletionSkipsCallbackOnHit proves the on-disk completion cache
// actually short-circuits the live-DB query: within CompletionCacheTTL, a second
// invocation of the same wrapped completion returns the cached candidates without
// re-running the (expensive: connect + whole-DB Read + format) callback. That skip
// is the entire point of wrapping the per-keystroke completions — see the
// whole-DB-fetch cost measured in cmd/aims/BENCH_COMPLETIONS.md. The uncached
// control shows the callback would otherwise run on every invocation.
func TestCacheCompletionSkipsCallbackOnHit(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir()) // isolate carapace's on-disk cache

	con := &client.Client{} // nil Teamclient -> CompletionScope() == "local"
	ctx := carapace.Context{}

	// Control: a bare callback runs every time it is invoked.
	var uncached int
	bare := carapace.ActionCallback(func(carapace.Context) carapace.Action {
		uncached++
		return carapace.ActionValues("alpha", "beta")
	})
	bare.Invoke(ctx)
	bare.Invoke(ctx)
	if uncached != 2 {
		t.Fatalf("control: expected uncached callback to run twice, ran %d", uncached)
	}

	// Cached: the second invocation is served from disk, callback not re-run.
	var cached int
	action := CacheCompletion(con, "test:hit", carapace.ActionCallback(
		func(carapace.Context) carapace.Action {
			cached++
			return carapace.ActionValues("alpha", "beta")
		}))
	action.Invoke(ctx) // miss: runs callback, writes cache
	action.Invoke(ctx) // hit: served from disk, callback NOT run
	if cached != 1 {
		t.Fatalf("expected cached callback to run once (second invoke a cache hit), ran %d", cached)
	}
}

// TestCacheCompletionScopesByName proves distinct completions sharing the
// CacheCompletion call site do not collide: different names key to different
// cache files, so each still runs its own callback once.
func TestCacheCompletionScopesByName(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())

	con := &client.Client{}
	ctx := carapace.Context{}

	var a, b int
	actionA := CacheCompletion(con, "test:a", carapace.ActionCallback(func(carapace.Context) carapace.Action {
		a++
		return carapace.ActionValues("a")
	}))
	actionB := CacheCompletion(con, "test:b", carapace.ActionCallback(func(carapace.Context) carapace.Action {
		b++
		return carapace.ActionValues("b")
	}))

	actionA.Invoke(ctx)
	actionB.Invoke(ctx)
	if a != 1 || b != 1 {
		t.Fatalf("expected each distinct completion to run once, got a=%d b=%d", a, b)
	}
}
