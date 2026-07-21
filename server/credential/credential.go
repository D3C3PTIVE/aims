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
	"context"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/d3c3ptive/aims/credential"
	credpb "github.com/d3c3ptive/aims/credential/pb"
	credentials "github.com/d3c3ptive/aims/credential/pb/rpc"
	"github.com/d3c3ptive/aims/host"
	hostpb "github.com/d3c3ptive/aims/host/pb"
	"github.com/d3c3ptive/aims/internal/db"
)

type server struct {
	db *gorm.DB
	*credentials.UnimplementedCredentialsServer
}

func New(db *gorm.DB) *server {
	return &server{db: db, UnimplementedCredentialsServer: &credentials.UnimplementedCredentialsServer{}}
}

// Read returns the first credential matching the request filter.
func (s *server) Read(ctx context.Context, req *credentials.ReadCredentialRequest) (*credentials.ReadCredentialResponse, error) {
	cred, err := req.GetCredential().ToORM(ctx)
	if err != nil {
		return nil, err
	}

	query := db.PreloadAll(s.db).Where(&cred)
	// Per-tool scoping: restrict to credentials contributed by a given tool via the
	// core_sources provenance join. Empty Source is a no-op (all credentials).
	query = db.ScopeBySource(query, "core_sources", "core_id", req.GetSource())
	// Server-side completion filter: when a prefix is set, push a prefix LIKE down to the DB so a
	// username Tab returns only the candidate credentials. Empty prefix is a no-op.
	query = scopeCredByPrefix(query, req.GetPrefix())
	// Host scoping: restrict to credentials gathered from a service running on the requested host.
	// Nil/unresolvable Host is a no-op (every host).
	query = scopeCredByHost(query, req.GetHost())

	// QueryToPBs runs the First and swallows gorm.ErrRecordNotFound as an empty result, so a
	// filtered Read matching no rows returns an empty list the caller's len==0 branch renders.
	// Any other error is a real DB failure, so it is wrapped to a coded gRPC status (R4).
	pbs, err := db.QueryToPBs[*credpb.CoreORM, credpb.Core](ctx, query, true)
	if err != nil {
		return nil, db.WrapDBError(err)
	}
	return &credentials.ReadCredentialResponse{Credentials: pbs}, nil
}

// List returns all credentials matching the request filter, with their sub-credentials preloaded.
func (s *server) List(ctx context.Context, req *credentials.ReadCredentialRequest) (*credentials.ReadCredentialResponse, error) {
	cred, err := req.GetCredential().ToORM(ctx)
	if err != nil {
		return nil, err
	}

	// The completion path (Creds.List) pushes the typed username down as a prefix filter; empty is
	// a no-op. Applied here as well as in Read so a List-backed completer gets the same pushdown.
	query := scopeCredByPrefix(db.PreloadAll(s.db).Where(&cred), req.GetPrefix())
	// Host scoping, as in Read: "credentials for this host", composing with the prefix filter.
	query = scopeCredByHost(query, req.GetHost())
	pbs, err := db.QueryToPBs[*credpb.CoreORM, credpb.Core](ctx, query, false)
	if err != nil {
		return nil, db.WrapDBError(err)
	}
	return &credentials.ReadCredentialResponse{Credentials: pbs}, nil
}

// scopeCredByPrefix restricts the query to credentials whose public username begins with prefix, OR
// whose id begins with it — the server-side completion filter behind HostFilters-style username
// completion (ReadCredentialRequest.Prefix). The id leg keeps the username-less credentials (which
// the completer renders by their id fallback) within the superset the client filter narrows, so the
// pushdown never drops a candidate carapace would show. Empty prefix is a no-op. The LIKE is
// left-anchored (prefix%) and its metacharacters are escaped (ESCAPE '\') so a typed '_'/'%' matches
// literally; the username leg is index-backed by publics.username's owner join.
func scopeCredByPrefix(query *gorm.DB, prefix string) *gorm.DB {
	if prefix == "" {
		return query
	}
	like := escapeLike(prefix) + "%"
	usernameIDs := query.Session(&gorm.Session{NewDB: true}).
		Table("publics").
		Select("publics.core_id").
		Where(`publics.username LIKE ? ESCAPE '\'`, like)
	return query.Where(`id IN (?) OR id LIKE ? ESCAPE '\'`, usernameIDs, like)
}

// scopeCredByHost restricts the query to credentials gathered from a service running on host h —
// the credential end of the host/subnet scoping axis (ReadCredentialRequest.Host), orthogonal to and
// composable with both Source and Prefix.
//
// It reuses credential.WhereLoggedInHost rather than db.ScopeByHost: a credential does not reach a
// host through a two-FK join table, but through its provenance (sources.service_id -> ports.host_id),
// which is exactly the path the Metasploit-style scope helpers in credential/core.go already model.
// That helper needs a resolved host id, so an id-less filter (address/hostname only) is resolved
// through host.IDsMatching first. A nil host, or one that denotes nothing, is a no-op.
func scopeCredByHost(query *gorm.DB, h *hostpb.Host) *gorm.DB {
	if h == nil {
		return query
	}
	if h.GetId() != "" {
		return query.Scopes(credential.WhereLoggedInHost((*host.Host)(h)))
	}

	// No id on the filter: resolve its address/hostname identity to the stored host ids, then scope
	// to the union of those hosts. WhereLoggedInHost takes one host, so the legwork is inlined here
	// rather than looping it (an address may legitimately resolve to more than one stored host).
	hostIDs := host.IDsMatching(query, h)
	if hostIDs == nil {
		return query
	}

	newDB := func() *gorm.DB { return query.Session(&gorm.Session{NewDB: true}) }
	services := newDB().
		Table("ports").
		Select("ports.service_id").
		Where("ports.service_id IS NOT NULL").
		Where("ports.host_id IN (?)", hostIDs)
	cores := newDB().
		Table("core_sources").
		Select("core_sources.core_id").
		Joins("JOIN sources ON sources.id = core_sources.source_id").
		Where("sources.service_id IN (?)", services)

	return query.Where("id IN (?)", cores)
}

// escapeLike neutralises the SQL LIKE wildcards in a user-typed prefix so it is matched literally
// under an `ESCAPE '\'` clause (backslash escaped first so it does not double-escape).
func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

// Create inserts credentials that are genuinely new, skipping any whose (public, private, realm)
// identity already exists. Unlike Upsert it never merges into an existing credential.
func (s *server) Create(ctx context.Context, req *credentials.CreateCredentialRequest) (*credentials.CreateCredentialResponse, error) {
	if len(req.GetCredentials()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "no credentials were provided")
	}

	// The whole batch runs in one transaction (P3): a Create that fails partway must not leave the
	// earlier credentials committed. New(tx) rebinds loadAll to the transaction.
	var created []*credpb.CoreORM
	err := s.db.Transaction(func(tx *gorm.DB) error {
		existing, err := New(tx).loadAll(ctx)
		if err != nil {
			return err
		}
		for _, c := range req.GetCredentials() {
			corm, err := c.ToORM(ctx)
			if err != nil {
				return err
			}
			if findIdentical(&corm, existing) != nil {
				continue
			}
			if err := tx.Create(&corm).Error; err != nil {
				return err
			}
			existing = append(existing, &corm)
			created = append(created, &corm)
		}
		return nil
	})
	if err != nil {
		return nil, db.WrapDBError(err)
	}

	pbs, err := db.ToPBs[*credpb.CoreORM, credpb.Core](ctx, created)
	if err != nil {
		return nil, db.WrapDBError(err)
	}
	return &credentials.CreateCredentialResponse{Credentials: pbs}, nil
}

// Upsert inserts or enriches credentials following the identity + merge model (CREDENTIALS.md
// §2–4): match on the value triple, merge by field-class when found, absorb a Public-only partial
// when a richer credential subsumes it, otherwise insert.
func (s *server) Upsert(ctx context.Context, req *credentials.UpsertCredentialRequest) (*credentials.UpsertCredentialResponse, error) {
	if len(req.GetCredentials()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "no credentials were provided")
	}

	// The whole batch runs in one transaction (P3): the read (loadAll), each merge/absorb/insert
	// write commit or roll back together, so a partial failure never leaves the batch half-applied.
	// New(tx) rebinds loadAll to the transaction. Closing the concurrent read-then-write race fully
	// still needs the DB unique constraint on the value triple (P3, blocked on schema/regen).
	var out []*credpb.CoreORM
	err := s.db.Transaction(func(tx *gorm.DB) error {
		existing, err := New(tx).loadAll(ctx)
		if err != nil {
			return err
		}
		for _, c := range req.GetCredentials() {
			corm, err := c.ToORM(ctx)
			if err != nil {
				return err
			}

			// 1. Same credential already present → merge by field-class.
			if match := findIdentical(&corm, existing); match != nil {
				if credential.MergeCore(match, &corm) {
					if err := tx.Session(&gorm.Session{FullSaveAssociations: true}).Save(match).Error; err != nil {
						return err
					}
				}
				out = append(out, match)
				continue
			}

			// 2. A richer credential subsumes an existing Public-only partial → absorb (drop the
			//    partial and its children) before inserting the fuller credential.
			if partial := findAbsorbable(&corm, existing); partial != nil {
				if err := tx.Select(clause.Associations).Delete(partial).Error; err != nil {
					return err
				}
				existing = removeCore(existing, partial)
			}

			// 3. New credential → insert.
			if err := tx.Create(&corm).Error; err != nil {
				return err
			}
			existing = append(existing, &corm)
			out = append(out, &corm)
		}
		return nil
	})
	if err != nil {
		return nil, db.WrapDBError(err)
	}

	pbs, err := db.ToPBs[*credpb.CoreORM, credpb.Core](ctx, out)
	if err != nil {
		return nil, db.WrapDBError(err)
	}
	return &credentials.UpsertCredentialResponse{Credentials: pbs}, nil
}

// Delete removes credentials (and their owned sub-credentials) by Id when provided, else by
// resolving the value identity against the database.
func (s *server) Delete(ctx context.Context, req *credentials.DeleteCredentialRequest) (*credentials.DeleteCredentialResponse, error) {
	existing, err := s.loadAll(ctx)
	if err != nil {
		return nil, db.WrapDBError(err)
	}

	var deleted []*credpb.CoreORM

	for _, c := range req.GetCredentials() {
		corm, err := c.ToORM(ctx)
		if err != nil {
			return nil, err
		}

		target := &corm
		if target.Id == "" {
			if match := findIdentical(target, existing); match != nil {
				target = match
			} else {
				continue
			}
		}

		if err := s.db.Select(clause.Associations).Delete(target).Error; err != nil {
			return nil, db.WrapDBError(err)
		}
		deleted = append(deleted, target)
	}

	pbs, err := db.ToPBs[*credpb.CoreORM, credpb.Core](ctx, deleted)
	if err != nil {
		return nil, db.WrapDBError(err)
	}
	return &credentials.DeleteCredentialResponse{Credentials: pbs}, nil
}

//
// [ Helpers ] ------------------------------------------------------------
//

// loadAll loads every credential with its sub-credentials preloaded, so identity matching and
// merging happen against complete objects.
func (s *server) loadAll(ctx context.Context) ([]*credpb.CoreORM, error) {
	var cores []*credpb.CoreORM
	err := db.PreloadAll(s.db).Find(&cores).Error
	return cores, err
}

func findIdentical(c *credpb.CoreORM, in []*credpb.CoreORM) *credpb.CoreORM {
	m, _ := db.FindMatch(in, func(e *credpb.CoreORM) bool { return credential.AreCredentialsIdentical(c, e) })
	return m
}

func findAbsorbable(full *credpb.CoreORM, in []*credpb.CoreORM) *credpb.CoreORM {
	m, _ := db.FindMatch(in, func(e *credpb.CoreORM) bool { return credential.AbsorbsPartial(full, e) })
	return m
}

func removeCore(in []*credpb.CoreORM, drop *credpb.CoreORM) []*credpb.CoreORM {
	out := in[:0]
	for _, e := range in {
		if e != drop {
			out = append(out, e)
		}
	}
	return out
}
