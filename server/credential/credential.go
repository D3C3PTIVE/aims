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
	"errors"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/d3c3ptive/aims/credential"
	credpb "github.com/d3c3ptive/aims/credential/pb"
	credentials "github.com/d3c3ptive/aims/credential/pb/rpc"
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

	creds := []*credpb.CoreORM{}
	query := db.PreloadAll(s.db).Where(&cred)
	// Per-tool scoping: restrict to credentials contributed by a given tool via the
	// core_sources provenance join. Empty Source is a no-op (all credentials).
	query = db.ScopeBySource(query, "core_sources", "core_id", req.GetSource())
	// An empty result set is not an error: a filtered Read matching no rows returns an empty
	// list, so the caller's len==0 branch fires rather than a bare gorm "record not found".
	if err = query.First(&creds).Error; err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	pbs, err := db.ToPBs[*credpb.CoreORM, credpb.Core](ctx, creds)
	if err != nil {
		return nil, err
	}
	return &credentials.ReadCredentialResponse{Credentials: pbs}, nil
}

// List returns all credentials matching the request filter, with their sub-credentials preloaded.
func (s *server) List(ctx context.Context, req *credentials.ReadCredentialRequest) (*credentials.ReadCredentialResponse, error) {
	cred, err := req.GetCredential().ToORM(ctx)
	if err != nil {
		return nil, err
	}

	creds := []*credpb.CoreORM{}
	if err = db.PreloadAll(s.db).Where(&cred).Find(&creds).Error; err != nil {
		return nil, err
	}

	pbs, err := db.ToPBs[*credpb.CoreORM, credpb.Core](ctx, creds)
	if err != nil {
		return nil, err
	}
	return &credentials.ReadCredentialResponse{Credentials: pbs}, nil
}

// Create inserts credentials that are genuinely new, skipping any whose (public, private, realm)
// identity already exists. Unlike Upsert it never merges into an existing credential.
func (s *server) Create(ctx context.Context, req *credentials.CreateCredentialRequest) (*credentials.CreateCredentialResponse, error) {
	existing, err := s.loadAll(ctx)
	if err != nil {
		return nil, err
	}

	var created []*credpb.CoreORM

	for _, c := range req.GetCredentials() {
		corm, err := c.ToORM(ctx)
		if err != nil {
			return nil, err
		}
		if findIdentical(&corm, existing) != nil {
			continue
		}
		if err := s.db.Create(&corm).Error; err != nil {
			return nil, err
		}
		existing = append(existing, &corm)
		created = append(created, &corm)
	}

	pbs, err := db.ToPBs[*credpb.CoreORM, credpb.Core](ctx, created)
	if err != nil {
		return nil, err
	}
	return &credentials.CreateCredentialResponse{Credentials: pbs}, nil
}

// Upsert inserts or enriches credentials following the identity + merge model (CREDENTIALS.md
// §2–4): match on the value triple, merge by field-class when found, absorb a Public-only partial
// when a richer credential subsumes it, otherwise insert.
func (s *server) Upsert(ctx context.Context, req *credentials.UpsertCredentialRequest) (*credentials.UpsertCredentialResponse, error) {
	existing, err := s.loadAll(ctx)
	if err != nil {
		return nil, err
	}

	var out []*credpb.CoreORM

	for _, c := range req.GetCredentials() {
		corm, err := c.ToORM(ctx)
		if err != nil {
			return nil, err
		}

		// 1. Same credential already present → merge by field-class.
		if match := findIdentical(&corm, existing); match != nil {
			if credential.MergeCore(match, &corm) {
				if err := s.db.Session(&gorm.Session{FullSaveAssociations: true}).Save(match).Error; err != nil {
					return nil, err
				}
			}
			out = append(out, match)
			continue
		}

		// 2. A richer credential subsumes an existing Public-only partial → absorb (drop the
		//    partial and its children) before inserting the fuller credential.
		if partial := findAbsorbable(&corm, existing); partial != nil {
			if err := s.db.Select(clause.Associations).Delete(partial).Error; err != nil {
				return nil, err
			}
			existing = removeCore(existing, partial)
		}

		// 3. New credential → insert.
		if err := s.db.Create(&corm).Error; err != nil {
			return nil, err
		}
		existing = append(existing, &corm)
		out = append(out, &corm)
	}

	pbs, err := db.ToPBs[*credpb.CoreORM, credpb.Core](ctx, out)
	if err != nil {
		return nil, err
	}
	return &credentials.UpsertCredentialResponse{Credentials: pbs}, nil
}

// Delete removes credentials (and their owned sub-credentials) by Id when provided, else by
// resolving the value identity against the database.
func (s *server) Delete(ctx context.Context, req *credentials.DeleteCredentialRequest) (*credentials.DeleteCredentialResponse, error) {
	existing, err := s.loadAll(ctx)
	if err != nil {
		return nil, err
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
			return nil, err
		}
		deleted = append(deleted, target)
	}

	pbs, err := db.ToPBs[*credpb.CoreORM, credpb.Core](ctx, deleted)
	if err != nil {
		return nil, err
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
