package credentials

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
	"fmt"
	"strings"

	"github.com/carapace-sh/carapace"
	"github.com/carapace-sh/carapace/pkg/style"
	"github.com/spf13/cobra"

	"github.com/d3c3ptive/aims/client"
	aims "github.com/d3c3ptive/aims/cmd"
	"github.com/d3c3ptive/aims/cmd/display"
	"github.com/d3c3ptive/aims/cmd/export"
	cred "github.com/d3c3ptive/aims/credential"
	credential "github.com/d3c3ptive/aims/credential/pb"
	"github.com/d3c3ptive/aims/credential/pb/rpc"
)

// Commands returns a command tree to manage and display credentials.
func Commands(con *client.Client) *cobra.Command {
	credentialsCmd := &cobra.Command{
		Use:     "credentials",
		Short:   "Manage database credentials",
		GroupID: "database",
	}

	// --reveal shows secrets in clear text across the subtree (masked by default).
	credentialsCmd.PersistentFlags().BoolP("reveal", "r", false, "Show credential secrets in clear text")

	credentialsCmd.AddCommand(listCommand(con))
	credentialsCmd.AddCommand(infoCommand(con))
	credentialsCmd.AddCommand(addCommand(con))
	credentialsCmd.AddCommand(rmCommand(con))
	credentialsCmd.AddCommand(export.ImportCommand(credentialsCmd, con, importCredentials(con)))

	return credentialsCmd
}

// importCredentials unmarshals a JSON file of credential.Core objects and upserts them, so
// re-importing the same file enriches rather than duplicates (the merge engine, from the CLI).
func importCredentials(con *client.Client) func(cmd *cobra.Command, arg string, data []byte) error {
	return func(cmd *cobra.Command, arg string, data []byte) error {
		creds, err := export.ImportJSON[*credential.Core](data, arg)
		if err != nil {
			return fmt.Errorf("JSON: %s", err)
		}
		if len(creds) == 0 {
			return nil
		}

		res, err := con.Creds.Upsert(cmd.Context(), &rpc.UpsertCredentialRequest{Credentials: creds})
		if err = aims.CheckError(err); err != nil {
			return err
		}

		fmt.Printf("Imported %d credential(s) from %s.\n", len(res.GetCredentials()), arg)
		return nil
	}
}

// listCommand renders all credentials as a responsive table.
func listCommand(con *client.Client) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "Display credentials (with filters or styles)",
		RunE: func(command *cobra.Command, args []string) error {
			applyReveal(command)

			creds, err := readAll(con, command)
			if err != nil {
				return err
			}
			if len(creds) == 0 {
				fmt.Println("No credentials in database.")
				return nil
			}

			table := display.Table(creds, cred.DisplayFields, cred.DisplayHeaders()...)
			fmt.Println(table.Render())

			return nil
		},
	}
}

// infoCommand shows the full detail view of one or more credentials, with derived insights.
func infoCommand(con *client.Client) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "info",
		Aliases: []string{"show"},
		Short:   "Show one or more credentials in detail",
		RunE: func(command *cobra.Command, args []string) error {
			// The info view always reveals secrets: it is the focused loot view for one credential.
			cred.Reveal = true

			all, err := readAll(con, command)
			if err != nil {
				return err
			}

			matched := all
			if len(args) > 0 {
				matched = filterByIDPrefix(all, args)
			}
			if len(matched) == 0 {
				return errors.New("no matching credential")
			}

			for _, c := range matched {
				fmt.Println(cred.Detail(c, all).Render(0))
				fmt.Println()
			}

			return nil
		},
	}

	carapace.Gen(cmd).PositionalAnyCompletion(CompleteByID(con))

	return cmd
}

// addCommand builds a credential from flags and upserts it — the CLI entry point that exercises
// the identity/merge engine (add a username, then add it again with a password → absorption).
func addCommand(con *client.Client) *cobra.Command {
	var (
		username string
		password string
		hash     string
		hashType string
		realmVal string
		realmKey string
	)

	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add (or enrich) a credential in the database",
		RunE: func(command *cobra.Command, args []string) error {
			core := &credential.Core{Origin: &credential.Origin{Type: credential.OriginType_Manual}}

			if username != "" {
				core.Public = &credential.Public{Type: credential.PublicType_Username, Username: username}
			}
			switch {
			case password != "":
				core.Private = &credential.Private{Type: credential.PrivateType_Password, Data: password}
			case hash != "":
				pt, err := parseHashType(hashType)
				if err != nil {
					return err
				}
				core.Private = &credential.Private{Type: pt, Data: hash}
			}
			if realmVal != "" || realmKey != "" {
				core.Realm = &credential.Realm{Key: realmKey, Value: realmVal}
			}

			if core.Public == nil && core.Private == nil && core.Realm == nil {
				return errors.New("a credential needs at least one of --username, --password/--hash, or --realm")
			}

			res, err := con.Creds.Upsert(command.Context(), &rpc.UpsertCredentialRequest{
				Credentials: []*credential.Core{core},
			})
			if err = aims.CheckError(err); err != nil {
				return err
			}

			cred.Reveal = true
			for _, c := range res.GetCredentials() {
				fmt.Println(display.Details(c, cred.DisplayFields, cred.DisplayDetails()...))
			}

			return nil
		},
	}

	flags := cmd.Flags()
	flags.StringVarP(&username, "username", "u", "", "Public username")
	flags.StringVarP(&password, "password", "p", "", "Private password (clear text)")
	flags.StringVar(&hash, "hash", "", "Private password hash")
	flags.StringVar(&hashType, "hash-type", "replayable", "Hash type: ntlm|replayable|nonreplayable|postgres")
	flags.StringVar(&realmVal, "realm", "", "Realm value (e.g. domain name)")
	flags.StringVar(&realmKey, "realm-key", "", "Realm key (e.g. \"Active Directory domain\")")

	carapace.Gen(cmd).FlagCompletion(carapace.ActionMap{
		"hash-type": completeHashType(),
		"username":  CompleteByUsername(con),
	})

	return cmd
}

// rmCommand deletes one or more credentials resolved by ID prefix.
func rmCommand(con *client.Client) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rm",
		Short: "Remove one or more credentials from the database",
		RunE: func(command *cobra.Command, args []string) error {
			if len(args) == 0 {
				return errors.New("provide one or more credential ID prefixes to remove")
			}

			all, err := readAll(con, command)
			if err != nil {
				return err
			}

			matched := filterByIDPrefix(all, args)
			if len(matched) == 0 {
				return errors.New("no matching credential")
			}

			res, err := con.Creds.Delete(command.Context(), &rpc.DeleteCredentialRequest{
				Credentials: matched,
			})
			if err = aims.CheckError(err); err != nil {
				return err
			}

			fmt.Printf("Removed %d credential(s).\n", len(res.GetCredentials()))
			return nil
		},
	}

	carapace.Gen(cmd).PositionalAnyCompletion(CompleteByID(con))

	return cmd
}

//
// [ Helpers ] ------------------------------------------------------------
//

// readAll fetches every credential from the server.
func readAll(con *client.Client, command *cobra.Command) ([]*credential.Core, error) {
	res, err := con.Creds.List(command.Context(), &rpc.ReadCredentialRequest{
		Credential: &credential.Core{},
	})
	if err = aims.CheckError(err); err != nil {
		return nil, err
	}
	return res.GetCredentials(), nil
}

// filterByIDPrefix returns credentials whose (short) ID starts with any of the given prefixes.
func filterByIDPrefix(all []*credential.Core, prefixes []string) (matched []*credential.Core) {
	for _, c := range all {
		for _, p := range prefixes {
			if strings.HasPrefix(c.Id, p) {
				matched = append(matched, c)
				break
			}
		}
	}
	return matched
}

// applyReveal flips the display package into clear-text mode when --reveal is set.
func applyReveal(command *cobra.Command) {
	if r, err := command.Flags().GetBool("reveal"); err == nil && r {
		cred.Reveal = true
	}
}

//
// [ Completions ] --------------------------------------------------------
//

// completeCredentials is the shared engine for credential completions: it live-queries the
// database, picks `candidate` as the value to insert (falling back to `fallback` when the
// candidate column is empty for a row), and turns the remaining columns into the aligned
// description. `split` explodes a list-valued candidate column into several candidates.
func completeCredentials(con *client.Client, candidate, fallback, tag, split string) carapace.Action {
	return aims.CacheCompletion(con, "credentials:"+tag, carapace.ActionCallback(func(_ carapace.Context) carapace.Action {
		if msg, err := con.ConnectComplete(); err != nil {
			return msg
		}

		res, err := con.Creds.List(context.Background(), &rpc.ReadCredentialRequest{
			Credential: &credential.Core{},
		})
		if err = aims.CheckError(err); err != nil {
			return carapace.ActionMessage("Error: %s", err)
		}
		if len(res.GetCredentials()) == 0 {
			return carapace.ActionMessage("no credentials in database")
		}

		opts := cred.Completions()
		opts = append(opts, display.WithCandidateValue(candidate, fallback))
		if split != "" {
			opts = append(opts, display.WithSplitCandidate(split))
		}

		// Colour each candidate by state (carapace styles the inserted value): a credential with
		// a usable secret is "loot" (green); a bare-username partial stays dim.
		styleOf := func(c *credential.Core) string {
			if c.GetPrivate() != nil {
				return style.Green
			}
			return style.Dim
		}

		results := display.CompletionsStyled(res.GetCredentials(), cred.DisplayFields, styleOf, opts...)

		return carapace.ActionStyledValuesDescribed(results...).Tag(tag)
	}))
}

// CompleteByID completes credential IDs, described by their public/private/type/realm/origin.
func CompleteByID(con *client.Client) carapace.Action {
	return completeCredentials(con, "ID", "", "credentials (by id)", "")
}

// CompleteByUsername completes credentials by their public username, falling back to the ID for
// key/certificate credentials that have no username.
func CompleteByUsername(con *client.Client) carapace.Action {
	return completeCredentials(con, "Public", "ID", "credentials (by username)", "")
}

// completeHashType completes the --hash-type flag with its accepted, described tokens.
func completeHashType() carapace.Action {
	return carapace.ActionValuesDescribed(
		"ntlm", "NTLM hash — replayable (pass-the-hash)",
		"replayable", "Replayable password hash",
		"nonreplayable", "Non-replayable hash (e.g. /etc/shadow)",
		"postgres", "PostgreSQL MD5 hash — replayable",
	).Tag("hash types")
}

// parseHashType maps a CLI hash-type token to its PrivateType.
func parseHashType(t string) (credential.PrivateType, error) {
	switch strings.ToLower(t) {
	case "ntlm":
		return credential.PrivateType_NTLMHash, nil
	case "replayable", "":
		return credential.PrivateType_ReplayableHash, nil
	case "nonreplayable":
		return credential.PrivateType_NonReplayableHash, nil
	case "postgres", "postgresmd5":
		return credential.PrivateType_PostgresMD5, nil
	default:
		return credential.PrivateType_Password, fmt.Errorf("unknown hash type %q (want ntlm|replayable|nonreplayable|postgres)", t)
	}
}
