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
	context "context"
	"errors"
	fmt "fmt"
	time "time"

	gorm "github.com/jinzhu/gorm"
)

// BeforeCreate_ - All Logins undergo various validations based on their Status
func (l *Login) BeforeCreate_(ctx context.Context, db *gorm.DB) (*gorm.DB, error) {
	return db, l.validate()
}

// BeforeStrictUpdateSave - All Logins undergo various validations based on their Status
func (l *Login) BeforeStrictUpdateSave(ctx context.Context, db *gorm.DB) (*gorm.DB, error) {
	return db, l.validate()
}

// Login - Root login validation function, with checkers and formatters.
func (l *Login) validate() (err error) {

	// Check consistency of attempts with the claimed status of the Login
	if err = l.consistentLastAttempt(); err != nil {
		return err
	}

	// We must always have a service attached
	if l.Service == nil {
		return errors.New("Credential Login is not tied to a Service")
	}

	// Metasploit checks if the credential.Core of our login
	// is unique for the service we're authenticating to.
	// We don't do that since we can't have twice the same core in the database.

	// All validations have passed successfully, we can save.
	return
}

// Validates that LastAttemptedAt is nil when Status is credential.LoginStatus_Untried and
// that LastAttemptedAt is not nil when Status is not credential.LoginStatus_Untried.
func (l *Login) consistentLastAttempt() (err error) {

	// If we are untried, we must not have an attempt
	if l.Status == LoginStatus_Untried && l.LastAttemptedAt != nil {
		if l.LastAttemptedAt.Seconds == 0 && l.LastAttemptedAt.Nanos == 0 {
			return nil
		}
		last := time.Duration(time.Second * time.Duration(l.LastAttemptedAt.Seconds))
		return fmt.Errorf("Login is Untried although last attempt is %s", last.String())
	}

	// If we are tried, we must have an attempt.
	if l.LastAttemptedAt.Seconds == 0 && l.LastAttemptedAt.Nanos == 0 {
		if l.Status == LoginStatus_Untried {
			return nil
		}
		return fmt.Errorf("Login is %s but has no last attempt time", l.Status.String())
	}
	return
}
