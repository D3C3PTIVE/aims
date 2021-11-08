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

	gorm "github.com/jinzhu/gorm"
)

// BeforeCreate_ - All Cores undergo various validations based on their Status
func (c *Core) BeforeCreate_(ctx context.Context, db *gorm.DB) (*gorm.DB, error) {
	return db, c.validate()
}

// BeforeStrictUpdateSave - All Cores undergo various validations based on their Status
func (c *Core) BeforeStrictUpdateSave(ctx context.Context, db *gorm.DB) (*gorm.DB, error) {
	return db, c.validate()
}

// Login - Root credential.Core validation function.
func (c *Core) validate() (err error) {

	// Always check the fields are populated consistently
	// with the proclaimed Origin type. Might set values
	// to unknown strings when empty.
	if err = c.checkOriginConsistent(); err != nil {
		return err
	}

	// All validations have passed successfully, we can save.
	return
}

// checkOriginConsistent - Always check the fields are
// populated consistently with the proclaimed Origin type.
func (c *Core) checkOriginConsistent() (err error) {
	if c.Origin == nil {
		return errors.New("Credential Core cannot have no Origin")
	}

	// Import
	if c.Origin.Type == OriginType_Import && c.Origin.Filename == "" {
		c.Origin.Filename = "<unknown>"
	}

	// Cracked
	if c.Origin.Type == OriginType_CrackedPassword && c.Origin.Cracker == "" {
		c.Origin.Cracker = "<unknown>"
	}

	// Service
	if c.Origin.Type == OriginType_Service && c.Origin.Service == nil {
		return fmt.Errorf("Core declares origin %s but has no Service",
			OriginType_Service.String())
	}

	return
}
