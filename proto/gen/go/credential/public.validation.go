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
	fmt "fmt"

	gorm "github.com/jinzhu/gorm"
)

// BeforeCreate_ - All Public credentials undergo various validations depending on their type.
func (p *Public) BeforeCreate_(ctx context.Context, db *gorm.DB) (*gorm.DB, error) {
	return db, p.validate()
}

// BeforeStrictUpdateSave - All Public credentials undergo various validations depending on their type.
func (p *Public) BeforeStrictUpdateSave(ctx context.Context, db *gorm.DB) (*gorm.DB, error) {
	return db, p.validate()
}

//
// Common ----------------
//

// validate - Perform all validations regardless of the Public credential type.
func (p *Public) validate() (err error) {
	// Check data null
	if yes, err := p.hasData(); !yes && err != nil {
		return err
	}

	// All validations have passed successfully, we can save.
	return
}

// hasData - Validate that we have data when we need to
func (p *Public) hasData() (yes bool, err error) {

	// Only blank passwords can have no data
	if p.Type != PublicType_BlankUsername && p.Username == "" {
		return false, fmt.Errorf("Public credential of type %s has no data", p.Type.String())
	}

	// And blank passwords must have no data
	if p.Type == PublicType_BlankUsername && p.Username != "" {
		p.Username = ""
	}

	return true, nil
}
