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
	"crypto/x509"
	"errors"
	fmt "fmt"
	"regexp"

	gorm "github.com/jinzhu/gorm"
	uuid "github.com/satori/go.uuid"
)

// BeforeCreate_ - All Public credentials undergo various validations depending on their type.
func (p *PublicORM) BeforeCreate_(ctx context.Context, db *gorm.DB) (*gorm.DB, error) {
	return db, p.validate()
}

// BeforeStrictUpdateSave - All Public credentials undergo various validations depending on their type.
func (p *PublicORM) BeforeStrictUpdateSave(ctx context.Context, db *gorm.DB) (*gorm.DB, error) {
	return db, p.validate()
}

//
// Common ----------------
//

// validate - Perform all validations regardless of the Public credential type.
func (p *PublicORM) validate() (err error) {
	// Check data null
	if yes, err := p.hasData(); !yes && err != nil {
		return err
	}

	// Additional validations.
	// Add your own branching and checks for your type. Normally
	// these checks should not make any modification to the cred data.
	switch p.Type {

	case int32(PublicType_PublicKey):
		// Must be called first, otherwise can't check readable
		if err := p.checkUnencrypted(); err != nil {
			return err
		}
		if err := p.checkReadable(); err != nil {
			return err
		}
	}

	// All validations have passed successfully, we can save.
	return
}

// hasData - Validate that we have data when we need to
func (p *PublicORM) hasData() (yes bool, err error) {

	// Only blank passwords can have no data
	if p.Type == int32(PublicType_Username) && p.Username == "" {
		return false, fmt.Errorf("Public credential of type %s has no data",
			PublicType(p.Type).String())
	}

	// And blank passwords must have no data
	if p.Type == int32(PublicType_BlankUsername) && p.Username != "" {
		p.Username = ""
	}

	return true, nil
}

//
// Cryptographic Keys -----------
//

var errIsPKCS1 = errors.New("x509: failed to parse public key (use ParsePKCS1PublicKey instead for this key format)")

// checkReadable - Check that we can successfully load this key into a native Go type.
func (p *PublicORM) checkReadable() (err error) {

	// The parsing either outputs an ecc.PublicKey, rsa.PublicKey, dsa.PublicKey
	// or ed25519.PublicKey. We don't care why one as long as no errors.

	// Start with PKIX standard
	_, err = x509.ParsePKIXPublicKey([]byte(p.Data))

	// If it's a PKCS1 format, handle that.
	if err == errIsPKCS1 {
		_, err = x509.ParsePKCS1PublicKey([]byte(p.Data))
	}

	return
}

// checkUnencrypted -  Whether the key data in is encrypted.
// Encrypted keys cannot be saved and should be decrypted before saving.
func (p *PublicORM) checkUnencrypted() (err error) {
	matched, err := regexp.Match("ENCRYPTED", []byte(p.Data))
	if matched {
		return fmt.Errorf("Public Key is encrypted, cannot save to DB")
	}
	return nil
}

// checkUniqueness - Some private types, such as cryptographic keys
// and some tokens, must have .Data unique among all saved credentials.
func (p *PublicORM) checkUniqueness(db *gorm.DB) (err error) {
	switch p.Type {
	// Passwords can be identical from one access to another.
	case int32(PublicType_BlankUsername), int32(PublicType_Username):
		return
	default:
		// NOTE: that we consider here that MD5 hashes are collision-free...
		var cred = &PublicORM{}
		err = db.Where(&PrivateORM{Data: p.Data}).First(cred).Error

		// Either we didn't find it, we're good
		if err == gorm.ErrRecordNotFound {
			return nil
		}
		// Of another error but credential fetched, good
		if err != nil && cred.Id == uuid.Nil {
			return nil
		}
		// Or no error and we have an ID, thus a collision.
		if err == nil && cred.Id != uuid.Nil {
			return fmt.Errorf("Public %s (%s) key is colliding",
				PublicType(cred.Type).String(), cred.Id.String())
		}
	}
	return
}

//
