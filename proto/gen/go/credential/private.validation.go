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
	fmt "fmt"
	"regexp"
	strings "strings"

	gorm "github.com/jinzhu/gorm"
)

// BeforeCreate_ - All Private credentials undergo various validations depending on their type.
func (p *Private) BeforeCreate_(ctx context.Context, db *gorm.DB) (*gorm.DB, error) {
	return db, p.validate()
}

// BeforeStrictUpdateSave - All Private credentials undergo various validations depending on their type.
func (p *Private) BeforeStrictUpdateSave(ctx context.Context, db *gorm.DB) (*gorm.DB, error) {
	return db, p.validate()
}

//
// Common ----------------
//

// validate - Perform all validations regardless of the Private credential type.
func (p *Private) validate() (err error) {
	// Check data null
	if yes, err := p.hasData(); !yes && err != nil {
		return err
	}

	// All credential pass through a common data formatter
	// that may apply some formatting to the data. If you
	// want to apply some to your credential type, do it here.
	p.normalizeData()

	// Then, the credential data is passed through a checker
	// that will perform some regexp matchings against the
	// Credential, depending on its declared type.
	// Add your own branching in this function if you need.
	if err = p.checkDataFormat(); err != nil {
		return err
	}

	// Additional validations.
	// Add your own branching and checks for your type. Normally
	// these checks should not make any modification to the cred data.
	switch p.Type {

	case PrivateType_Key:
		// Must be called first, otherwise can't check readable
		if err := p.checkUnencrypted(); err != nil {
			return err
		}
		if err := p.checkPrivate(); err != nil {
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
func (p *Private) hasData() (yes bool, err error) {

	// Only blank passwords can have no data
	if p.Type != PrivateType_BlankPassword && p.Data == "" {
		return false, fmt.Errorf("Private credential of type %s has no data", p.Type)
	}

	// And blank passwords must have no data
	if p.Type == PrivateType_BlankPassword && p.Data != "" {
		p.Data = ""
	}

	return true, nil
}

// Normalizes {Private.Data} by making it all lowercase so that the unique validation and index on
// ({Private.Type}, {.Data}) catches collision in a case-insensitive manner without the need
// to use case-insensitive comparisons.
func (p *Private) normalizeData() {
	switch p.Type {
	case PrivateType_NTLMHash, PrivateType_PostgresMD5:
		p.Data = strings.ToLower(p.Data)
	}
}

// The credential data is passed through a checker that will perform some regexp matchings against the
// Credential, depending on its declared type. Add your own branching in this function if you need.
func (p *Private) checkDataFormat() (err error) {
	switch p.Type {

	case PrivateType_NTLMHash:
		// Check the structure of the data: we must find one or two hashes.
		if err := p.dataFormatNTLM(); err != nil {
			return err
		}

	case PrivateType_PostgresMD5:
		if err := p.dataFormatPostresMD5(); err != nil {
			return err
		}
	}
	return
}

//
// Cryptographic Keys -----------
//

// checkReadable - Check that we can successfully load this key into a native Go type.
func (p *Private) checkReadable() (err error) {

	// The parsing either outputs an ecc.PrivateKey, rsa.PrivateKey
	// or ed25519.PrivateKey. We don't care why one as long as no errors.
	_, err = x509.ParsePKCS8PrivateKey([]byte(p.Data))

	return
}

// checkUnencrypted -  Whether the key data in is encrypted.
// Encrypted keys cannot be saved and should be decrypted before saving.
func (p *Private) checkUnencrypted() (err error) {
	matched, err := regexp.Match("ENCRYPTED", []byte(p.Data))
	if matched {
		return fmt.Errorf("Private Key is encrypted, cannot save to DB")
	}
	return nil
}

// checkPrivate - Check that the credential data is a Private Key
func (p *Private) checkPrivate() (err error) {
	matched, err := regexp.Match("-----BEGIN (.+) PRIVATE KEY-----", []byte(p.Data))
	if matched {
		return fmt.Errorf("Credential data is not a Private Key")
	}
	return nil
}

//
// NTLM Hash --------------------
//

const (
	// LanManagerHexCharacters - See https://en.wikipedia.org/wiki/LM_hash#Algorithm
	LanManagerHexCharacters = 14
	// Valid format for LAN Manager hex digest portion of {#data}: 32 lowercase hexadecimal characters.
	lanManagerHexDigestRegexp = "[0-9a-f]{32}"
	// Valid format for NT LAN Manager hex digest portion of {#data}: 32 lowercase hexadecimal characters.
	ntLanManagerHexDigestRegexp = "[0-9a-f]{32}"

	// Value of {lanManagerHexDigestRegexp} when the effective password
	// is blank because it exceeds {lanManagerMaxCharacters}
	blankLMHash = "aad3b435b51404eeaad3b435b51404ee"
	// # Value of {ntLanManagerHexDigestRegexp} when the password is blank.
	blankNTHash = "31d6cfe0d16ae931b73c59d7e0c089c0"
)

var (
	//Valid format for {#data} composed of `'<LAN Manager hex digest>:<NT LAN Manager hex digest>'`.
	ntlmDataRegexp = fmt.Sprintf("\\A%s:%s\\z", lanManagerHexDigestRegexp, ntLanManagerHexDigestRegexp)
)

// Validates that {#data} is in the NTLM data format of <LAN Manager hex digest>:<NT LAN Manager hex digest>.
// Both hex digests are 32 lowercase hexadecimal characters.
func (p *Private) dataFormatNTLM() (err error) {
	re := regexp.MustCompile(ntlmDataRegexp)
	if match := re.MatchString(p.Data); !match {
		return fmt.Errorf("NTML Credential data does not match its associated regular expression")
	}
	return
}

// lmHashPresent - Check that we have the LM portion of the hash
func (p *Private) lmHashPresent() bool {
	if strings.HasPrefix(p.Data, blankLMHash) {
		return false
	}
	return true
}

// verify we don't have a blank Password under the appearance of a default NTLM hash.
func (p *Private) blankPassword() bool {
	match, err := regexp.MatchString(fmt.Sprintf("%s:%s", blankLMHash, blankNTHash), p.Data)
	if err != nil {
		return false
	}
	if match {
		return true
	}
	return false
}

//
// PostgreSQL MD5 --------------------
//

const (
	postresMD5Regexp = "md5([a-f0-9]{32})"
)

// Validates that {#data} is in the PostgreSQL MD5 data format.
func (p *Private) dataFormatPostresMD5() (err error) {
	re := regexp.MustCompile(postresMD5Regexp)
	if match := re.MatchString(p.Data); !match {
		return fmt.Errorf("PostgresMD5 Credential is not in Postgres MD5 Hash format")
	}
	return
}
