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
	"bytes"
	"crypto/des"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"unicode/utf16"

	"github.com/maxlandon/gondor/maltego"
	"golang.org/x/crypto/md4"

	"github.com/maxlandon/aims/proto/credential"
)

// NTLMHash - A credential.Private password hash that can be credential.ReplayableHash replayed
// to authenticate to SMB.  It is composed of two hash hex digests (where the hash bytes are
// printed as a hexadecimal string where 2 characters represent a byte of the original hash with
// the high nibble first): (1) {lanManagerHexDigestRegexp, the LAN Manager hash's hex digest} and
// (2) {ntLanManagerHexDigestRegexp, the NTLM hash's hex digest}.
// NOTE: Please instantiate a new NTLMHash with NewNTLMHash().
type NTLMHash Private

// NewNTLMHash - Create a new NTLM hash Credential.
func NewNTLMHash(hash []byte) *NTLMHash {
	h := NTLMHash(Private{Data: string(hash)})
	h.Type = credential.PrivateType_NTLMHash
	h.JTRFormat = "nt,lm"
	return &h
}

//
// General Functions
//

// ToPB - Get the Protobuf object for the NTLMHash credential.
func (h *NTLMHash) ToPB() *credential.Private {
	h.Type = credential.PrivateType_NTLMHash
	return (*Private)(h).ToPB()
}

// AsEntity - Returns the Private as a valid Maltego Entity.
func (h *NTLMHash) AsEntity() maltego.Entity {
	// e:= maltego.NewEntity(h)
	// base := (*Private)(h).AsEntity()
	// e.SetBase(base)
	// return e
	return maltego.NewEntity(h)
}

//
// Type-Specific functions
//

// HexDigest - Converts a buffer containing `hash` bytes to a String containing the hex digest of that `hash`.
// @param hash [String] a buffer of bytes
// @return [String] a string where every 2 hexadecimal characters represents a byte in the original hash buffer.
func (h *NTLMHash) HexDigest(hash []byte) (digest string) {
	return hex.EncodeToString(hash)
}

// LMHexDigestFromPassword - Converts a Private.Data to an LanManager Hash hex digest.
// Handles passwords over the LanManager limit of 14 characters by treating them as ” for the
// LanManager Hash calculation.
//
// @param password_data the plain text password
// @return  a 32 character hexadecimal string
func (h *NTLMHash) LMHexDigestFromPassword(password string) (digest string) {
	effectiveData := password
	if len(password) > credential.LanManagerHexCharacters {
		effectiveData = ""
	}

	// Taken from https://github.com/free/sql_exporter/blob/master/vendor/github.com/denisenkom/go-mssqldb/ntlm.go
	var hash [21]byte
	var lmpass [14]byte
	copy(lmpass[:14], []byte(strings.ToUpper(effectiveData)))
	magic := []byte("KGS!@#$%")
	encryptDes(lmpass[:7], magic, hash[:8])
	encryptDes(lmpass[7:], magic, hash[8:])

	// Return the encoded version
	return hex.EncodeToString(hash[:])
}

// NTLMHexDigestFromPassword - Converts a Private.Password.Data to a NTLM Hash hex digest.
//
//	@param password_data the plain text password
//	@return a 32 character hexadecimal string
func (h *NTLMHash) NTLMHexDigestFromPassword(password string) (digest string) {
	var hash [21]byte
	hache := md4.New()
	hache.Write(utf16le(password))
	hache.Sum(hash[:0])

	// Return the encoded version
	return hex.EncodeToString(hash[:])
}

//
// LM Utils ----------------------
//

func createDesKey(bytes, material []byte) {
	material[0] = bytes[0]
	material[1] = (byte)(bytes[0]<<7 | (bytes[1]&0xff)>>1)
	material[2] = (byte)(bytes[1]<<6 | (bytes[2]&0xff)>>2)
	material[3] = (byte)(bytes[2]<<5 | (bytes[3]&0xff)>>3)
	material[4] = (byte)(bytes[3]<<4 | (bytes[4]&0xff)>>4)
	material[5] = (byte)(bytes[4]<<3 | (bytes[5]&0xff)>>5)
	material[6] = (byte)(bytes[5]<<2 | (bytes[6]&0xff)>>6)
	material[7] = (byte)(bytes[6] << 1)
}

func encryptDes(key []byte, cleartext []byte, ciphertext []byte) {
	var desKey [8]byte
	createDesKey(key, desKey[:])
	cipher, err := des.NewCipher(desKey[:])
	if err != nil {
		panic(err)
	}
	cipher.Encrypt(ciphertext, cleartext)
}

func toUnicode(s string) []byte {
	uints := utf16.Encode([]rune(s))
	b := bytes.Buffer{}
	binary.Write(&b, binary.LittleEndian, &uints)
	return b.Bytes()
}

//
// NT_LM Utils ----------------------
//

func utf16le(val string) []byte {
	var v []byte
	for _, r := range val {
		if utf16.IsSurrogate(r) {
			r1, r2 := utf16.EncodeRune(r)
			v = append(v, byte(r1), byte(r1>>8))
			v = append(v, byte(r2), byte(r2>>8))
		} else {
			v = append(v, byte(r), byte(r>>8))
		}
	}
	return v
}
