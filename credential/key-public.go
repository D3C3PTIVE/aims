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
	"crypto/md5"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"

	"github.com/maxlandon/gondor/maltego"
	"golang.org/x/crypto/ssh"

	"github.com/maxlandon/aims/proto/credential"
)

// PublicKey - The Public part of a cryptographic key. All public key types
// in AIMS are derived from this type, but the base type offers some methods
// allowing to get the key type, cyphers, algorithms and other info about it.
// As well, a credential.PublicKey can be used to produce Certificates, which
// - as a reminder - are not keys but public.Credentials *containing* a key.
type PublicKey Public

// NewPublicKeyFromBytes - Creates a new Public key from bytes data.
func NewPublicKeyFromBytes(data []byte) *PublicKey {
	p := PublicKey(Public{Data: string(data)})
	p.Type = credential.PublicType_PublicKey
	return &p
}

//
// General Functions
//

// ToORM - Get the SQL object for the PublicKey credential.
func (p *PublicKey) ToORM(ctx context.Context) (credential.PublicORM, error) {
	p.Type = credential.PublicType_PublicKey
	return (*Public)(p).ToORM(ctx)
}

// ToPB - Get the Protobuf object for the PublicKey credential.
func (p *PublicKey) ToPB() *credential.Public {
	p.Type = credential.PublicType_PublicKey
	return (*Public)(p).ToPB()
}

// AsEntity - Returns the PublicKey as a valid Maltego Entity.
func (p *PublicKey) AsEntity() maltego.Entity {
	// e:= maltego.NewEntity(h)
	// base := (*Private)(h).AsEntity()
	// e.SetBase(base)
	// return e
	return maltego.NewEntity(p)
}

//
// Key Functions
//

// Fingerprint - The public returns its base64-encoded, md5-hashed fingerprint.
// MD5 is used because this function is not meant to be used in networking code.
func (p *PublicKey) Fingerprint() string {
	_, data, _ := p.toValidData()
	pk, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err == nil {
		return ssh.FingerprintLegacyMD5(pk)
	}
	// Ensure base-64
	k, _ := base64.StdEncoding.DecodeString(string(data))
	hash := md5.New()
	return string(hash.Sum(k))
}

// Algorithm - Gives the cipher algorithm for the Public key
func (p *PublicKey) Algorithm() x509.PublicKeyAlgorithm {
	return p.AsCertificate().PublicKeyAlgorithm
}

// AsCertificate - Returns the Public key parsed into a Certificate,
// which might help for any use in native networking code, or even
// for additional usage/printing of the information embedded in the key.
func (p *PublicKey) AsCertificate() *x509.Certificate {
	// Get a key for our data, with a short
	// indication of what type of key it is.
	_, data, _ := p.toValidData()

	// Parse the key into a certificate
	cert, _ := x509.ParseCertificate(data)
	return cert
}

// errIsPKCS1 - Reexport of the x509.ParsePKIXPublicKey function when failing to parse ASN1 format
var errIsPKCS1 = errors.New("x509: failed to parse public key (use ParsePKCS1PublicKey instead for this key format)")

func (p *PublicKey) toValidData() (key interface{}, data []byte, isPKCS1 bool) {

	// Start with PKIX standard
	key, err := x509.ParsePKIXPublicKey([]byte(p.Data))

	// If it's a PKCS1 format, handle that.
	if err == errIsPKCS1 {
		isPKCS1 = true
		key, err = x509.ParsePKCS1PublicKey([]byte(p.Data))
	}

	// And marshal according to the type
	if !isPKCS1 {
		data, _ = x509.MarshalPKIXPublicKey(key)
	}

	// ... with a little cast if needed
	if isPKCS1 {
		rsaKey := key.(*rsa.PublicKey)
		data = x509.MarshalPKCS1PublicKey(rsaKey)
	}

	return
}
