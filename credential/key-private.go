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

	"github.com/maxlandon/gondor/maltego"
	"golang.org/x/crypto/ssh"

	"github.com/maxlandon/aims/proto/gen/go/credential"
)

// PrivateKey - The Private part of a cryptographic key. All private key types
// in AIMS are derived from this type, but the base type offers some methods
// allowing to get the key type, cyphers, algorithms and other info about it.
type PrivateKey Private

// NewPrivateKeyFromBytes - Creates a new Private key from bytes data.
func NewPrivateKeyFromBytes(data []byte) *PrivateKey {
	p := PrivateKey(Private{Data: string(data)})
	p.Type = credential.PrivateType_Key
	return &p
}

//
// General Functions
//

// ToORM - Get the SQL object for the PrivateKey credential.
func (p *PrivateKey) ToORM(ctx context.Context) (credential.PrivateORM, error) {
	p.Type = credential.PrivateType_Key
	return (*Private)(p).ToORM(ctx)
}

// ToPB - Get the Protobuf object for the PrivateKey credential.
func (p *PrivateKey) ToPB() *credential.Private {
	p.Type = credential.PrivateType_Key
	return (*Private)(p).ToPB()
}

// AsEntity - Returns the PrivateKey as a valid Maltego Entity.
func (p *PrivateKey) AsEntity() maltego.Entity {
	// e:= maltego.NewEntity(h)
	// base := (*Private)(h).AsEntity()
	// e.SetBase(base)
	// return e
	return maltego.NewEntity(p)
}

//
// Key Functions
//

// Fingerprint - The private returns its base64-encoded, md5-hashed fingerprint.
// MD5 is used because this function is not meant to be used in networking code.
func (p *PrivateKey) Fingerprint() (fingerprint string) {
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

// Algorithm - Gives the cipher algorithm for the Private key
func (p *PrivateKey) Algorithm() x509.PublicKeyAlgorithm {
	return p.AsCertificate().PublicKeyAlgorithm
}

// AsCertificate - Returns the Private key parsed into a Certificate.
// Note that this will automatically return you a Certificate filed
func (p *PrivateKey) AsCertificate() *x509.Certificate {
	// Get a key for our data, with a short
	// indication of what type of key it is.
	_, data, _ := p.toValidData()

	// Parse the key into a certificate
	cert, _ := x509.ParseCertificate(data)
	return cert
}

func (p *PrivateKey) toValidData() (key interface{}, data []byte, isPKCS1 bool) {

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
