// Copyright 2018 Adam Shannon
// Use of this source code is governed by an Apache License
// license that can be found in the LICENSE file.

// Package pwnedkeys looks up Certificates, Certificate requests, Keys, etc in the pwnedkeys.com database.
//
// Lookup is done using the SubjectPublicKeyInfo (SPKI) associated with a key. The SPKI fingerprint of a key (or certificate)
// is the all-lowercase hex-encoded SHA-256 hash of the DER-encoded form of the subjectPublicKeyInfo ASN.1 structure representing
// a given public key.
package pwnedkeys

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
)

var (
	// ErrKeyFound is returned when the key was found in pwnedkeys.com database
	ErrKeyFound   = errors.New("private key found in pwnedkeys.com database")

	// ErrHashFailed is returned only when the SHA-256 hashing fails.
	ErrHashFailed = errors.New("unable to generate SHA-256 hash")
)

// CheckCertificate returns a non-nil error only if the key information is found in the pwnedkeys.com database.
// Finding key data implies a compromised key.
func CheckCertificate(client *http.Client, cert *x509.Certificate) error {
	return check(client, cert.RawSubjectPublicKeyInfo)
}

// check makes an HTTP call to the pwnedkeys.com API and returns an error
// if the key was found. A found key represents a compromised key.
func check(client *http.Client, bs []byte) error {
	hash := computeSha256(bs)
	if hash == "" {
		return ErrHashFailed
	}

	resp, err := client.Get(fmt.Sprintf("https://v1.pwnedkeys.com/%s", hash))
	if err != nil {
		return fmt.Errorf("problem with pwnedkeys.com GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		// If the response to the request is a 200 OK, then the key appears in the database
		return ErrKeyFound
	}
	if resp.StatusCode == 404 {
		// while a 404 response indicates that the key doesn’t appear in the pwnedkeys database.
		return nil
	}
	return fmt.Errorf("bogus HTTP status: got %v", resp.Status)
}

// computeSha256 returns the lowercase hex-encoded SHA-256 hash of the given bytes.
// An empty string returned represents an error.
func computeSha256(bs []byte) string {
	ss := sha256.New()
	n, err := ss.Write(bs)
	if err != nil || n == 0 {
		return ""
	}
	return hex.EncodeToString(ss.Sum(nil))
}
