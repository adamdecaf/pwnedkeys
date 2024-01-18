// Copyright 2018 Adam Shannon
// Use of this source code is governed by an Apache License
// license that can be found in the LICENSE file.

package pwnedkeys

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPwnedkeys__CheckCertificate checks against the pwnedkeys.com API for
// certificates that are known to be included in the database.
func TestPwnedkeys__CheckCertificate(t *testing.T) {
	cases := []string{
		filepath.Join("testdata", "p256_cert.pem"),
	}

	for i := range cases {
		bs, err := os.ReadFile(cases[i])
		if err != nil {
			t.Fatalf("file: %s couldn't be read: %v", cases[i], err)
		}
		certs, err := parsePEM(bs)
		if err != nil || len(certs) != 1 {
			t.Errorf("file: %s wasn't read as PEM properly (certs=%d): %v", cases[i], len(certs), err)
		}

		err = CheckCertificate(http.DefaultClient, certs[0])
		if err == nil {
			t.Errorf("file %s had no error, but expected one", cases[i])
		}
		if !strings.Contains(err.Error(), "private key found") {
			t.Errorf("file: %s had unknown error: %v", cases[i], err)
		}
	}
}

func TestPwnedKeys__CheckFingerprint(t *testing.T) {
	// Example fingerprints from https://pwnedkeys.com/search.html
	cases := []string{
		"9e03b56749abe821a6f5299d6f634b35404975f0552eb3347bf3adfad9af1109", // 2048 RSA
		"819f7d1dcd9f07bfcb59b7699f68994d89390c3bcd498cf7fb2e1ef3d272b89b", // P-256 EC
		"316194405bf1c56c3395c4b6fcf32af83ca0e273fbf0832ef8364069a178ad75", // P-256 EC
	}
	for i := range cases {
		err := CheckFingerprint(http.DefaultClient, cases[i])
		if !errors.Is(err, ErrKeyFound) {
			t.Errorf("fingerprint %s was not found in pwnedkeys", cases[i])
		}
	}
}

func parsePEM(blob []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	var block *pem.Block
	for {
		block, blob = pem.Decode(blob)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}
			certs = append(certs, cert)
		}
	}
	return certs, nil
}
