// Copyright 2018 Adam Shannon
// Use of this source code is governed by an Apache License
// license that can be found in the LICENSE file.

package pwnedkeys

import (
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

// TestPwnedkeys__found checks against the pwnedkeys.com API for
// certificates that are known to be included in the database.
func TestPwnedkeys__found(t *testing.T) {
	cases := []string{
		filepath.Join("testdata", "p256_cert.pem"),
	}

	for i := range cases {
		bs, err := ioutil.ReadFile(cases[i])
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
