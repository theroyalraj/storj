// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package peertls

// Many cryptography standards use ASN.1 to define their data structures,
// and Distinguished Encoding Rules (DER) to serialize those structures.
// Because DER produces binary output, it can be challenging to transmit
// the resulting files through systems, like electronic mail, that only
// support ASCII. The PEM format solves this problem by encoding the
// binary data using base64.
// (see https://en.wikipedia.org/wiki/Privacy-enhanced_Electronic_Mail)

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"

	"github.com/zeebo/errs"
)

// SHA256Hash calculates the SHA256 hash of the input data
func SHA256Hash(data []byte) ([]byte, error) {
	hash := crypto.SHA256.New()
	if _, err := hash.Write(data); err != nil {
		return nil, err
	}
	return hash.Sum(nil), nil
}

func parseCertificateChains(rawCerts [][]byte) ([]*x509.Certificate, error) {
	parsedCerts, err := parseCerts(rawCerts)
	if err != nil {
		return nil, err
	}

	return parsedCerts, nil
}

func parseCerts(rawCerts [][]byte) ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, len(rawCerts))
	for i, c := range rawCerts {
		var err error
		certs[i], err = x509.ParseCertificate(c)
		if err != nil {
			return nil, ErrParseCerts.New("unable to parse certificate at index %d", i)
		}
	}
	return certs, nil
}

func verifyChainSignatures(certs []*x509.Certificate) error {
	for i, cert := range certs {
		j := len(certs)
		if i+1 < j {
			err := verifyCertSignature(certs[i+1], cert)
			if err != nil {
				return ErrVerifyCertificateChain.Wrap(err)
			}

			continue
		}

		err := verifyCertSignature(cert, cert)
		if err != nil {
			return ErrVerifyCertificateChain.Wrap(err)
		}

	}

	return nil
}

func verifyCertSignature(parentCert, childCert *x509.Certificate) error {
	return VerifySignature(childCert.Signature, childCert.RawTBSCertificate, parentCert.PublicKey)
}

func newSerialNumber() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, errs.New("failed to generateServerTls serial number: %s", err.Error())
	}

	return serialNumber, nil
}
func uniqueExts(exts []pkix.Extension) bool {
	seen := make(map[string]struct{}, len(exts))
	for _, e := range exts {
		s := e.Id.String()
		if _, ok := seen[s]; ok {
			return false
		}
		seen[s] = struct{}{}
	}
	return true
}
func signHashOf(key crypto.PrivateKey, data []byte) ([]byte, error) {
	hash, err := SHA256Hash(data)
	if err != nil {
		return nil, ErrSign.Wrap(err)
	}
	signature, err := signBytes(key, hash)
	if err != nil {
		return nil, ErrSign.Wrap(err)
	}
	return signature, nil
}
