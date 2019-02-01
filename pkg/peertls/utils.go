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
	"crypto/x509/pkix"
	"math/big"

	"github.com/zeebo/errs"
)

// SHA256Hash calculates the SHA256 hash of the input data
func SHA256Hash(data []byte) []byte {
	hash := crypto.SHA256.New()
	if _, err := hash.Write(data); err != nil {
		// hash.Write() is documented as never returning an error
		panic(err)
	}
	return hash.Sum(nil)
}

func parseCertificateChains(rawCerts [][]byte) ([]*Certificate, error) {
	parsedCerts, err := parseCerts(rawCerts)
	if err != nil {
		return nil, err
	}

	return parsedCerts, nil
}

func parseCerts(rawCerts [][]byte) ([]*Certificate, error) {
	certs := make([]*Certificate, len(rawCerts))
	for i, rawCert := range rawCerts {
		cert, err := LoadCertificateFromBytes(rawCert)
		if err != nil {
			return nil, ErrParseCerts.New("chain index %d: %v", i, err)
		}
		certs[i] = cert
	}
	return certs, nil
}

func verifyChainSignatures(certs []*Certificate) error {
	for i, cert := range certs {
		j := len(certs)
		if i+1 < j {
			if ok := verifyCertSignature(certs[i+1], cert); !ok {
				return ErrVerifyCertificateChain.New("signature on cert %d", i)
			}

			continue
		}

		if ok := verifyCertSignature(cert, cert); !ok {
			return ErrVerifyCertificateChain.New("self-signature on cert %d", i)
		}

	}

	return nil
}

func verifyCertSignature(parentCert *Certificate, childCert *Certificate) bool {
	return parentCert.PubKey().VerifyMsg(childCert.Signature, childCert.RawTBSCertificate)
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
