// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package peertls

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"io"

	"github.com/zeebo/errs"

	"storj.io/storj/pkg/utils"
)

const (
	// PEMLabelEcPrivateKey is the value to define a block type of elliptic curve private key
	PEMLabelEcPrivateKey = "EC PRIVATE KEY"
	// PEMLabelEcPublicKey is the value to define a block type of elliptic curve public key
	PEMLabelEcPublicKey = "ECDSA PUBLIC KEY"
	// PEMLabelCertificate is the value to define a block type of certificates
	PEMLabelCertificate = "CERTIFICATE"
	// PEMLabelExtension is the value to define a block type of certificate extensions
	PEMLabelExtension = "EXTENSION"
)

var (
	// ErrNotExist is used when a file or directory doesn't exist.
	ErrNotExist = errs.Class("file or directory not found error")
	// ErrGenerate is used when an error occurred during cert/key generation.
	ErrGenerate = errs.Class("tls generation error")
	// ErrUnsupportedKey is used when key type is not supported.
	ErrUnsupportedKey = errs.Class("unsupported key type")
	// ErrTLSTemplate is used when an error occurs during tls template generation.
	ErrTLSTemplate = errs.Class("tls template error")
	// ErrVerifyPeerCert is used when an error occurs during `VerifyPeerCertificate`.
	ErrVerifyPeerCert = errs.Class("tls peer certificate verification error")
	// ErrParseCerts is used when an error occurs while parsing a certificate or cert chain.
	ErrParseCerts = errs.Class("unable to parse certificate")
	// ErrParseKey is used when an error occurs while parsing a private key.
	ErrParseKey = errs.Class("unable to parse key")
	// ErrVerifySignature is used when a signature can not be verified.
	ErrVerifySignature = errs.Class("signature verification error")
	// ErrVerifyCertificateChain is used when a certificate chain can't be verified from leaf to root
	// (i.e.: each cert in the chain should be signed by the preceding cert and the root should be self-signed).
	ErrVerifyCertificateChain = errs.Class("certificate chain signature verification failed")
	// ErrVerifyCAWhitelist is used when a signature wasn't produced by any CA in the whitelist.
	ErrVerifyCAWhitelist = errs.Class("not signed by any CA in the whitelist")
	// ErrSign is used when something goes wrong while generating a signature.
	ErrSign = errs.Class("unable to generate signature")
)

type Certificate struct {
	*x509.Certificate
	pubKey PublicKey
}

func NewCertificate(x509Cert *x509.Certificate) (*Certificate, error) {
	pubKey := NewPublicKey(x509Cert.PublicKey)
	if pubKey == nil {
		return nil, ErrUnsupportedKey.New("certificate %q public key type %s",
			x509Cert.Subject.String(), x509Cert.PublicKeyAlgorithm.String())
	}
	return &Certificate{x509Cert, pubKey}, nil
}

func (cert *Certificate) PubKey() PublicKey {
	return cert.pubKey
}

func (cert *Certificate) VerifyMsg(msg, sig []byte) bool {
	return cert.pubKey.VerifyMsg(msg, sig)
}

func LoadCertificateFromBytes(certBytes []byte) (*Certificate, error) {
	x509Cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, ErrParseCerts.Wrap(err)
	}
	return NewCertificate(x509Cert)
}

func CertificatesSlice(x509Certs []*x509.Certificate) ([]*Certificate, error) {
	certs := make([]*Certificate, len(x509Certs))
	for i, xCert := range x509Certs {
		cert, err := NewCertificate(xCert)
		if err != nil {
			return nil, ErrUnsupportedKey.New("chain index %d: %v", i, errs.Unwrap(err))
		}
		certs[i] = cert
	}
	return certs, nil
}

// PeerX509CertVerificationFunc is the signature for a `*tls.Config{}`'s
// `VerifyPeerCertificate` function.
type PeerX509CertVerificationFunc func([][]byte, [][]*x509.Certificate) error

// PeerCertVerificationFunc is the signature for VerifyPeerFunc argument functions
// that accept peertls-aware Certificate objects.
type PeerCertVerificationFunc func([][]byte, [][]*Certificate) error

// VerifyPeerFunc combines multiple `*tls.Config#VerifyPeerCertificate`
// functions and adds certificate parsing.
func VerifyPeerFunc(next ...PeerCertVerificationFunc) PeerX509CertVerificationFunc {
	return func(chain [][]byte, _ [][]*x509.Certificate) error {
		c, err := parseCertificateChains(chain)
		if err != nil {
			return ErrVerifyPeerCert.Wrap(err)
		}

		for _, n := range next {
			if n != nil {
				if err := n(chain, [][]*Certificate{c}); err != nil {
					return ErrVerifyPeerCert.Wrap(err)
				}
			}
		}
		return nil
	}
}

// VerifyPeerCertChains verifies that the first certificate chain contains certificates
// which are signed by their respective parents, ending with a self-signed root.
func VerifyPeerCertChains(_ [][]byte, parsedChains [][]*Certificate) error {
	return verifyChainSignatures(parsedChains[0])
}

// VerifyCAWhitelist verifies that the peer identity's CA was signed by any one
// of the (certificate authority) certificates in the provided whitelist.
func VerifyCAWhitelist(cas []*Certificate) PeerCertVerificationFunc {
	if cas == nil {
		return nil
	}
	return func(_ [][]byte, parsedChains [][]*Certificate) error {
		for _, ca := range cas {
			if ok := verifyCertSignature(ca, parsedChains[0][CAIndex]); ok {
				return nil
			}
		}
		return ErrVerifyCAWhitelist.New("CA cert")
	}
}

// NewCertBlock converts an ASN1/DER-encoded byte-slice of a tls certificate
// into a `pem.Block` pointer.
func NewCertBlock(b []byte) *pem.Block {
	return &pem.Block{Type: PEMLabelCertificate, Bytes: b}
}

// NewExtensionBlock converts an ASN1/DER-encoded byte-slice of a tls certificate
// extension into a `pem.Block` pointer.
func NewExtensionBlock(b []byte) *pem.Block {
	return &pem.Block{Type: PEMLabelExtension, Bytes: b}
}

// TLSCert creates a tls.Certificate from chains, key and leaf.
func TLSCert(chain [][]byte, leaf *Certificate, key PrivateKey) (*tls.Certificate, error) {
	var err error
	var leafX509 *x509.Certificate
	if leaf == nil {
		leafX509, err = x509.ParseCertificate(chain[0])
		if err != nil {
			return nil, err
		}
	} else {
		leafX509 = leaf.Certificate
	}

	return &tls.Certificate{
		Leaf:        leafX509,
		Certificate: chain,
		PrivateKey:  key.CryptoPrivate(),
	}, nil
}

// WriteChain writes the certificate chain (leaf-first) to the writer, PEM-encoded.
func WriteChain(w io.Writer, chain ...*Certificate) error {
	if len(chain) < 1 {
		return errs.New("expected at least one certificate for writing")
	}

	var extErrs utils.ErrorGroup
	for _, c := range chain {
		if err := pem.Encode(w, NewCertBlock(c.Raw)); err != nil {
			return errs.Wrap(err)
		}

		for _, e := range c.ExtraExtensions {
			extBytes, err := asn1.Marshal(e)
			if err != nil {
				extErrs.Add(errs.Wrap(err))
			}
			if err := pem.Encode(w, NewExtensionBlock(extBytes)); err != nil {
				extErrs.Add(errs.Wrap(err))
			}
		}
	}
	return extErrs.Finish()
}

// ChainBytes returns bytes of the certificate chain (leaf-first) to the writer, PEM-encoded.
func ChainBytes(chain ...*Certificate) ([]byte, error) {
	var data bytes.Buffer
	err := WriteChain(&data, chain...)
	return data.Bytes(), err
}

// CreateSelfSignedCertificate creates a new self-signed X.509v3 certificate
// using fields from the given template.
func CreateSelfSignedCertificate(key PrivateKey, template *x509.Certificate) (*Certificate, error) {
	return CreateCertificate(key.PubKey(), key, template, template)
}

// CreateCertificate creates a new X.509v3 certificate based on a template.
// The new certificate:
//
//  * will have the public key given as 'signee'
//  * will be signed by 'signer' (which should be the private key of 'issuer')
//  * will be issued by 'issuer'
//  * will have metadata fields copied from 'template'
//
// Returns the new Certificate object.
func CreateCertificate(signee PublicKey, signer PrivateKey, template, issuer *x509.Certificate) (
	*Certificate, error) {
	cb, err := x509.CreateCertificate(
		rand.Reader,
		template,
		issuer,
		signee.CryptoPublic(),
		signer.CryptoPrivate(),
	)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	return LoadCertificateFromBytes(cb)
}

// VerifyUnrevokedChainFunc returns a peer certificate verification function which
// returns an error if the incoming cert chain contains a revoked CA or leaf.
func VerifyUnrevokedChainFunc(revDB *RevocationDB) PeerCertVerificationFunc {
	return func(_ [][]byte, chains [][]*Certificate) error {
		leaf := chains[0][LeafIndex]
		ca := chains[0][CAIndex]
		lastRev, lastRevErr := revDB.Get(chains[0])
		if lastRevErr != nil {
			return ErrExtension.Wrap(lastRevErr)
		}
		if lastRev == nil {
			return nil
		}

		if bytes.Equal(lastRev.CertHash, ca.Raw) || bytes.Equal(lastRev.CertHash, leaf.Raw) {
			lastRevErr := lastRev.Verify(ca)
			if lastRevErr != nil {
				return ErrExtension.Wrap(lastRevErr)
			}
			return ErrRevokedCert
		}

		return nil
	}
}
