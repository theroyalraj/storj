package peertls

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"io"
	"math/big"

	"github.com/zeebo/errs"
)

// ECDSASignature holds the `r` and `s` values in an ecdsa signature
// (see https://golang.org/pkg/crypto/ecdsa)
type ECDSASignature struct {
	R, S *big.Int
}

var authECCurve = elliptic.P256()

// GeneratePrivateKey returns a new PrivateKey for signing messages
func GeneratePrivateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(authECCurve, rand.Reader)
}

// VerifySignature checks the signature against the passed data and public key
func VerifySignature(signedData []byte, data []byte, pubKey crypto.PublicKey) error {
	key, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return ErrUnsupportedKey.New("%T", key)
	}

	signature := new(ECDSASignature)
	if _, err := asn1.Unmarshal(signedData, signature); err != nil {
		return ErrVerifySignature.New("unable to unmarshal ecdsa signature: %v", err)
	}

	digest, err := SHA256Hash(data)
	if err != nil {
		return ErrVerifySignature.Wrap(err)
	}

	if !ecdsa.Verify(key, digest, signature.R, signature.S) {
		return ErrVerifySignature.New("signature is not valid")
	}
	return nil
}

func signBytes(key crypto.PrivateKey, data []byte) ([]byte, error) {
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, ErrUnsupportedKey.New("%T", key)
	}

	r, s, err := ecdsa.Sign(rand.Reader, ecKey, data)
	if err != nil {
		return nil, ErrSign.Wrap(err)
	}

	return asn1.Marshal(ECDSASignature{R: r, S: s})
}

// WriteKey writes the private key to the writer, PEM-encoded.
func WriteKey(w io.Writer, key crypto.PrivateKey) error {
	var (
		kb  []byte
		err error
	)

	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		kb, err = x509.MarshalECPrivateKey(k)
		if err != nil {
			return errs.Wrap(err)
		}
	default:
		return ErrUnsupportedKey.New("%T", k)
	}

	if err := pem.Encode(w, NewKeyBlock(kb)); err != nil {
		return errs.Wrap(err)
	}
	return nil
}

// KeyBytes returns bytes of the private key to the writer, PEM-encoded.
func KeyBytes(key crypto.PrivateKey) ([]byte, error) {
	var data bytes.Buffer
	err := WriteKey(&data, key)
	return data.Bytes(), err
}
