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

type MessageSigner interface {
	crypto.Signer
	SignMsg(data []byte) ([]byte, error)
}

type MessageVerifier interface {
	VerifyMsg(msgBytes, signatureBytes []byte) bool
}

type PrivateKey interface {
	MessageSigner
	PubKey() PublicKey
	MarshalToDER() ([]byte, error)
	PEMLabel() string
	CryptoPrivate() crypto.PrivateKey
}

type PublicKey interface {
	MessageVerifier
	MarshalToDER() ([]byte, error)
	PEMLabel() string
	CryptoPublic() crypto.PublicKey
}

type ecdsaPrivateKey struct {
	ecdsa.PrivateKey
}

type ecdsaPublicKey struct {
	ecdsa.PublicKey
}

var authECCurve = elliptic.P256()

// GeneratePrivateKey returns a new PrivateKey for signing messages
func GeneratePrivateKey() (PrivateKey, error) {
	rawPrivateKey, err := ecdsa.GenerateKey(authECCurve, rand.Reader)
	if err != nil {
		return nil, err
	}
	return &ecdsaPrivateKey{*rawPrivateKey}, nil
}

func NewPublicKey(pubKey crypto.PublicKey) PublicKey {
	switch key := pubKey.(type) {
	case *ecdsa.PublicKey:
		return &ecdsaPublicKey{*key}
	}
	return nil
}

func (pubKey *ecdsaPublicKey) CryptoPublic() crypto.PublicKey {
	return pubKey.PublicKey
}

// MarshalToDER serializes a public key to DER-encoded PKIX format.
func (pubKey *ecdsaPublicKey) MarshalToDER() ([]byte, error) {
	return x509.MarshalPKIXPublicKey(pubKey.PublicKey)
}

func LoadPublicKeyFromPEMBytes(keyBytes []byte) (PublicKey, error) {
	pemBlock, _ := pem.Decode(keyBytes)
	switch pemBlock.Type {
	case PEMLabelEcPublicKey:
		k, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
		if err != nil {
			return nil, err
		}
		return NewPublicKey(k), nil
	}
	return nil, ErrUnsupportedKey.New("PEM label %q not supported for public keys", pemBlock.Type)
}

func (pubKey *ecdsaPublicKey) VerifyMsg(msgBytes, signatureBytes []byte) bool {
	var signature struct {
		// the `r` and `s` values in an ecdsa signature
		// (see https://golang.org/pkg/crypto/ecdsa)
		R, S *big.Int
	}
	if _, err := asn1.Unmarshal(signatureBytes, &signature); err != nil {
		return false
	}

	digest := SHA256Hash(msgBytes)
	return ecdsa.Verify(&pubKey.PublicKey, digest, signature.R, signature.S)
}

func (pubKey *ecdsaPublicKey) PEMLabel() string {
	return PEMLabelEcPublicKey
}

func (privKey *ecdsaPrivateKey) CryptoPrivate() crypto.PrivateKey {
	return privKey.PrivateKey
}

func (privKey *ecdsaPrivateKey) SignMsg(data []byte) ([]byte, error) {
	digest := SHA256Hash(data)
	return privKey.PrivateKey.Sign(rand.Reader, digest, nil)
}

func (privKey *ecdsaPrivateKey) MarshalToDER() ([]byte, error) {
	keyBytes, err := x509.MarshalECPrivateKey(&privKey.PrivateKey)
	return keyBytes, errs.Wrap(err)
}

func (privKey *ecdsaPrivateKey) PEMLabel() string {
	return PEMLabelEcPrivateKey
}

func (privKey *ecdsaPrivateKey) PubKey() PublicKey {
	return &ecdsaPublicKey{privKey.PublicKey}
}

func LoadPrivateKeyFromBytes(keyBytes []byte) (PrivateKey, error) {
	pemBlock, _ := pem.Decode(keyBytes)
	switch pemBlock.Type {
	case PEMLabelEcPrivateKey:
		k, err := x509.ParseECPrivateKey(pemBlock.Bytes)
		if err != nil {
			return nil, ErrParseKey.Wrap(err)
		}
		return &ecdsaPrivateKey{*k}, nil
	}
	return nil, ErrUnsupportedKey.New("PEM type %q not supported for private keys", pemBlock.Type)
}

// WriteKey writes the private key to the writer, PEM-encoded.
func WriteKey(w io.Writer, key PrivateKey) error {
	kb, err := key.MarshalToDER()
	if err != nil {
		return err
	}
	pemBlock := &pem.Block{Type: key.PEMLabel(), Bytes: kb}
	return errs.Wrap(pem.Encode(w, pemBlock))
}

// KeyBytes returns bytes of the private key to the writer, PEM-encoded.
func KeyBytes(key PrivateKey) ([]byte, error) {
	var data bytes.Buffer
	err := WriteKey(&data, key)
	return data.Bytes(), err
}
