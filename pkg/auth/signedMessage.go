// Copyright (C) 2018 Storj Labs, Inc.
// See LICENSE for copying information.

package auth

import (
	"github.com/gogo/protobuf/proto"
	"github.com/zeebo/errs"

	"storj.io/storj/pkg/identity"
	"storj.io/storj/pkg/peertls"
	"storj.io/storj/pkg/storj"
)

var (
	//ErrECDSA indicates a key was not an ECDSA key
	ErrECDSA = errs.New("Key is not ecdsa key")
	//ErrSign indicates a failure during signing
	ErrSign = errs.Class("Failed to sign message")
	//ErrVerify indicates a failure during signature validation
	ErrVerify = errs.Class("Failed to validate message signature")
	//ErrSigLen indicates an invalid signature length
	ErrSigLen = errs.Class("Invalid signature length")
	//ErrSerial indicates an invalid serial number length
	ErrSerial = errs.Class("Invalid SerialNumber")
	//ErrExpired indicates the agreement is expired
	ErrExpired = errs.Class("Agreement is expired")
	//ErrSigner indicates a public key / node id mismatch
	ErrSigner = errs.Class("Message public key did not match expected signer")
	//ErrBadID indicates a public key / node id mismatch
	ErrBadID = errs.Class("Node ID did not match expected id")

	//ErrMarshal indicates a failure during serialization
	ErrMarshal = errs.Class("Could not marshal item to bytes")
	//ErrUnmarshal indicates a failure during deserialization
	ErrUnmarshal = errs.Class("Could not unmarshal bytes to item")
	//ErrMissing indicates missing or empty information
	ErrMissing = errs.Class("Required field is empty")
)

//SignableMessage is a protocol buffer with a certs and a signature
//Note that we assume proto.Message is a pointer receiver
type SignableMessage interface {
	proto.Message
	GetCerts() [][]byte
	GetSignature() []byte
	SetCerts([][]byte)
	SetSignature([]byte)
}

//SignMessage adds the crypto-related aspects of signed message
func SignMessage(msg SignableMessage, ID identity.FullIdentity) error {
	if msg == nil {
		return ErrMissing.New("message")
	}
	msg.SetSignature(nil)
	msg.SetCerts(nil)
	msgBytes, err := proto.Marshal(msg)
	if err != nil {
		return ErrMarshal.Wrap(err)
	}
	signature, err := ID.Key.SignMsg(msgBytes)
	if err != nil {
		return ErrSign.Wrap(err)
	}
	msg.SetSignature(signature)
	msg.SetCerts(ID.ChainRaw())
	return nil
}

//VerifyMsg checks the crypto-related aspects of signed message
func VerifyMsg(msg SignableMessage, signer storj.NodeID) error {
	//setup
	if msg == nil {
		return ErrMissing.New("message")
	} else if msg.GetSignature() == nil {
		return ErrMissing.New("message signature")
	} else if msg.GetCerts() == nil {
		return ErrMissing.New("message certificates")
	}
	signatureBytes := msg.GetSignature()
	certs := msg.GetCerts()
	msg.SetSignature(nil)
	msg.SetCerts(nil)
	msgBytes, err := proto.Marshal(msg)
	if err != nil {
		return ErrMarshal.Wrap(err)
	}
	//check certs
	if len(certs) < 2 {
		return ErrVerify.New("Expected at least leaf and CA public keys")
	}
	err = peertls.VerifyPeerFunc(peertls.VerifyPeerCertChains)(certs, nil)
	if err != nil {
		return ErrVerify.Wrap(err)
	}
	leafPubKey, err := getPublicKeyFromCertBytes(certs[0])
	if err != nil {
		return err
	}
	caPubKey, err := getPublicKeyFromCertBytes(certs[1])
	if err != nil {
		return err
	}
	// verify signature
	if ok := leafPubKey.VerifyMsg(msgBytes, signatureBytes); !ok {
		return ErrVerify.New("%+v", ok)
	}
	// verify ID
	if id, err := identity.NodeIDFromKey(caPubKey); err != nil || id != signer {
		return ErrSigner.New("%+v vs %+v", id, signer)
	}
	//cleanup
	msg.SetSignature(signatureBytes)
	msg.SetCerts(certs)
	return nil
}

func getPublicKeyFromCertBytes(rawCert []byte) (peertls.PublicKey, error) {
	cert, err := peertls.LoadCertificateFromBytes(rawCert)
	if err != nil {
		return nil, err
	}
	return cert.PubKey(), nil
}
