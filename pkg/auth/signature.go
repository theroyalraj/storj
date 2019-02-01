// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package auth

import (
	"encoding/pem"

	"storj.io/storj/pkg/identity"
	"storj.io/storj/pkg/pb"
	"storj.io/storj/pkg/peertls"
)

// GenerateSignature creates signature from identity id
func GenerateSignature(data []byte, identity *identity.FullIdentity) ([]byte, error) {
	return identity.Key.SignMsg(data)
}

// NewSignedMessage creates instance of signed message
func NewSignedMessage(signature []byte, identity *identity.FullIdentity) (*pb.SignedMessage, error) {
	derBytes, err := identity.Leaf.PubKey().MarshalToDER()
	if err != nil {
		return nil, err
	}

	// We go the extra step to encode the DER bytes to PEM, although this isn't
	// meant for human consumption and doesn't need to be in ASCII. This is for
	// backwards compatibility, or in case there is some other non-obvious reason
	// for it (if there is, please add an explanatory comment!).
	//
	// Or if this is changed to use the DER bytes directly, make the corresponding
	// changes in NewSignedMessageVerifier(), below.
	encodedKey := pem.EncodeToMemory(&pem.Block{
		Type:  identity.Leaf.PubKey().PEMLabel(),
		Bytes: derBytes,
	})

	return &pb.SignedMessage{
		Data:      identity.ID.Bytes(),
		Signature: signature,
		PublicKey: encodedKey,
	}, nil
}

// SignedMessageVerifier checks if provided signed message can be verified
type SignedMessageVerifier func(signature *pb.SignedMessage) error

// NewSignedMessageVerifier creates default implementation of SignedMessageVerifier
func NewSignedMessageVerifier() SignedMessageVerifier {
	return func(signedMessage *pb.SignedMessage) error {
		if signedMessage == nil {
			return Error.New("no message to verify")
		}
		if signedMessage.Signature == nil {
			return Error.New("missing signature for verification")
		}
		if signedMessage.Data == nil {
			return Error.New("missing data for verification")
		}
		if signedMessage.PublicKey == nil {
			return Error.New("missing public key for verification")
		}

		k, err := peertls.LoadPublicKeyFromPEMBytes(signedMessage.GetPublicKey())
		if err != nil {
			return err
		}
		if ok := k.VerifyMsg(signedMessage.GetData(), signedMessage.GetSignature()); !ok {
			return Error.New("failed to verify message")
		}
		return nil
	}
}
