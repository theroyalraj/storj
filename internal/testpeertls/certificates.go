// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package testpeertls

import (
	"crypto/x509"

	"storj.io/storj/pkg/peertls"
)

// NewCertChain creates a valid peertls certificate chain (and respective keys) of the desired length.
// NB: keys are in the reverse order compared to certs (i.e. first key belongs to last cert)!
func NewCertChain(length int) (keys []peertls.PrivateKey, certs []*peertls.Certificate, _ error) {
	for i := 0; i < length; i++ {
		key, err := peertls.GeneratePrivateKey()
		if err != nil {
			return nil, nil, err
		}
		keys = append(keys, key)

		var template *x509.Certificate
		if i == length-1 {
			template, err = peertls.CATemplate()
		} else {
			template, err = peertls.LeafTemplate()
		}
		if err != nil {
			return nil, nil, err
		}

		var cert *peertls.Certificate
		if i == 0 {
			cert, err = peertls.CreateSelfSignedCertificate(key, template)
		} else {
			cert, err = peertls.CreateCertificate(key.PubKey(), keys[i-1], template, certs[i-1:][0].Certificate)
		}
		if err != nil {
			return nil, nil, err
		}

		certs = append([]*peertls.Certificate{cert}, certs...)
	}
	return keys, certs, nil
}
