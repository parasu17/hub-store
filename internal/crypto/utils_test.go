/*
   Copyright SecureKey Technologies Inc.
   This file contains software code that is the intellectual property of SecureKey.
   SecureKey reserves all rights in the code and you may not use it without written permission from SecureKey.
*/

package crypto

import (
	"io/ioutil"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type testCase struct {
	Name       string
	Success    bool
	isPriv     bool
	keyPath    string
	keyContent string
	ErrorMsg   string
}

func TestParseKey(t *testing.T) {
	testCases := []testCase{
		{
			Name:     "Success case for private key",
			Success:  true,
			isPriv:   true,
			keyPath:  "../../tests/keys/did-server/ec-key.pem",
			ErrorMsg: "",
		},
		{
			Name:       "Fail Parse invalid private key format case",
			Success:    false,
			isPriv:     true,
			keyContent: "invalid/content",
			ErrorMsg:   "square/go-jose: parse error",
		},
		{
			Name:     "Fail Parse invalid private key content case",
			Success:  false,
			isPriv:   true,
			keyPath:  "../../tests/keys/did-server/ec-pubCert",
			ErrorMsg: "square/go-jose: parse error, got 'asn1: syntax error: sequence truncated'",
		},
		{
			Name:     "Success case for public key",
			Success:  true,
			isPriv:   false,
			keyPath:  "../../tests/keys/did-server/ec-pubKey.pem",
			ErrorMsg: "",
		},
		{
			Name:       "Fail Parse invalid public key case",
			Success:    false,
			isPriv:     false,
			keyContent: "invalid/content",
			ErrorMsg:   "square/go-jose: parse error",
		},
		{
			Name:     "Fail Parse invalid public key content case",
			Success:  false,
			isPriv:   false,
			keyPath:  "../../tests/keys/did-server/ec-pubCert",
			ErrorMsg: "square/go-jose: parse error, got 'asn1: syntax error: sequence truncated'",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			var err error
			if tc.Success {
				keyBytes, err := ioutil.ReadFile(tc.keyPath)
				require.NoError(t, err, "must be able to read a valid key file")
				if tc.isPriv {
					_, err = ParsePrivateKey(keyBytes)
				} else {
					_, err = ParsePublicKey(keyBytes)
				}

				require.NoError(t, err, "must be able to parse a valid key")
				return
			}
			if tc.isPriv {
				_, err = ParsePrivateKey([]byte(tc.keyContent))
			} else {
				_, err = ParsePublicKey([]byte(tc.keyContent))
			}
			require.Error(t, err, "parsing invalid key should return an error")
			require.True(t, strings.HasPrefix(err.Error(), tc.ErrorMsg), "parse key error message mismatch want error starting with %s, but got %s", tc.ErrorMsg, err.Error())
		})
	}
}
