/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package crypto

import (
	"io/ioutil"
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
			Name:    "Success case for private key",
			Success: true,
			isPriv:  true,
			keyPath: "../../tests/keys/did-server/ec-key.pem",
		},
		{
			Name:       "Fail Parse invalid private key format case",
			Success:    false,
			isPriv:     true,
			keyContent: "invalid/content",
		},
		{
			Name:       "Fail Parse empty private key content case",
			Success:    false,
			isPriv:     true,
			keyContent: "",
		},
		{
			Name:    "Success case for public key",
			Success: true,
			isPriv:  false,
			keyPath: "../../tests/keys/did-server/ec-pubKey.pem",
		},
		{
			Name:       "Fail Parse invalid public key case",
			Success:    false,
			isPriv:     false,
			keyContent: "invalid/content",
		},
		{
			Name:       "Fail Parse empty public key content case",
			Success:    false,
			isPriv:     false,
			keyContent: "",
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
		})
	}
}
