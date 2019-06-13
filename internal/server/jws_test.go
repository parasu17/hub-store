/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package server

import (
	"crypto/ecdsa"
	"io/ioutil"
	"path/filepath"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/square/go-jose"
	"github.com/square/go-jose/jwt"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/hub-store/internal/crypto"
)

func TestCreateNewAccessToken(t *testing.T) {
	privKey, e1 := getPrivateKeyFromFile("../../tests/keys/did-server/ec-key.pem")
	require.NoError(t, e1)
	ecdsaKey := privKey.(*ecdsa.PrivateKey)
	_, err := createNewAccessToken("p6OLLpeRafCWbOAEYpuGVTKNkcq8l", "subject", ecdsaKey)
	require.NoError(t, err)
}

func TestCreateNewAccessTokenWithNilKey(t *testing.T) {
	var pk *ecdsa.PrivateKey
	_, err := createNewAccessToken("", "", pk)
	require.Error(t, err)
	require.Equal(t, "Failed to create new signer for new access token JWS: invalid private key", err.Error())
}

func TestValidateAccessToken(t *testing.T) {
	privKey, e1 := getPrivateKeyFromFile("../../tests/keys/did-server/ec-key.pem")
	require.NoError(t, e1)
	ecdsaKey := privKey.(*ecdsa.PrivateKey)
	tok, err := createNewAccessToken("p6OLLpeRafCWbOAEYpuGVTKNkcq8l", "subject", ecdsaKey)
	require.NoError(t, err)
	authJWT, parseErr := jwt.ParseSigned(tok)
	require.NoError(t, parseErr)
	err = validateAccessToken(authJWT, ecdsaKey, "subject")
	require.NoError(t, err)
}

func TestValidateAccessTokenWithWrongIssuer(t *testing.T) {
	privKey, err := getPrivateKeyFromFile("../../tests/keys/did-server/ec-key.pem")
	require.NoError(t, err)
	ecdsaKey := privKey.(*ecdsa.PrivateKey)
	key := jose.SigningKey{Algorithm: jose.ES256, Key: ecdsaKey}
	var signerOpts = jose.SignerOptions{NonceSource: staticNonceSource("nonce")} // using passed in nonce
	signer, err := jose.NewSigner(key, signerOpts.WithType("JWT"))
	require.NoError(t, err)
	builder := jwt.Signed(signer)

	issuedTime := time.Now().UTC()
	expiryTime := issuedTime.Add(5 * time.Minute)
	claims := jwt.Claims{
		Issuer:    "Issuer",
		Subject:   "subject",
		ID:        "id",
		Audience:  jwt.Audience{HubIssuerID},
		NotBefore: jwt.NewNumericDate(issuedTime),
		IssuedAt:  jwt.NewNumericDate(issuedTime),
		Expiry:    jwt.NewNumericDate(expiryTime),
	}
	tok, err := builder.Claims(claims).CompactSerialize()
	require.NoError(t, err)
	authJWT, err := jwt.ParseSigned(tok)
	require.NoError(t, err)
	err = validateAccessToken(authJWT, ecdsaKey, "subject")
	require.Error(t, err)
	require.Equal(t, "Access Token validation failed: square/go-jose/jwt: validation failed, invalid issuer claim (iss)", err.Error())
}

func TestValidateAccessTokenWithWrongKey(t *testing.T) {
	privKey, e1 := getPrivateKeyFromFile("../../tests/keys/did-server/ec-key.pem")
	require.NoError(t, e1)
	ecdsaKey := privKey.(*ecdsa.PrivateKey)
	tok, err := createNewAccessToken("p6OLLpeRafCWbOAEYpuGVTKNkcq8l", "subject", ecdsaKey)
	require.NoError(t, err)
	authJWT, parseErr := jwt.ParseSigned(tok)
	require.NoError(t, parseErr)

	privKey, e1 = getPrivateKeyFromFile("../../tests/keys/did-client/ec-key.pem")
	require.NoError(t, e1)
	ecdsaKey = privKey.(*ecdsa.PrivateKey)
	err = validateAccessToken(authJWT, ecdsaKey, "subject")
	require.Error(t, err)
	require.Equal(t, "square/go-jose: error in cryptographic primitive", err.Error())
}

func getPrivateKeyFromFile(filePath string) (interface{}, error) {
	keyBytes, err := ioutil.ReadFile(filepath.Clean(filePath))
	if err != nil {
		return nil, errors.Wrapf(err, "Crypto [Warning]: could not read private Key")
	}

	pvKey, err := crypto.ParsePrivateKey(keyBytes)
	if err != nil {
		return nil, errors.Wrapf(err, "Crypto [Warning]: could not parse private Key")
	}

	return pvKey, nil
}

func TestRandomString(t *testing.T) {
	arr := make([]string, 1000)
	for i := 0; i < len(arr); i++ {
		arr[i] = randomString()
	}
	for i := 0; i < (len(arr) - 1); i++ {
		for j := i + 1; j < len(arr); j++ {
			require.NotEqual(t, arr[i], arr[j])
		}
	}
}
