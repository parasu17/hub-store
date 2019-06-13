/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package server

import (
	"crypto/ecdsa"
	"math/rand"
	"time"

	"github.com/pkg/errors"
	"github.com/square/go-jose"
	"github.com/square/go-jose/jwt"
)

const (
	// HubIssuerID represents the ID of the hub (TODO: in the future this should be made configurable for each instance)
	HubIssuerID = "did:hub:id"
)

var seededRand = rand.New(rand.NewSource(time.Now().UnixNano()))

type staticNonceSource string

func (sns staticNonceSource) Nonce() (string, error) {
	return string(sns), nil
}

// createNewAccessToken will generate a new access token with the given nonce and using publicKey
func createNewAccessToken(nonce, subject string, pvKey *ecdsa.PrivateKey) (string, error) {
	// for now creating keys with ECDSA using P-256 and SHA-256
	key := jose.SigningKey{Algorithm: jose.ES256, Key: pvKey}
	var signerOpts = jose.SignerOptions{NonceSource: staticNonceSource(nonce)} // using passed in nonce
	signerOpts.WithType("JWT")

	signer, err := jose.NewSigner(key, &signerOpts)
	if err != nil {
		return "", errors.Wrapf(err, "Failed to create new signer for new access token JWS")
	}

	builder := jwt.Signed(signer)

	issuedTime := time.Now().UTC()
	expiryTime := issuedTime.Add(5 * time.Minute)
	claims := jwt.Claims{
		Issuer:    HubIssuerID,
		Subject:   subject,
		ID:        randomString(),
		Audience:  jwt.Audience{HubIssuerID},
		NotBefore: jwt.NewNumericDate(issuedTime),
		IssuedAt:  jwt.NewNumericDate(issuedTime),
		Expiry:    jwt.NewNumericDate(expiryTime),
	}

	return builder.Claims(claims).CompactSerialize()
}

func validateAccessToken(accessToken *jwt.JSONWebToken, pvKey *ecdsa.PrivateKey, subject string) error {
	resultClaims := jwt.Claims{}
	err := accessToken.Claims(&pvKey.PublicKey, &resultClaims)
	if err != nil {
		return err
	}

	err = resultClaims.Validate(jwt.Expected{
		Issuer:   HubIssuerID,
		Audience: jwt.Audience{HubIssuerID},
		Subject:  subject,
		ID:       resultClaims.ID,
		Time:     time.Now().UTC(),
	})
	if err != nil {
		return errors.Wrapf(err, "Access Token validation failed")
	}
	return nil
}

// randomString creates a random string of a constant length
func randomString() string {
	const charset string = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	const idLength int = 20
	b := make([]byte, idLength)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}
